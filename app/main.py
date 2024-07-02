from datetime import date, datetime, timedelta, timezone
import logging
import os
from pathlib import Path
import shutil
from typing import List, Optional
import uuid
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette import status
import aiofiles
from . import crud, models, schemas, database, config
from .database import async_session

app = FastAPI()

app.mount("/static", StaticFiles(directory="app/static"), name="static")

origins = [
    "http://localhost:5173", 
    "http://localhost:5174",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],
)

ACCESS_TOKEN_EXPIRE_MINUTES = 30

load_dotenv()

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

async def init_models():
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

@app.on_event("startup")
async def on_startup():
    await init_models()
    await init_roles()

async def init_roles():
    async with async_session() as session:
        async with session.begin():
            roles = ["admin", "user"]
            for role_name in roles:
                result = await session.execute(select(models.Role).filter_by(RoleName=role_name))
                role = result.scalars().first()
                if not role:
                    new_role = models.Role(RoleName=role_name)
                    session.add(new_role)
                    await session.commit()  

@app.get("/")
async def root():
    return {"message": "Top Travel"}


@app.post("/token", response_model=schemas.SessionToken)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(database.get_db)):
    user = await crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not verified.",
        )
    jwt_token, session_token = await crud.create_access_token(
        {"sub": user.username}, db, user.UserID, timedelta(minutes=30)
    )

    return {
        "token": jwt_token,
        "session_token": session_token.token,
        "user_id": user.UserID,
        "super_admin_id": None,
        "expiry_date": session_token.expiry_date
    }

@app.post("/auth/google", response_model=schemas.UserInDB)
async def google_login(token: str, db: AsyncSession = Depends(database.get_db)):
    user_info = await crud.verify_google_token(token)

    existing_user = await db.execute(select(models.User).filter(models.User.Email == user_info['email']))
    existing_user = existing_user.scalars().first()

    if existing_user:
        if not existing_user.google_id:
            existing_user.google_id = user_info['sub']
            await db.commit()
            await db.refresh(existing_user)

        session_token = await crud.create_google_session_token(db, existing_user.UserID, token)
        return schemas.UserInDB(
            **existing_user.__dict__,
            session_token=session_token.token
        )

    new_user_data = schemas.UserCreate(
        username=user_info['email'],
        Email=user_info['email'],
        Password="",
        FirstName=user_info.get('given_name', ''),
        LastName=user_info.get('family_name', ''),
        Phone="",
        DateOfBirth=None,
        google_id=user_info['sub']
    )

    new_user = await crud.create_user(db, new_user_data, is_google_login=True)
    session_token = await crud.create_google_session_token(db, new_user.UserID, token)
    return schemas.UserInDB(
        **new_user.__dict__,
        session_token=session_token.token
    )



@app.post("/logout", response_model=schemas.Message)
async def logout(session_token: str = Query(None), google_token: str = Query(None), db: AsyncSession = Depends(database.get_db)):
    if session_token:
        existing_token = await crud.get_session_token(db, session_token)
        logging.info(f"Existing_token: {existing_token}")
        if existing_token is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session token not found")
        await crud.delete_session_token(db, session_token)
        return {"message": "Logged out successfully"}

    elif google_token:
        existing_google_token = await crud.get_session_token(db, google_token)
        if existing_google_token is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Google session token not found")
        await crud.delete_session_token(db, google_token)
        return {"message": "Google session token deleted successfully"}

    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Neither session token nor Google token provided")


@app.get("/users/me/", response_model=schemas.UserInDB)
async def read_users_me(current_user: schemas.UserInDB = Depends(crud.get_current_active_user)):
    return current_user

# Create User Endpoint

@app.post("/users/create", response_model=schemas.UserInDB)
async def create_user_endpoint(user: schemas.UserCreate, db: AsyncSession = Depends(database.get_db)):
    result = await db.execute(
        select(models.User).filter(
            (models.User.username == user.username) | (models.User.Email == user.Email)
        )
    )
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username or email already taken"
        )
    try:
        new_user = await crud.create_user(db, user)

        # Generates a verification code
        session_token = await crud.create_session_token(db, new_user.UserID)
        activation_token = session_token.activation_token
        

        # Loads email credentials
        email_sender = os.getenv("EMAIL_SENDER")
        email_password = os.getenv("EMAIL_PASSWORD")

        print(f"Email Sender: {email_sender}")
        print(f"Email Password: {email_password}")

        # Sends a verification email
        await crud.send_verification_email(email_sender, email_password, user.Email, activation_token)

        # Assigns role to the user
        result = await db.execute(select(models.Role).filter_by(RoleName=user.Role))
        role = result.scalars().first()
        if not role:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role not found")
    
        user_role = models.UserRole(
            UserID=new_user.UserID,
            RoleID=role.RoleID
        )
        db.add(user_role)
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    return new_user

# End Of Create User Endpoint

@app.get("/users/", response_model=List[schemas.UserInDB])
async def get_users(
    response: Response,  # Include the Response object here (non-default argument)
    skip: int = 0, 
    limit: int = 10, 
    _sort: str = "UserID", 
    _order: str = "asc", 
    db: AsyncSession = Depends(database.get_db)
):
    try:
        users = await crud.get_all_users(db, page=skip // limit, limit=limit, sort=_sort, order=_order)
        
        # Count total users
        total = await db.scalar(select(func.count()).select_from(models.User))

        # Set X-Total-Count header
        response.headers["X-Total-Count"] = str(total)
        
        return users
    except ValueError as ve:
        logging.error(f"Invalid sort field: {_sort}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logging.error(f"Error fetching users: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.get("/users/{user_id}", response_model=schemas.UserInDB)
async def get_user(user_id: int, db: AsyncSession = Depends(database.get_db)):
    user = await crud.get_user_by_id(db, user_id=user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@app.delete("/users/{user_id}", response_model=schemas.UserInDB)
async def delete_user(user_id: int, db: AsyncSession = Depends(database.get_db)):
    db_event = await crud.delete_user(db, user_id=user_id)
    if db_event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return db_event

@app.post("/verify-user")
async def verify_code(request: schemas.VerifyCodeRequest, db: AsyncSession = Depends(database.get_db)):
    result = await db.execute(
        select(models.AccountActivation).join(models.User).filter(
            models.AccountActivation.activation_token == request.code,
            models.User.Email == request.email,
            models.AccountActivation.expiry_date > datetime.now(timezone.utc),
        )
    )
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid code or email, or the code has expired.",
        )

    user_id = token_record.user_id
    user_result = await crud.get_user_by_id(db, user_id)
    user_result.is_verified = True
    await db.commit()

    await db.delete(token_record)
    await db.commit()

    return {"message": "Account successfully verified."}

# Destination Endpoints

@app.post("/destinations/", response_model=schemas.DestinationInDB)
async def create_destination(destination: schemas.DestinationCreate, db: AsyncSession = Depends(database.get_db)):
    return await crud.create_destination(db, destination)

@app.get("/destinations/", response_model=List[schemas.DestinationInDB])
async def read_destinations(response: Response, skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    destinations, total = await crud.get_destinations(db, skip=skip, limit=limit)
    response.headers["X-Total-Count"] = str(total)
    return destinations

@app.get("/destinations/{destination_id}", response_model=schemas.DestinationInDB)
async def read_destination(destination_id: int, db: AsyncSession = Depends(database.get_db)):
    db_destination = await crud.get_destination(db, destination_id)
    if db_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return db_destination

@app.put("/destinations/{destination_id}", response_model=schemas.DestinationInDB)
async def update_destination(destination_id: int, destination: schemas.DestinationCreate, db: AsyncSession = Depends(database.get_db)):
    db_destination = await crud.update_destination(db, destination_id, destination)
    if db_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return db_destination

@app.delete("/destinations/", response_model=List[schemas.DestinationInDB])
async def delete_destinations(destination_ids: List[int], db: AsyncSession = Depends(database.get_db)):
    destinations = []
    for destination_id in destination_ids:
        destination = await db.execute(select(models.Destination).filter(models.Destination.DestinationID == destination_id))
        destination = destination.scalars().first()
        if destination:
            await db.delete(destination)
            await db.commit()
            destinations.append(destination)
        else:
            raise HTTPException(status_code=404, detail=f"Destination with ID {destination_id} not found")
    return destinations

@app.delete("/destinations/{destination_id}", response_model=schemas.DestinationInDB)
async def delete_destination(destination_id: int, db: AsyncSession = Depends(database.get_db)):
    db_destination = await crud.delete_destination(db, destination_id)
    if db_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return db_destination

# End of Destination Endpoints

# Package Endpoints

@app.post("/packages/", response_model=schemas.PackageInDB)
async def create_package(
        PackageName: str = Form(...),
        Description: Optional[str] = Form(None),
        Price: float = Form(...),
        Duration: int = Form(...),
        StartDate: date = Form(...),
        EndDate: date = Form(...),
        DestinationID: int = Form(...),
        attachments: List[UploadFile] = File(None),
        db: AsyncSession = Depends(database.get_db)
):
    if attachments is None:
        attachments = []
    
    attachments_data = []
    for attachment in attachments:
        filename = f"{uuid.uuid4()}{Path(attachment.filename).suffix}"
        file_path = Path("static/images") / filename
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(attachment.file, buffer)
        
        with open(file_path, "rb") as buffer:
            file_content = buffer.read()
        
        attachments_data.append(schemas.AttachmentCreate(
            title=attachment.filename,
            src=f"/static/images/{filename}",  # Use a relative URL for static files
            rawFile=file_content  # Store the file bytes
        ))

    package_data = schemas.PackageCreate(
        PackageName=PackageName,
        Description=Description,
        Price=Price,
        Duration=Duration,
        StartDate=StartDate,
        EndDate=EndDate,
        DestinationID=DestinationID,
        Attachments=attachments_data
    )

    return await crud.create_package(db=db, package=package_data, attachments=attachments)

@app.get("/packages/", response_model=List[schemas.PackageInDB])
async def read_packages(response: Response, skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    packages, total = await crud.get_packages(db, skip=skip, limit=limit)
    response.headers["X-Total-Count"] = str(total)
    return packages

@app.get("/packages/{package_id}", response_model=schemas.PackageInDB)
async def read_package(package_id: int, db: AsyncSession = Depends(database.get_db)):
    db_package = await crud.get_package(db, package_id)
    if db_package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return db_package

@app.put("/packages/{package_id}", response_model=schemas.PackageInDB)
async def update_package(package_id: int, package: schemas.PackageCreate, db: AsyncSession = Depends(database.get_db)):
    db_package = await crud.update_package(db, package_id, package)
    if db_package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return db_package

@app.delete("/packages/", response_model=List[schemas.PackageInDB])
async def delete_packages(package_ids: List[int], db: AsyncSession = Depends(database.get_db)):
    packages = []
    for package_id in package_ids:
        package = await db.execute(select(models.Package).filter(models.Package.PackageID == package_id))
        package = package.scalars().first()
        if package:
            await db.delete(package)
            await db.commit()
            packages.append(package)
        else:
            raise HTTPException(status_code=404, detail=f"Package with ID {package_id} not found")
    return packages

@app.delete("/packages/{package_id}", response_model=schemas.PackageInDB)
async def delete_package(package_id: int, db: AsyncSession = Depends(database.get_db)):
    db_package = await crud.delete_package(db, package_id)
    if db_package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return db_package

# End of Package Endpoints

# Booking Endpoints

@app.post("/bookings/", response_model=schemas.BookingInDB)
async def create_booking(booking: schemas.BookingCreate, db: AsyncSession = Depends(database.get_db)):
    return await crud.create_booking(db, booking)

@app.get("/bookings/", response_model=List[schemas.BookingInDB])
async def read_bookings(response: Response, skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    result = await db.execute(
        select(models.Booking).offset(skip).limit(limit)
    )
    bookings = result.scalars().all()

    total = await db.scalar(select(func.count()).select_from(models.Booking))
    response.headers["X-Total-Count"] = str(total)

    results = []
    for booking in bookings:
        user_result = await db.execute(
            select(models.User).filter(models.User.UserID == booking.UserID)
        )
        user = user_result.scalars().first()

        results.append(schemas.BookingInDB(
            BookingID=booking.BookingID,
            BookingDate=booking.BookingDate,
            Status=booking.Status,
            NumberOfPeople=booking.NumberOfPeople,
            UserID=booking.UserID,
            PackageID=booking.PackageID,
            UserEmail=user.Email,
            UserFirstName=user.FirstName,
            UserLastName=user.LastName
        ))

    return results


@app.get("/bookings/pending", response_model=List[schemas.BookingInDB])
async def read_pending_bookings(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    db_bookings = await crud.get_bookings_by_status(db, models.BookingStatus.PENDING, skip=skip, limit=limit)
    
    bookings_with_user_info = [
        schemas.BookingInDB(
            BookingID=booking["BookingID"],
            BookingDate=booking["BookingDate"],
            Status=booking["Status"],
            NumberOfPeople=booking["NumberOfPeople"],
            UserID=booking["UserID"],
            PackageID=booking["PackageID"],
            UserEmail=booking["UserEmail"],
            UserFirstName=booking["UserFirstName"],
            UserLastName=booking["UserLastName"]
        )
        for booking in db_bookings
    ]
    
    return bookings_with_user_info



@app.get("/bookings/{booking_id}", response_model=schemas.BookingInDB)
async def read_booking(booking_id: int, db: AsyncSession = Depends(database.get_db)):
    db_booking = await crud.get_booking(db, booking_id)
    if db_booking is None:
        raise HTTPException(status_code=404, detail="Booking not found")
    
    # Map the query result to the BookingInDB schema
    booking, email, first_name, last_name = db_booking
    return schemas.BookingInDB(
        BookingID=booking.BookingID,
        BookingDate=booking.BookingDate,
        Status=booking.Status,
        NumberOfPeople=booking.NumberOfPeople,
        UserID=booking.UserID,
        PackageID=booking.PackageID,
        UserEmail=email,
        UserFirstName=first_name,
        UserLastName=last_name
    )

@app.put("/bookings/{booking_id}", response_model=schemas.BookingInDB)
async def update_booking(booking_id: int, booking: schemas.BookingCreate, db: AsyncSession = Depends(database.get_db)):
    db_booking = await crud.update_booking(db, booking_id, booking)
    if db_booking is None:
        raise HTTPException(status_code=404, detail="Booking not found")
    return db_booking

@app.put("/bookings/{booking_id}/status", response_model=schemas.BookingInDB)
async def update_booking_status(booking_id: int, status: models.BookingStatus, db: AsyncSession = Depends(database.get_db)):
    db_booking = await crud.update_booking_status(db, booking_id, status)
    if db_booking is None:
        raise HTTPException(status_code=404, detail="Booking not found")

    # Fetch user details asynchronously
    user_result = await db.execute(select(models.User).filter(models.User.UserID == db_booking.UserID))
    user = user_result.scalars().first()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return schemas.BookingInDB(
        BookingID=db_booking.BookingID,
        BookingDate=db_booking.BookingDate,
        Status=db_booking.Status,
        NumberOfPeople=db_booking.NumberOfPeople,
        UserID=db_booking.UserID,
        PackageID=db_booking.PackageID,
        UserEmail=user.Email,
        UserFirstName=user.FirstName,
        UserLastName=user.LastName
    )

@app.delete("/bookings/", response_model=List[schemas.BookingInDB])
async def delete_bookings(booking_ids: List[int], db: AsyncSession = Depends(database.get_db)):
    bookings = []
    for booking_id in booking_ids:
        booking = await db.execute(select(models.Booking).filter(models.Booking.BookingID == booking_id))
        booking = booking.scalars().first()
        if booking:
            await db.delete(booking)
            await db.commit()
            bookings.append(booking)
        else:
            raise HTTPException(status_code=404, detail=f"Booking with ID {booking_id} not found")
    return bookings

@app.delete("/bookings/{booking_id}", response_model=schemas.BookingInDB)
async def delete_booking(booking_id: int, db: AsyncSession = Depends(database.get_db)):
    db_booking = await crud.delete_booking(db, booking_id)
    if db_booking is None:
        raise HTTPException(status_code=404, detail="Booking not found")
    return db_booking

# End Of Booking Endpoints

# Review Endpoints

@app.post("/reviews/", response_model=schemas.ReviewInDB)
async def create_review(review: schemas.ReviewCreate, db: AsyncSession = Depends(database.get_db)):
    return await crud.create_review(db, review)

@app.get("/reviews/", response_model=List[schemas.ReviewInDB])
async def read_reviews(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    reviews = await crud.get_reviews(db, skip=skip, limit=limit)
    return reviews

@app.get("/reviews/{review_id}", response_model=schemas.ReviewInDB)
async def read_review(review_id: int, db: AsyncSession = Depends(database.get_db)):
    db_review = await crud.get_review(db, review_id)
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return db_review

@app.get("/reviews/package/{package_id}", response_model=schemas.PackageReviews)
async def read_reviews_by_package(package_id: int, skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    avg_rating, reviews = await crud.get_reviews_by_package(db, package_id, skip=skip, limit=limit)
    return schemas.PackageReviews(
        average_rating=avg_rating,
        reviews=reviews
    )

@app.put("/reviews/{review_id}", response_model=schemas.ReviewInDB)
async def update_review(review_id: int, review: schemas.ReviewCreate, db: AsyncSession = Depends(database.get_db)):
    db_review = await crud.update_review(db, review_id, review)
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return db_review

@app.delete("/reviews/{review_id}", response_model=schemas.ReviewInDB)
async def delete_review(review_id: int, db: AsyncSession = Depends(database.get_db)):
    db_review = crud.delete_review(db, review_id)
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return db_review

# End Of Review Endpoints

# Forgot Password Endpoints

@app.post("/forgot-password")
async def forgot_password(email: schemas.ForgotPassword, db: AsyncSession = Depends(database.get_db)):
    user = await crud.get_user_email(db, email.email)

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User does not exists")

    user_id = user.UserID

    secret_token = crud.create_reset_password_token(email=email.email)
    expiration_date = datetime.now(timezone.utc) + timedelta(minutes=10)
    email_sender = os.getenv("EMAIL_SENDER")
    email_password = os.getenv("EMAIL_PASSWORD")

    password_reset_token = await crud.insert_password_reset_token(user_id, secret_token, expiration_date, db)
    await crud.send_reset_password_email(email_sender, email_password, email.email, secret_token)

    return password_reset_token

@app.post("/reset-password", response_model=schemas.SuccessMessage)
async def reset_password(rfp: schemas.ResetForgetPassword, db: AsyncSession = Depends(database.get_db)):
    try:
        info = crud.decode_reset_password_token(token=rfp.secret_token)

        if info is None:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="Invalid Password Reset Payload or Reset Link Expired")
        if rfp.new_password != rfp.confirm_password:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail="New password and confirm password are not same.")

        user = await crud.get_user_email(email=info, db=db)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        hashed_password = crud.pwd_context.hash(rfp.new_password)
        user_id = user.UserID
        success = await crud.update_user_password(hashed_password, user_id, rfp.secret_token, db)
        if success:
            await crud.delete_reset_password_token(db, rfp.secret_token)
            return schemas.SuccessMessage(success=True, status_code=200, message="Password reset successfully.")
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to reset password.")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to reset password.")

# End Of Forgot Password Endpoints