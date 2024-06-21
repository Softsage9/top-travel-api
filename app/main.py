from datetime import datetime, timedelta, timezone
import logging
import os
from pathlib import Path
from typing import List
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette import status

from . import crud, models, schemas, database
from .database import async_session, engine

app = FastAPI()

IMAGEDIR = Path(__file__).parent.parent / "static/images"

app.mount("/static", StaticFiles(directory="static"), name="static")

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
)

ACCESS_TOKEN_EXPIRE_MINUTES = 30

load_dotenv()

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

@app.get("/users/", response_model=list[schemas.UserInDB])
async def get_users(skip: int = 0, limit: int = 100, db: AsyncSession = Depends(database.get_db)):
    events = await crud.get_all_users(db, skip=skip, limit=limit)
    return events

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
async def read_destinations(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    destinations = await crud.get_destinations(db, skip=skip, limit=limit)
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

@app.delete("/destinations/{destination_id}", response_model=schemas.DestinationInDB)
async def delete_destination(destination_id: int, db: AsyncSession = Depends(database.get_db)):
    db_destination = await crud.delete_destination(db, destination_id)
    if db_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return db_destination

# End of Destination Endpoints

# Package Endpoints

@app.post("/packages/", response_model=schemas.PackageInDB)
async def create_package(package: schemas.PackageCreate, db: AsyncSession = Depends(database.get_db)):
    return await crud.create_package(db, package)

@app.get("/packages/", response_model=List[schemas.PackageInDB])
async def read_packages(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    packages = await crud.get_packages(db, skip=skip, limit=limit)
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
async def read_bookings(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    result = await db.execute(
        select(models.Booking).offset(skip).limit(limit)
    )
    bookings = result.scalars().all()
    
    results = []
    for booking in bookings:
        user_result = await db.execute(
            select(models.User).filter(models.User.UserID == booking.UserID)
        )
        user = user_result.scalars().first()
        
        results.append({
            "BookingID": booking.BookingID,
            "UserID": booking.UserID,
            "PackageID": booking.PackageID,
            "BookingDate": booking.BookingDate,
            "Status": booking.Status,
            "NumberOfPeople": booking.NumberOfPeople,
            "UserEmail": user.Email,
            "UserFirstName": user.FirstName,
            "UserLastName": user.LastName
        })
    
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
        UserEmail=user.Email,
        UserFirstName=user.FirstName,
        UserLastName=user.LastName
    )

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
