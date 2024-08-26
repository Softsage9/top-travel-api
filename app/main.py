from datetime import date, datetime, timedelta, timezone
import logging
import os
from pathlib import Path
import shutil
from typing import List, Optional
import uuid
from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, logger
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette import status
import aiofiles
import stripe
import stripe
import uvicorn
from . import crud, models, schemas, database, config
from .database import async_session

app = FastAPI()

app.mount("/static", StaticFiles(directory="app/static"), name="static")

origins = [
    # "http://localhost:5173", 
    # "http://localhost:5174",
    # "http://localhost:3000",
    "https://top-travel.uk",
    "https://www.top-travel.uk",
    "https://server-app-zxcxm.ondigitalocean.app",
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

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

stripe.api_key = os.getenv("STRIPE_API_KEY")
endpoint_secret = os.getenv("STRIPE_ENDPOINT_SECRET")
YOUR_DOMAIN = os.getenv("YOUR_DOMAIN")

async def init_models():
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

@app.on_event("startup")
async def on_startup():
    await database.check_connection()
    await database.check_connection()
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
async def login_for_access_token(
    credentials: schemas.LoginCredentials = Body(...),
    db: AsyncSession = Depends(database.get_db)
):
    logging.info(f"Received credentials: {credentials}")
    user = await crud.authenticate_user(db, credentials.email, credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check if user account is disabled
    if user.disabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # Check if user account is verified
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is not verified.",
        )

    # Generate JWT token and session token
    jwt_token, session_token = await crud.create_access_token(
        {"sub": user.Email}, db, user.UserID, timedelta(minutes=30)
    )

    # Return the access token and related information
    return {
        "token": jwt_token,
        "token_type": "bearer",
        "session_token": session_token.session_token,
        "user_id": user.UserID,
        "expiry_date": session_token.expiry_date.isoformat()
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
async def logout(token: str = Query(None), google_token: str = Query(None), db: AsyncSession = Depends(database.get_db)):
    if token:
        return await crud.handle_logout(token, db, "Session token not found")
    elif google_token:
        return await crud.handle_logout(google_token, db, "Google session token not found")
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No token provided")


@app.get("/users/me/", response_model=schemas.UserInDB)
async def read_users_me(current_user: schemas.UserInDB = Depends(crud.get_current_active_user)):
    return current_user

# Create User Endpoint

@app.post("/users/create", response_model=schemas.UserInDB)
async def create_user_endpoint(user: schemas.UserCreate, db: AsyncSession = Depends(database.get_db)):
    print(f"Received request to create user: {user.Email}")
    
    result = await db.execute(
        select(models.User).filter((models.User.Email == user.Email))
    )
    existing_user = result.scalars().first()

    if existing_user:
        print("Email already taken")
        raise HTTPException(
            status_code=400,
            detail="Email already taken"
        )

    try:
        new_user = await crud.create_user(db, user)
        print(f"Created new user with ID: {new_user.UserID}")

        # Generates a verification code
        session_token = await crud.create_session_token(db, new_user.UserID)
        print(f"Generated session token: {session_token.activation_token}")

        activation_token = session_token.activation_token

        # Loads email credentials
        email_sender = os.getenv("EMAIL_SENDER")
        email_password = os.getenv("EMAIL_PASSWORD")

        print(f"Email Sender: {email_sender}")
        print(f"Email Password: {email_password}")

        # Sends a verification email
        await crud.send_verification_email(email_sender, email_password, user.Email, activation_token)
        print("Sent verification email")

        # Assigns role to the user
        result = await db.execute(select(models.Role).filter_by(RoleName=user.Role))
        role = result.scalars().first()
        if not role:
            print("Role not found")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role not found")

        user_role = models.UserRole(
            UserID=new_user.UserID,
            RoleID=role.RoleID
        )
        db.add(user_role)
        await db.commit()
        print(f"Assigned role {user.Role} to user {new_user.UserID}")

    except Exception as e:
        await db.rollback()
        print(f"Error occurred: {e}")
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
        raise HTTPException(status_code=404, detail="User not found")
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
async def create_destination(
        DestinationName: str = Form(...),
        Country: str = Form(...),
        Description: Optional[str] = Form(None),
        image: UploadFile = File(None),
        db: AsyncSession = Depends(database.get_db)
):
    logger.info("Received request to create a destination")
    
    if image:
        filename = f"{uuid.uuid4()}{Path(image.filename).suffix}"
        file_path = config.IMAGEDIR / filename

        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        
        title = DestinationName
        src = str(file_path)
    else:
        title = None
        src = None
    
    image_data = schemas.ImageBase(
        title=title,
        src=src,
    )

    destination_data = schemas.DestinationCreate(
        DestinationName=DestinationName,
        Country=Country,
        Description=Description,
        image=image_data
    )

    created_destination = await crud.create_destination(db, destination_data)
    
    if not created_destination:
        raise HTTPException(status_code=500, detail="Failed to create the destination")
    
    logger.info("Package created successfully")
    return created_destination

@app.get("/destinations/", response_model=List[schemas.DestinationInDB])
async def read_destinations(
    response: Response, 
    skip: int = Query(default=0, ge=0), 
    limit: int = Query(default=10, ge=0),
    destination_name: str = Query(None),
    start_date: date = Query(None),
    end_date: date = Query(None),
    db: AsyncSession = Depends(database.get_db)
):
    destinations, total = await crud.get_destinations(
        db, 
        skip=skip, 
        limit=limit,
        destination_name=destination_name, 
        start_date=start_date, 
        end_date=end_date,
    )

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
    updated_destination = await crud.update_destination(db, destination_id, destination)
    if updated_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return updated_destination

@app.delete("/destinations/", response_model=List[int])
async def delete_many_destinations(delete_request: schemas.DeleteManyRequest, db: AsyncSession = Depends(database.get_db)):
    deleted_ids = await crud.delete_many_destinations(db, delete_request.ids)
    if not deleted_ids:
        raise HTTPException(status_code=404, detail="No destinations found with these IDs")
    return deleted_ids

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
        db: AsyncSession = Depends(database.get_db)
):
    logger.info("Received request to create a package")

    package_data = schemas.PackageCreate(
        PackageName=PackageName,
        Description=Description,
        Price=Price,
        Duration=Duration,
        StartDate=StartDate,
        EndDate=EndDate,
        DestinationID=DestinationID
    )

    created_package = await crud.create_package(db, package_data)

    if not created_package:
        raise HTTPException(status_code=500, detail="Failed to create the package")

    logger.info("Package created successfully")
    return created_package
    
@app.get("/packages/", response_model=List[schemas.PackageInDB])
async def read_packages(response: Response, skip: int = 0, limit: int = 10, db: AsyncSession = Depends(database.get_db)):
    packages, total = await crud.get_packages(db, skip, limit)
    response.headers["X-Total-Count"] = str(total)
    return packages

@app.get("/packages-by-destination/{destination_id}", response_model=List[schemas.PackageInDB])
async def read_packages_by_destination(destination_id: int, db: AsyncSession = Depends(database.get_db)):
    packages = await crud.get_packages_by_destination_id(db, destination_id)
    if not packages:
        raise HTTPException(status_code=404, detail="Packages not found")
    return packages

@app.get("/packages/{package_id}", response_model=schemas.PackageInDB)
async def read_package(package_id: int, db: AsyncSession = Depends(database.get_db)):
    package = await crud.get_package(db, package_id)
    if package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return package

@app.put("/packages/{package_id}", response_model=schemas.PackageInDB)
async def update_package(package_id: int, package: schemas.PackageUpdate, db: AsyncSession = Depends(database.get_db)):
    updated_package = await crud.update_package(db, package_id, package)
    if updated_package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return schemas.PackageInDB.from_orm(updated_package)

@app.delete("/packages/", response_model=List[int])
async def delete_many_packages(delete_request: schemas.DeleteManyRequest, db: AsyncSession = Depends(database.get_db)):
    deleted_ids = await crud.delete_many_packages(db, delete_request.ids)
    if not deleted_ids:
        raise HTTPException(status_code=404, detail="No packages found with these IDs")
    return deleted_ids

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
    
    if status == models.BookingStatus.CONFIRMED:
        email_sender = os.getenv("EMAIL_SENDER")
        email_password = os.getenv("EMAIL_PASSWORD")
        try:
            await crud.send_booking_email(email_sender, email_password, user.Email)
        except Exception as e:
            logging.error(f"Failed to send confirmation email: {str(e)}")

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
@app.delete("/bookings/", response_model=List[int])
async def delete_many_bookings(delete_request: schemas.DeleteManyRequest, db: AsyncSession = Depends(database.get_db)):
    deleted_ids = await crud.delete_many_bookings(db, delete_request.ids)
    if not deleted_ids:
        raise HTTPException(status_code=404, detail="No bookings found with these IDs")
    return deleted_ids

# End Of Booking Endpoints

# Payment Endpoints

@app.post("/create-checkout-session")
async def create_checkout_session(request: schemas.CheckoutSessionRequest, db: AsyncSession = Depends(database.get_db)):
    try:
        booking = await crud.get_booking(db, request.booking_id)

        if not booking:
            raise HTTPException(status_code=404, detail="Booking not found")
        
        quantity = booking.NumberOfPeople

        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': request.price_id,
                'quantity': quantity,
            }],
            currency='gbp',
            mode='payment',
            success_url=f"{YOUR_DOMAIN}/payment-success/?success=true&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{YOUR_DOMAIN}/payment-error/?canceled=true&session_id={{CHECKOUT_SESSION_ID}}",
            metadata={'booking_id': str(request.booking_id)},
            automatic_tax={'enabled': True},
        )

        logger.info(f"Complete session details: {session}")

        logger.info(f"Created checkout Session: {session.id}, Payment Intent: {session.payment_intent}")

        # Create a payment record in the database
        await crud.create_payment(db, session.id, session.payment_intent, session.amount_total / 100, request.booking_id)

        return {"url": session.url}
    
    except Exception as e:
        logger.error(f"Error creating checkout session: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/webhook")
async def stripe_webhook(request: Request, db: AsyncSession = Depends(database.get_db)):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')

    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, endpoint_secret
        )
    except ValueError as e:
        logger.error(f"Invalid payload: {e}")
        return JSONResponse(status_code=400, content={"detail": "Invalid payload"})
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Invalid signature: {e}")
        return JSONResponse(status_code=400, content={"detail": "Invalid signature"})
    except Exception as e:
        logger.error(f"Error verifying webhook signature: {e}")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    # Handle the checkout.session.completed event
    try:
        if event['type'] == 'checkout.session.completed':
            session = event['data']['object']
            payment_intent_id = session.get('payment_intent')
            booking_id = session['metadata'].get('booking_id')
            amount_total = session['amount_total'] / 100
            await crud.update_payment(db, session.id, payment_intent_id, amount_total, booking_id)

        # elif event['type'] == 'payment_intent.succeeded':
        #     payment_intent_id = event['data']['object']['id']

        #     # Check for duplicate PaymentIntentID before proceeding
        #     existing_payment = await db.execute(select(models.Payment).filter(models.Payment.PaymentIntentID == payment_intent_id))
        #     if existing_payment.scalars().first():
        #         logger.info(f"PaymentIntentID {payment_intent_id} already exists, skipping insertion.")
        #         return JSONResponse(status_code=200, content={"detail": "Duplicate PaymentIntentID, skipping insertion."})

        #     return await crud.handle_payment_intent_succeeded(event['data'], db)
        
        elif event['type'] == 'payment_intent.payment_failed':
            payment_intent = event['data']['object']
            return await crud.handle_payment_intent_failed(payment_intent, db)
    except Exception as e:
        logger.error(f"Error handling webhook event: {e}")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return JSONResponse(status_code=200, content={"detail": "Success"})


@app.get("/payments/", response_model=List[schemas.PaymentInDB])
async def read_payments(response: Response,  # Include the Response object here (non-default argument)
    skip: int = 0, 
    limit: int = 10, 
    _sort: str = "PaymentID", 
    _order: str = "asc", 
    db: AsyncSession = Depends(database.get_db)):
    try:
        payments = await crud.get_payments(db, page=skip // limit, limit=limit, sort=_sort, order=_order)
        total = await db.scalar(select(func.count()).select_from(models.User))
        response.headers["X-Total-Count"] = str(total)
        return payments
    
    except ValueError as ve:
        logging.error(f"Invalid sort field: {_sort}")
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logging.error(f"Error fetching users: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    
@app.delete("/payments/", response_model=List[int])
async def delete_many_destinations(delete_request: schemas.DeleteManyRequest, db: AsyncSession = Depends(database.get_db)):
    deleted_ids = await crud.delete_many_payments(db, delete_request.ids)
    if not deleted_ids:
        raise HTTPException(status_code=404, detail="No payments found with these IDs")
    return deleted_ids

# End of Payment Endpints

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
    db_review = await crud.delete_review(db, review_id)
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

    return {"success": True, "message": "Password reset link sent", "data": password_reset_token}

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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)