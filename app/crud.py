from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
import logging
import random
import smtplib
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError
import asyncio

from fastapi import Depends, HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, select
from starlette import status

from . import models, schemas

from fastapi.security import OAuth2PasswordBearer
from app import database

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
oauth2_admin_scheme = OAuth2PasswordBearer(tokenUrl="admin-login")


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

# Get Users Crud

async def get_user(db: AsyncSession, username: str):
    result = await db.execute(select(models.User).where(models.User.username == username))
    return result.scalars().first()


async def get_all_users(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
):
    result = await db.execute(select(models.User).offset(skip).limit(limit))
    users = result.scalars().all()
    return users


async def get_user_by_id(db: AsyncSession, user_id: int):
    result = await db.execute(select(models.User).where(models.User.UserID == user_id))
    return result.scalars().first()

async def get_user_email(db: AsyncSession, email: str):
    result =  db.execute(select(models.User).filter(models.User.Email == email))
    return result.scalars().first()

async def delete_user(db: AsyncSession, user_id: int):
    user = await get_user_by_id(db, user_id)
    if user is None:
        return None
    await db.delete(user)
    await db.commit()
    return user

async def get_user_by_google_id(db: AsyncSession, google_id: str):
    result = await db.execute(select(models.User).filter(models.User.google_id == google_id))
    return result.scalars().first()

async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(database.get_db)
):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, database.SECRET_KEY, algorithms=[database.ALGORITHM])  # Decoding JWT
        username = payload.get("sub")  # Get user ID from 'sub'

        if username is None:
            raise credential_exception

        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credential_exception

    user = await get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception

    return user

async def get_current_active_user(current_user: schemas.UserInDB = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user

# End Of Get Users Crud

# Authentication Crud

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, password_hash):
    return pwd_context.verify(plain_password, password_hash)


async def authenticate_user(db: AsyncSession, username: str, password: str):
    user = await get_user(db, username)
    if not user:
        logging.error(f"User {username} not found")
        return None
    if not verify_password(password, user.Password):
        logging.error(f"Password for user {username} is incorrect")
        return None
    return user

async def create_access_token(data: dict, db: AsyncSession, user_id: int, expires_delta: timedelta or None = None):
    token = str(uuid.uuid4())
    expiry_date = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode = data.copy()

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    session_token = models.SessionToken(
        token=token,
        user_id=user_id,
        expiry_date=expiry_date
    )

    db.add(session_token)
    await db.commit()  
    await db.refresh(session_token)  

    return encoded_jwt, session_token

async def create_google_session_token(db: AsyncSession, user_id: int, google_access_token: str,
                                expires_delta: timedelta or None = None):
    expiry_date = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))

    session_token = models.SessionToken(
        token=google_access_token,
        user_id=user_id,
        expiry_date=expiry_date
    )

    db.add(session_token)  
    await db.commit() 
    await db.refresh(session_token)  

    return session_token

# End Of Authentication Crud

# Create User Crud

async def create_user(db: AsyncSession, user: schemas.UserCreate):
    db_user = models.User(
        username=user.username,
        Email=user.Email,
        Password=get_password_hash(user.Password),
        FirstName=user.FirstName,
        LastName=user.LastName,
        Phone=user.Phone,
        DateOfBirth=user.DateOfBirth,
        is_verified=False,
        disabled=False,  
    )

    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)

    return db_user

# End Of Create User Crud

def generate_six_digit_code():
    return str(random.randint(100000, 999999))


async def create_session_token(db: AsyncSession, user_id: int):
    activation_code = generate_six_digit_code()

    expiry_date = datetime.now(timezone.utc) + timedelta(days=1)

    account_activation = models.AccountActivation(
        user_id=user_id,
        activation_token=activation_code,
        expiry_date=expiry_date,
    )

    db.add(account_activation)
    await db.commit()
    await db.refresh(account_activation)

    return account_activation


async def get_session_token(db: AsyncSession, token: str):
    logging.info(f"Fetching session token: {token}")
    result = await db.execute(select(models.SessionToken).filter(models.SessionToken.token == token))
    logging.info(f"Query result for token {token}: {result}")
    return result.scalars().first()

async def delete_session_token(db: AsyncSession, token: str):
    logging.info(f"Deleting session token: {token}")
    
    result = await db.execute(select(models.SessionToken).where(models.SessionToken.token == token))
    session_token = result.scalars().first()
    
    if session_token:
        await db.delete(session_token)
        await db.commit()
        logging.info(f"Deleted session token: {token}")
        return True
    
    logging.error(f"Session token {token} not found for deletion")
    return False

# Send Email Verification

async def send_verification_email(email_sender, email_password, email_receiver, code):
    smtp_server = "smtp.gmail.com"
    smtp_port = 465

    message = MIMEMultipart()
    message["From"] = email_sender
    message["To"] = email_receiver
    message["Subject"] = "Verify Your Email Address - Top Travel"
    body = f"""
    Dear Customer,

    Welcome to Top Travel! Thank you for choosing us for your travel needs. Please use the following verification code to activate your account:

    Verification Code: {code}

    This code will expire in 24 hours.

    If you did not request this, please ignore this email.

    Best regards,
    The Top Travel Team
    """
    message.attach(MIMEText(body, 'plain'))

    def send_email():
        try:
            smtp_obj = smtplib.SMTP_SSL(smtp_server, smtp_port)
            smtp_obj.login(email_sender, email_password)
            smtp_obj.send_message(message)
            smtp_obj.quit()
            print('Email sent successfully.')
        except Exception as e:
            print(f"Failed to send verification email: {e}")

    try:
        validate_email(email_receiver)  # Validate email format
        await asyncio.to_thread(send_email)  # Run blocking function in a separate thread
    except EmailNotValidError as e:
        print(f"Invalid email address: {e}")
        
# End Of Send Email Verification

# Reset Password Crud

def create_reset_password_token(email: str):
    data = {"sub": email, "exp": datetime.now(timezone.utc) + timedelta(minutes=10)}
    token = jwt.encode(data, SECRET_KEY, ALGORITHM)
    return token

async def update_user_password(password: str, user_id: int, token: str, db: AsyncSession):
    try:
        result = await db.execute(select(models.User).filter(models.User.UserID == user_id))
        user = result.scalars().first()
        if user:
            user.Password = password
            await db.commit()

            result_token = await db.execute(select(models.PasswordReset).filter(models.PasswordReset.reset_token == token))
            user_token = result_token.scalars().first()
            if user_token:
                user_token.is_used = True
                await db.commit()

            return True
        else:
            return False
    except Exception as e:
        db.rollback()
        print(f"An error occurred: {str(e)}")
        raise


async def delete_reset_password_token(db: AsyncSession, token: str):
    try:
        result_token = await db.execute(select(models.PasswordReset).filter(models.PasswordReset.reset_token == token))
        session_token = result_token.scalars().first()
        if session_token:
            await db.delete(session_token)
            await db.commit()
            return True
        return False
    except SQLAlchemyError as e:
        await db.rollback()
        print(f"An error occurred: {str(e)}")
        return False

async def insert_password_reset_token(user_id: int, reset_token: str, expiry_date: datetime, db: AsyncSession):
    password_reset_token = models.PasswordReset(
        user_id=user_id,
        reset_token=reset_token,
        expiry_date=expiry_date,
    )
    db.add(password_reset_token)
    await db.commit()
    await db.refresh(password_reset_token)
    return password_reset_token


def decode_reset_password_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY,
                             algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        return email
    except JWTError:
        return None
    
# End Of Reset Password Crud

# send reset password email

# End of send reset password email

# Destination Cruds

async def get_destination(db: AsyncSession, destination_id: int):
    result = await db.execute(select(models.Destination).filter(models.Destination.DestinationID == destination_id))
    return result.scalars().first()

async def get_destinations(db: AsyncSession, skip: int = 0, limit: int = 10):
    result = await db.execute(select(models.Destination).offset(skip).limit(limit))
    return result.scalars().all()

async def create_destination(db: AsyncSession, destination: schemas.DestinationCreate):
    db_destination = models.Destination(
        DestinationName=destination.DestinationName,
        Country=destination.Country,
        Description=destination.Description
    )
    db.add(db_destination)
    await db.commit()
    await db.refresh(db_destination)
    return db_destination

async def update_destination(db: AsyncSession, destination_id: int, destination: schemas.DestinationCreate):
    db_destination = await get_destination(db, destination_id)
    if db_destination is None:
        return None
    db_destination.DestinationName = destination.DestinationName
    db_destination.Country = destination.Country
    db_destination.Description = destination.Description
    await db.commit()
    await db.refresh(db_destination)
    return db_destination

async def delete_destination(db: AsyncSession, destination_id: int):
    db_destination = await get_destination(db, destination_id)
    if db_destination is None:
        return None
    await db.delete(db_destination)
    await db.commit()
    return db_destination

# Package Cruds

async def get_package(db: AsyncSession, package_id: int):
    result = await db.execute(select(models.Package).filter(models.Package.PackageID == package_id))
    return result.scalars().first()

async def get_packages(db: AsyncSession, skip: int = 0, limit: int = 10):
    result = await db.execute(select(models.Package).offset(skip).limit(limit))
    return result.scalars().all()

async def create_package(db: AsyncSession, package: schemas.PackageCreate):
    db_package = models.Package(
        PackageName=package.PackageName,
        Description=package.Description,
        Price=package.Price,
        Duration=package.Duration,
        StartDate=package.StartDate,
        EndDate=package.EndDate,
        DestinationID=package.DestinationID
    )
    db.add(db_package)
    await db.commit()
    await db.refresh(db_package)
    return db_package

async def update_package(db: AsyncSession, package_id: int, package: schemas.PackageCreate):
    db_package = await get_package(db, package_id)
    if db_package is None:
        return None
    db_package.PackageName = package.PackageName
    db_package.Description = package.Description
    db_package.Price = package.Price
    db_package.Duration = package.Duration
    db_package.StartDate = package.StartDate
    db_package.EndDate = package.EndDate
    db_package.DestinationID = package.DestinationID
    await db.commit()
    await db.refresh(db_package)
    return db_package

async def delete_package(db: AsyncSession, package_id: int):
    db_package = await get_package(db, package_id)
    if db_package is None:
        return None
    await db.delete(db_package)
    await db.commit()
    return db_package

# End Of Package

# Bookings Cruds

async def get_booking(db: AsyncSession, booking_id: int):
    result = await db.execute(select(models.Booking).filter(models.Booking.BookingID == booking_id))
    return result.scalars().first()

async def get_bookings(db: AsyncSession, skip: int = 0, limit: int = 10):
    result = await db.execute(select(models.Booking).offset(skip).limit(limit))
    return result.scalars().all()

async def get_bookings_by_status(db: AsyncSession, status: models.BookingStatus, skip: int = 0, limit: int = 10):
    result = await db.execute(
        select(models.Booking)
        .options(joinedload(models.Booking.user))
        .filter(models.Booking.Status == status)
        .offset(skip)
        .limit(limit)
    )
    bookings = result.scalars().all()
    
    # Extract and include user details
    bookings_with_user_info = [
        {
            "BookingID": booking.BookingID,
            "UserID": booking.UserID,
            "PackageID": booking.PackageID,
            "BookingDate": booking.BookingDate,
            "Status": booking.Status,
            "NumberOfPeople": booking.NumberOfPeople,
            "UserEmail": booking.user.Email,
            "UserFirstName": booking.user.FirstName,
            "UserLastName": booking.user.LastName
        }
        for booking in bookings
    ]
    
    return bookings_with_user_info

async def create_booking(db: AsyncSession, booking: schemas.BookingCreate):
    db_booking = models.Booking(
        UserID=booking.UserID,
        PackageID=booking.PackageID,
        Status=booking.Status,
        NumberOfPeople=booking.NumberOfPeople
    )
    db.add(db_booking)
    await db.commit()
    await db.refresh(db_booking)

    # Fetch user details
    result = await db.execute(select(models.User).filter(models.User.UserID == booking.UserID))
    user = result.scalars().first()

    return {
        "BookingID": db_booking.BookingID,
        "UserID": db_booking.UserID,
        "PackageID": db_booking.PackageID,
        "BookingDate": db_booking.BookingDate,
        "Status": db_booking.Status,
        "NumberOfPeople": db_booking.NumberOfPeople,
        "UserEmail": user.Email,
        "UserFirstName": user.FirstName,
        "UserLastName": user.LastName
    }


async def update_booking(db: AsyncSession, booking_id: int, booking: schemas.BookingCreate):
    db_booking = await get_booking(db, booking_id)
    if db_booking is None:
        return None
    db_booking.UserID = booking.UserID
    db_booking.PackageID = booking.PackageID
    db_booking.Status = booking.Status
    db_booking.NumberOfPeople = booking.NumberOfPeople
    await db.commit()
    await db.refresh(db_booking)
    return db_booking

async def update_booking_status(db: AsyncSession, booking_id: int, status: models.BookingStatus):
    db_booking = await get_booking(db, booking_id)
    if db_booking:
        db_booking.Status = status
        await db.commit()
        await db.refresh(db_booking)
        return db_booking
    return None

async def delete_booking(db: AsyncSession, booking_id: int):
    db_booking = await get_booking(db, booking_id)
    if db_booking is None:
        return None
    await db.delete(db_booking)
    await db.commit()
    return db_booking

# End Of Bookings

# Review Crud

async def get_review(db: AsyncSession, review_id: int):
    result = await db.execute(select(models.Review).filter(models.Review.ReviewID == review_id))
    return result.scalars().first()

async def get_reviews(db: AsyncSession, skip: int = 0, limit: int = 10):
    result = await db.execute(select(models.Review).offset(skip).limit(limit))
    return result.scalars().all()

async def get_reviews_by_package(db: AsyncSession, package_id: int, skip: int = 0, limit: int = 10):
    result = await db.execute(
        select(models.Review)
        .filter(models.Review.PackageID == package_id)
        .offset(skip)
        .limit(limit)
    )
    reviews = result.scalars().all()
    avg_rating = await db.execute(
        select(func.avg(models.Review.Rating))
        .filter(models.Review.PackageID == package_id)
    )
    avg_rating = avg_rating.scalar()
    
    if avg_rating is None:
        avg_rating = 0.0

    reviews_in_db = [
        schemas.ReviewInDB(
            ReviewID=review.ReviewID,
            UserID=review.UserID,
            PackageID=review.PackageID,
            Rating=review.Rating,
            Comment=review.Comment,
            ReviewDate=review.ReviewDate
        )
        for review in reviews
    ]
    
    return avg_rating, reviews_in_db


async def create_review(db: AsyncSession, review: schemas.ReviewCreate):
    db_review = models.Review(
        UserID=review.UserID,
        PackageID=review.PackageID,
        Rating=review.Rating,
        Comment=review.Comment
    )
    db.add(db_review)
    await db.commit()
    await db.refresh(db_review)
    return db_review

async def update_review(db: AsyncSession, review_id: int, review: schemas.ReviewCreate):
    db_review = await get_review(db, review_id)
    if db_review is None:
        return None
    db_review.UserID = review.UserID
    db_review.PackageID = review.PackageID
    db_review.Rating = review.Rating
    db_review.Comment = review.Comment
    await db.commit()
    await db.refresh(db_review)
    return db_review

async def delete_review(db: AsyncSession, review_id: int):
    db_review = await get_review(db, review_id)
    if db_review is None:
        return None
    await db.delete(db_review)
    await db.commit()
    return db_review

# End Of Review 