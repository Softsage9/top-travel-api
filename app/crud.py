from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import random
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
import os
from dotenv import load_dotenv
import uuid
from typing import Optional

from fastapi import BackgroundTasks, Depends, HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, update
from sqlalchemy.orm import Session
from starlette import status

from . import models, schemas

from fastapi.security import OAuth2PasswordBearer

from .database import SessionLocal

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
oauth2_admin_scheme = OAuth2PasswordBearer(tokenUrl="admin-login")


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Get Users Crud

def get_user(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def get_all_users(
        db: Session,
        skip: int = 0,
        limit: int = 100,
):
    query = db.query(models.User)
    return query.offset(skip).limit(limit).all()


def get_user_by_id(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

async def get_user_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.Email == email).first()

def delete_user(db: Session, user_id: int):
    user = get_user_by_id(db, user_id)
    if user is None:
        return None
    db.delete(user)
    db.commit()
    return user

def get_user_by_google_id(db: Session, google_id: str):
    return db.query(models.User).filter(models.User.google_id == google_id).first()

async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: Session = Depends(get_db)
):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Decoding JWT
        username = payload.get("sub")  # Get user ID from 'sub'

        if username is None:
            raise credential_exception

        token_data = schemas.TokenData(username=username)
    except jwt.JWTError:
        raise credential_exception

    user = get_user(db, username=token_data.username)
    if user in None:
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


async def authenticate_user(db: Session, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        logging.error(f"User {username} not found")
        return None
    if not verify_password(password, user.Password):
        logging.error(f"Password for user {username} is incorrect")
        return None
    return user

def create_access_token(data: dict, db: Session, user_id: int, expires_delta: timedelta or None = None):
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
    db.commit()  
    db.refresh(session_token)  

    return encoded_jwt, session_token

def create_google_session_token(db: Session, user_id: int, google_access_token: str,
                                expires_delta: timedelta or None = None):
    expiry_date = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))

    session_token = models.SessionToken(
        token=google_access_token,
        user_id=user_id,
        expiry_date=expiry_date
    )

    db.add(session_token)  
    db.commit() 
    db.refresh(session_token)  

    return session_token

# End Of Authentication Crud

# Create User Crud

async def create_user(db: Session, user: schemas.UserCreate):
    db_user = models.User(
        username=user.username,
        Email=user.Email,
        Password=get_password_hash(user.Password), 
        FirstName=user.FirstName,
        LastName=user.LastName,
        Phone=user.Phone,
        DateOfBirth=user.DateOfBirth,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return db_user

# End Of Create User Crud

def generate_six_digit_code():
    return str(random.randint(100000, 999999))


def create_session_token(db: Session, user_id: int):
    activation_code = generate_six_digit_code()

    expiry_date = datetime.now(timezone.utc) + timedelta(days=1)

    account_activation = models.AccountActivation(
        user_id=user_id,
        activation_token=activation_code,
        expiry_date=expiry_date,
    )

    db.add(account_activation)
    db.commit()
    db.refresh(account_activation)

    return account_activation


def get_session_token(db: Session, token: str):
    logging.info(f"Fetching session token: {token}")
    result = db.query(models.SessionToken).filter(models.SessionToken.token == token).first()
    logging.info(f"Query result for token {token}: {result}")
    return result


def delete_session_token(db: Session, token: str):
    logging.info(f"Deleting session token: {token}")
    session_token = db.query(models.SessionToken).filter(models.SessionToken.token == token).first()
    if session_token:
        db.delete(session_token)
        db.commit()
        logging.info(f"Deleted session token: {token}")
        return True
    logging.error(f"Session token {token} not found for deletion")
    return False

# Send Email Verification

# End Of Send Email Verification

# Reset Password Crud

def create_reset_password_token(email: str):
    data = {"sub": email, "exp": datetime.now(timezone.utc) + timedelta(minutes=10)}
    token = jwt.encode(data, SECRET_KEY, ALGORITHM)
    return token


async def update_user_password(password: str, user_id: int, token: str, db: Session):
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if user:
            user.Password = password
            db.commit()

            user_token = db.query(models.PasswordReset).filter(models.PasswordReset.reset_token == token).first()
            if user_token:
                user_token.is_used = True
                db.commit()

            return True
        else:
            return False
    except Exception as e:
        db.rollback()
        print(f"An error occurred: {str(e)}")
        raise


async def delete_reset_password_token(db: Session, token: str):
    try:
        session_token = db.query(models.PasswordReset).filter(models.PasswordReset.reset_token == token).first()
        if session_token:
            db.delete(session_token)
            db.commit()
            return True
        return False
    except Exception as e:
        db.rollback()
        print(f"An error occurred: {str(e)}")
        return False

async def insert_password_reset_token(user_id: int, reset_token: str, expiry_date: datetime, db: Session):
    password_reset_token = models.PasswordReset(
        user_id=user_id,
        reset_token=reset_token,
        expiry_date=expiry_date,
    )
    db.add(password_reset_token)
    db.commit()
    db.refresh(password_reset_token)
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

def get_destination(db: Session, destination_id: int):
    return db.query(models.Destination).filter(models.Destination.DestinationID == destination_id).first()

def get_destinations(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Destination).offset(skip).limit(limit).all()

def create_destination(db: Session, destination: schemas.DestinationCreate):
    db_destination = models.Destination(
        DestinationName=destination.DestinationName,
        Country=destination.Country,
        Description=destination.Description
    )
    db.add(db_destination)
    db.commit()
    db.refresh(db_destination)
    return db_destination

def update_destination(db: Session, destination_id: int, destination: schemas.DestinationCreate):
    db_destination = get_destination(db, destination_id)
    if db_destination is None:
        return None
    db_destination.DestinationName = destination.DestinationName
    db_destination.Country = destination.Country
    db_destination.Description = destination.Description
    db.commit()
    db.refresh(db_destination)
    return db_destination

def delete_destination(db: Session, destination_id: int):
    db_destination = get_destination(db, destination_id)
    if db_destination is None:
        return None
    db.delete(db_destination)
    db.commit()
    return db_destination

# Package Cruds

def get_package(db: Session, package_id: int):
    return db.query(models.Package).filter(models.Package.PackageID == package_id).first()

def get_packages(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Package).offset(skip).limit(limit).all()

def create_package(db: Session, package: schemas.PackageCreate):
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
    db.commit()
    db.refresh(db_package)
    return db_package

def update_package(db: Session, package_id: int, package: schemas.PackageCreate):
    db_package = get_package(db, package_id)
    if db_package is None:
        return None
    db_package.PackageName = package.PackageName
    db_package.Description = package.Description
    db_package.Price = package.Price
    db_package.Duration = package.Duration
    db_package.StartDate = package.StartDate
    db_package.EndDate = package.EndDate
    db_package.DestinationID = package.DestinationID
    db.commit()
    db.refresh(db_package)
    return db_package

def delete_package(db: Session, package_id: int):
    db_package = get_package(db, package_id)
    if db_package is None:
        return None
    db.delete(db_package)
    db.commit()
    return db_package

# End Of Package

# Bookings Cruds

def get_booking(db: Session, booking_id: int):
    return db.query(models.Booking).filter(models.Booking.BookingID == booking_id).first()

def get_bookings(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Booking).offset(skip).limit(limit).all()

def get_bookings_by_status(db: Session, status: models.BookingStatus, skip: int = 0, limit: int = 10):
    return db.query(
        models.Booking,
        models.User.Email,
        models.User.FirstName,
        models.User.LastName
    ).join(
        models.User, models.Booking.UserID == models.User.UserID
    ).filter(
        models.Booking.Status == status
    ).offset(skip).limit(limit).all()

def create_booking(db: Session, booking: schemas.BookingCreate):
    db_booking = models.Booking(
        UserID=booking.UserID,
        PackageID=booking.PackageID,
        Status=booking.Status,
        NumberOfPeople=booking.NumberOfPeople
    )
    db.add(db_booking)
    db.commit()
    db.refresh(db_booking)

    # Fetch user details
    user = db.query(models.User).filter(models.User.UserID == booking.UserID).first()

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


def update_booking(db: Session, booking_id: int, booking: schemas.BookingCreate):
    db_booking = get_booking(db, booking_id)
    if db_booking is None:
        return None
    db_booking.UserID = booking.UserID
    db_booking.PackageID = booking.PackageID
    db_booking.Status = booking.Status
    db_booking.NumberOfPeople = booking.NumberOfPeople
    db.commit()
    db.refresh(db_booking)
    return db_booking

def update_booking_status(db: Session, booking_id: int, status: models.BookingStatus):
    db_booking = get_booking(db, booking_id)
    if db_booking:
        db_booking.Status = status
        db.commit()
        db.refresh(db_booking)
        return db_booking
    return None

def delete_booking(db: Session, booking_id: int):
    db_booking = get_booking(db, booking_id)
    if db_booking is None:
        return None
    db.delete(db_booking)
    db.commit()
    return db_booking

# End Of Bookings

# Review Crud

def get_review(db: Session, review_id: int):
    return db.query(models.Review).filter(models.Review.ReviewID == review_id).first()

def get_reviews(db: Session, skip: int = 0, limit: int = 10):
    return db.query(models.Review).offset(skip).limit(limit).all()

def get_reviews_by_package(db: Session, package_id: int, skip: int = 0, limit: int = 10):
    reviews = db.query(models.Review).filter(models.Review.PackageID == package_id).offset(skip).limit(limit).all()
    avg_rating = db.query(func.avg(models.Review.Rating)).filter(models.Review.PackageID == package_id).scalar()
    return avg_rating, reviews

def create_review(db: Session, review: schemas.ReviewCreate):
    db_review = models.Review(
        UserID=review.UserID,
        PackageID=review.PackageID,
        Rating=review.Rating,
        Comment=review.Comment
    )
    db.add(db_review)
    db.commit()
    db.refresh(db_review)
    return db_review

def update_review(db: Session, review_id: int, review: schemas.ReviewCreate):
    db_review = get_review(db, review_id)
    if db_review is None:
        return None
    db_review.UserID = review.UserID
    db_review.PackageID = review.PackageID
    db_review.Rating = review.Rating
    db_review.Comment = review.Comment
    db.commit()
    db.refresh(db_review)
    return db_review

def delete_review(db: Session, review_id: int):
    db_review = get_review(db, review_id)
    if db_review is None:
        return None
    db.delete(db_review)
    db.commit()
    return db_review

# End Of Review 