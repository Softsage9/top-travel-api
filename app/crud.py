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

# Send Email Verification

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


async def get_user_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.Email == email).first()


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

# send reset password email

# send reset password email