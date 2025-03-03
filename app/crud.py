from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import selectinload
import logging
import random
import smtplib
from datetime import date, datetime, timedelta, timezone
import os
from dotenv import load_dotenv
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError
import asyncio
import requests
from fastapi import Depends, HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import and_, asc, desc, func, select, text, update
from starlette import status
import stripe
from . import models, schemas
from app import database

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

load_dotenv()

stripe.api_key = os.getenv("STRIPE_API_KEY")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Get Users Crud

async def get_user(db: AsyncSession, email: str):
    result = await db.execute(select(models.User).where(models.User.Email == email))
    return result.scalars().first()

async def get_all_users(
        db: AsyncSession,
        page: int = 0,
        limit: int = 10,
        sort: str = "UserID",  # Default sort field
        order: str = "asc",  # Default order
):
    try:
        sort_field = getattr(models.User, sort)
        order_by = asc(sort_field) if order == "asc" else desc(sort_field)
        
        result = await db.execute(
            select(models.User)
            .order_by(order_by)
            .offset(page * limit)
            .limit(limit)
        )
        
        users = result.scalars().all()
        return users
    except AttributeError:
        raise ValueError(f"Invalid sort field: {sort}")
    except Exception as e:
        raise RuntimeError(f"Error querying the database: {e}")

async def get_user_by_id(db: AsyncSession, user_id: int):
    logging.info(f"Fetching user with ID: {user_id}")
    result = await db.execute(select(models.User).filter(models.User.UserID == user_id))
    user = result.scalars().first()
    logging.info(f"Retrieved user: {user}")
    return user

async def get_user_email(db: AsyncSession, email: str):
    result = await db.execute(select(models.User).filter(models.User.Email == email))
    return result.scalars().first()

async def delete_user(db: AsyncSession, user_id: int):
    user = await get_user_by_id(db, user_id)
    if user is None:
        return None
    await db.delete(user)
    await db.commit()
    return user

async def delete_many_users(db: AsyncSession, ids: list[int]) -> list[int]:
    query = select(models.User).where(models.User.UserID.in_(ids))
    result = await db.execute(query)
    users = result.scalars().all()
    if not users:
        raise HTTPException(status_code=404, detail="Users not found")
    
    for user in users:
        await db.delete(user)
    await db.commit()
    
    return ids

async def get_user_by_google_id(db: AsyncSession, google_id: str):
    result = await db.execute(select(models.User).filter(models.User.google_id == google_id))
    return result.scalars().first()

async def get_current_user(
        token: str = Depends(schemas.LoginCredentials),
        db: AsyncSession = Depends(database.get_db)
):
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, database.SECRET_KEY, algorithms=[database.ALGORITHM])  # Decoding JWT
        email = payload.get("sub")  # Get user ID from 'sub'

        if email is None:
            raise credential_exception

        token_data = schemas.TokenData(email=email)
    except JWTError:
        raise credential_exception

    user = await get_user_email(db, email=token_data.email)
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


async def authenticate_user(db: AsyncSession, email: str, password: str):
    user = await get_user_email(db, email)
    if not user:
        logging.error(f"User {email} not found")
        return None
    if not verify_password(password, user.Password):
        logging.error(f"Password for user {email} is incorrect")
        return None
    return user

async def create_access_token(data: dict, db: AsyncSession, user_id: int, expires_delta: timedelta or None = None):
    session_token_str = str(uuid.uuid4())  # This is the session token
    expiry_date = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode = data.copy()

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    session_token = models.SessionToken(
        token=encoded_jwt, 
        session_token=session_token_str,  
        user_id=user_id,
        expiry_date=expiry_date
    )

    db.add(session_token)
    await db.commit()  
    await db.refresh(session_token)  

    return encoded_jwt, session_token

async def invalidate_existing_sessions(user_id: int, db: AsyncSession):
    # Correctly prepare and execute a raw SQL statement using `text()`
    sql = text("DELETE FROM session_tokens WHERE user_id = :user_id")
    await db.execute(sql, {"user_id": user_id})
    await db.commit()

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

async def verify_google_token(token: str):
    url = f"https://oauth2.googleapis.com/tokeninfo?id_token={token}"
    response = requests.get(url)
    user_info = response.json()

    if response.status_code != 200 or user_info.get("aud") != os.getenv("GOOGLE_CLIENT_ID"):
        raise HTTPException(status_code=401, detail="Invalid Google token")

    return user_info

# End Of Authentication Crud

# Create User Crud

async def create_user(db: AsyncSession, user: schemas.UserCreate, is_google_login: bool = False):
    db_user = models.User(
        Email=user.Email,
        Password=get_password_hash(user.Password) if not is_google_login else "",
        FirstName=user.FirstName,
        LastName=user.LastName,
        Phone=user.Phone,
        DateOfBirth=user.DateOfBirth,
        google_id=user.google_id,
        is_verified=is_google_login, 
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

    print(f"Created session token for user ID {user_id}: {activation_code}")

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

async def handle_logout(token: str, db: AsyncSession, error_message: str):
    existing_token = await get_session_token(db, token)
    if existing_token is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=error_message)

    await delete_session_token(db, token)
    return {"message": "Logged out successfully"}

# Send Email Verification

async def send_verification_email(email_sender, email_password, email_receiver, code):
    smtp_server = "smtp.ionos.co.uk"
    smtp_port = 587 

    message = MIMEMultipart('alternative')
    message["From"] = email_sender
    message["To"] = email_receiver
    message["Subject"] = "Verify Your Email Address - Top Travel"

    # Define the plain text version of the email
    text = f"""
    Dear Customer,

    Welcome to Top Travel! Thank you for choosing us for your travel needs. Please use the following verification code to activate your account: 
    https://top-travel.uk/activate-account?code={code}

    Verification Code: {code}

    This code will expire in 24 hours.

    If you did not request this, please ignore this email.

    Best regards,
    The Top Travel Team
    """

    # Define the HTML version of the email
    html = f"""
    <html>
    <body>
        <p>Dear Customer,</p>
        <p>Welcome to <strong>Top Travel</strong>! Thank you for choosing us for your travel needs.</p>
        <p>Please use the following verification code to activate your account:</p>
        <p><a href="https://top-travel.uk/activate-account?code={code}">Activate Account</a></p>
        <p>Verification Code: {code} </p>
        <p>This code will expire in 24 hours.</p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Best regards,<br>The Top Travel Team</p>
    </body>
    </html>
    """

    # Create MIMEText objects for the plain text and HTML parts
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')

    # Attach both parts to the MIMEMultipart message
    message.attach(part1)
    message.attach(part2)

    def send_email():
        try:
            logging.info("Connecting to SMTP server")
            smtp_obj = smtplib.SMTP(smtp_server, smtp_port)  # Use smtplib.SMTP for TLS
            smtp_obj.ehlo()  # Identify yourself to the server
            smtp_obj.starttls()  # Upgrade to a secure connection
            smtp_obj.ehlo()  # Re-identify after upgrading
            logging.info("Logging in to SMTP server")
            smtp_obj.login(email_sender, email_password)  # Login to the email server
            logging.info("Sending email")
            smtp_obj.send_message(message)
            smtp_obj.quit()
            logging.info("Email sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send verification email: {e}")

    try:
        # Validate the email format
        validate_email(email_receiver)
        logging.info(f"Email {email_receiver} is valid")
        await asyncio.to_thread(send_email)  # Run the email-sending logic in a thread
    except EmailNotValidError as e:
        logging.error(f"Invalid email address: {e}")

async def send_reset_password_email(email_sender, email_password, email_receiver, reset_code):
    smtp_server = "smtp.ionos.co.uk"
    smtp_port = 587 

    message = MIMEMultipart()
    message["From"] = email_sender
    message["To"] = email_receiver
    message["Subject"] = "Reset Your Password - Top Travel"
    body = f"""
    Dear Customer,

    We received a request to reset your password for your Top Travel account. Please use the following reset code to change your password:

    You can reset your password using the following link:
    https://top-travel.uk/reset-password?secret_token={reset_code}

    This code will expire in 24 hours.

    If you did not request this, please ignore this email.

    Best regards,
    The Top Travel Team
    """
    message.attach(MIMEText(body, 'plain'))

    def send_email():
        try:
            logging.info("Connecting to SMTP server")
            smtp_obj = smtplib.SMTP(smtp_server, smtp_port)  # Use smtplib.SMTP for TLS
            smtp_obj.ehlo()  # Identify yourself to the server
            smtp_obj.starttls()  # Upgrade to a secure connection
            smtp_obj.ehlo()  # Re-identify after upgrading
            logging.info("Logging in to SMTP server")
            smtp_obj.login(email_sender, email_password)  # Login to the email server
            logging.info("Sending email")
            smtp_obj.send_message(message)
            smtp_obj.quit()
            logging.info("Email sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send reset password email: {e}")

    try:
        # Validate the email format
        validate_email(email_receiver)
        logging.info(f"Email {email_receiver} is valid")
        await asyncio.to_thread(send_email)  # Run the email-sending logic in a thread
    except EmailNotValidError as e:
        logging.error(f"Invalid email address: {e}")

async def send_booking_email(email_sender, email_password, email_receiver):
    smtp_server = "smtp.ionos.co.uk"
    smtp_port = 587  # TLS port

    message = MIMEMultipart()
    message["From"] = email_sender
    message["To"] = email_receiver
    message["Subject"] = "Your Booking Has Been Accepted - Top Travel"
    body = """
    Dear Customer,

    Welcome to Top Travel! Thank you for choosing us for your travel needs. Your booking request has been successfully confirmed. This is an automated email. Do not reply to this!

    Best regards,
    The Top Travel Team
    """
    message.attach(MIMEText(body, 'plain'))

    def send_email():
        try:
            logging.info("Connecting to SMTP server")
            smtp_obj = smtplib.SMTP(smtp_server, smtp_port)  # Use smtplib.SMTP for TLS
            smtp_obj.ehlo()  # Identify yourself to the server
            smtp_obj.starttls()  # Upgrade to a secure connection
            smtp_obj.ehlo()  # Re-identify after upgrading
            logging.info("Logging in to SMTP server")
            smtp_obj.login(email_sender, email_password)  # Login to the email server
            logging.info("Sending email")
            smtp_obj.send_message(message)
            smtp_obj.quit()
            logging.info("Email sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send booking email: {e}")

    try:
        # Validate the email format
        validate_email(email_receiver)
        logging.info(f"Email {email_receiver} is valid")
        await asyncio.to_thread(send_email)  # Run the email-sending logic in a thread
    except EmailNotValidError as e:
        logging.error(f"Invalid email address: {e}")

async def send_booking_notification(email_password):
    email_sender = "info@toptravel-albania.com"
    smtp_server = "smtp.ionos.co.uk"
    smtp_port = 587  # TLS port

    message = MIMEMultipart()
    message["From"] = email_sender
    message["To"] = email_sender  # Send notification to yourself
    message["Subject"] = "New Booking Notification - Top Travel"
    body = """
    Dear Admin,

    A new booking has been made. Please log in to the admin panel to view the details.

    Best regards,
    The Top Travel System
    """
    message.attach(MIMEText(body, 'plain'))

    def send_email():
        try:
            logging.info("Connecting to SMTP server")
            smtp_obj = smtplib.SMTP(smtp_server, smtp_port)
            smtp_obj.ehlo()
            smtp_obj.starttls()
            smtp_obj.ehlo()
            logging.info("Logging in to SMTP server")
            smtp_obj.login(email_sender, email_password)
            logging.info("Sending email")
            smtp_obj.send_message(message)
            smtp_obj.quit()
            logging.info("Notification email sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send notification email: {e}")

    try:
        # Validate the admin email format
        validate_email(email_sender)
        logging.info(f"Admin email {email_sender} is valid")
        await asyncio.to_thread(send_email)
    except EmailNotValidError as e:
        logging.error(f"Invalid email address: {e}")
        
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

# Destination Cruds

async def get_destination(db: AsyncSession, destination_id: int):
    result = await db.execute(select(models.Destination).filter(models.Destination.DestinationID == destination_id))
    destination = result.scalars().first()
    if not destination:
        raise HTTPException(status_code=404, detail=f"Destination with ID {destination_id} not found")
    
    response_destination = schemas.DestinationInDB(
        DestinationID=destination.DestinationID,
        DestinationName=destination.DestinationName,
        Country=destination.Country,
        Description=destination.Description,
        image=schemas.ImageBase(
                title=destination.title,
                src=destination.src,
                rawFile=None 
            ) if destination.title and destination.src else None
    )
    
    return response_destination

async def get_destinations(
    db: AsyncSession, 
    skip: int = 0, 
    limit: int = 10, 
    destination_name: Optional[str] = None, 
    start_date: Optional[date] = None, 
    end_date: Optional[date] = None, 
):
    query = select(models.Destination).options(selectinload(models.Destination.packages))

    if destination_name:
        query = query.filter(models.Destination.DestinationName.ilike(f"%{destination_name}%"))

    if start_date or end_date:
        package_conditions = []
        if start_date:
            package_conditions.append(models.Package.StartDate >= start_date)
        if end_date:
            package_conditions.append(models.Package.EndDate <= end_date)

        query = query.join(models.Destination.packages).filter(and_(*package_conditions))

    # Execute the query with pagination
    destinations_result = await db.execute(query.offset(skip).limit(limit))
    
    # Use .unique().scalars() to handle eager loaded collections
    destinations = destinations_result.unique().scalars().all()

    # Count total available results without pagination
    total_count = await db.scalar(
        select(func.count()).select_from(query.subquery())
    )

    # Create response format
    response_destinations = [
        schemas.DestinationInDB(
            DestinationID=destination.DestinationID,
            DestinationName=destination.DestinationName,
            Country=destination.Country,
            Description=destination.Description,
            image=schemas.ImageBase(
                title=destination.title,
                src=destination.src,
                rawFile=None
            )
        )
        for destination in destinations
    ]

    return response_destinations, total_count


async def create_destination(db: AsyncSession, destination: schemas.DestinationCreate):
    try:
        db_destination = models.Destination(
            DestinationName=destination.DestinationName,
            Country=destination.Country,
            Description=destination.Description,
            title=destination.image.title,
            src=destination.image.src,
            rawFile=None
        )
        db.add(db_destination)
        
        await db.commit()
        await db.refresh(db_destination)

        response_destination = schemas.DestinationInDB(
            DestinationID=db_destination.DestinationID,
            DestinationName=db_destination.DestinationName,
            Country=db_destination.Country,
            Description=db_destination.Description,
            image=schemas.ImageBase(
                title=db_destination.title,
                src=db_destination.src,
                rawFile=None  
            )
        )
        
        return response_destination
    except SQLAlchemyError as e:
        await db.rollback()  
        raise HTTPException(status_code=400, detail=str(e))

async def update_destination(db: AsyncSession, destination_id: int, destination_update: schemas.DestinationCreate):
    result = await db.execute(select(models.Destination).filter(models.Destination.DestinationID == destination_id))
    db_destination = result.scalars().first()
    if db_destination is None:
        raise HTTPException(status_code=404, detail=f"Destination with ID {destination_id} not found")
    
    update_data = destination_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_destination, key, value)
    
    await db.commit()
    await db.refresh(db_destination)
    return db_destination

async def delete_many_destinations(db: AsyncSession, ids: list[int]) -> list[int]:
    query = select(models.Destination).where(models.Destination.DestinationID.in_(ids))
    result = await db.execute(query)
    destinations = result.scalars().all()
    if not destinations:
        raise HTTPException(status_code=404, detail="Destinations not found")
    
    for destination in destinations:
        await db.delete(destination)
    await db.commit()
    
    return ids
    

# Package Cruds

async def create_package(db: AsyncSession, package: schemas.PackageCreate) -> schemas.PackageInDB:
    try:
        # Create a new product in Stripe
        stripe_product = stripe.Product.create(
            name=package.PackageName,
            description=package.Description,
        )

        # Create a new price in Stripe
        stripe_price = stripe.Price.create(
            product=stripe_product.id,
            unit_amount=int(package.Price * 100),  # Stripe expects the amount in the smallest currency unit
            currency="gbp",
        )

        # Convert back to GBP
        price_amount = stripe_price.unit_amount / 100
        
        # Create the package instance with the correct price and Stripe IDs
        db_package = models.Package(
            **package.dict(exclude={'Price', 'StripeProductID', 'StripePriceID'}),
            Price=price_amount,
            StripeProductID=stripe_product.id,
            StripePriceID=stripe_price.id
        )

        db.add(db_package)
        await db.commit()
        await db.refresh(db_package)

        # Fetch the related destination information
        destination_result = await db.execute(
            select(models.Destination).filter(models.Destination.DestinationID == db_package.DestinationID)
        )
        destination = destination_result.scalars().first()

        image_info = None
        country = None

        if destination:
            # Since we use Spaces for all images, destination.src should already be the full Spaces URL.
            image_info = {
                "rawFile": destination.rawFile,
                "src": destination.src,  # e.g. "https://top-travel-object-spaces.lon1.digitaloceanspaces.com/filename.jpg"
                "title": destination.title,
            }
            country = destination.Country

        return schemas.PackageInDB(
            PackageID=db_package.PackageID,
            PackageName=db_package.PackageName,
            Description=db_package.Description,
            Country=country,
            Price=db_package.Price,
            Duration=db_package.Duration,
            StartDate=db_package.StartDate,
            EndDate=db_package.EndDate,
            DestinationID=db_package.DestinationID,
            Image=image_info,
            StripeProductID=db_package.StripeProductID,
            StripePriceID=db_package.StripePriceID
        )

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")


async def get_package(db: AsyncSession, package_id: int) -> schemas.PackageInDB:
    # Fetch package by package_id
    result = await db.execute(select(models.Package).filter(models.Package.PackageID == package_id))
    package = result.scalars().first()

    if package is None:
        print(f"Package with ID {package_id} not found")
        return None

    # Fetch destination related to the package
    destination_result = await db.execute(
        select(models.Destination).filter(models.Destination.DestinationID == package.DestinationID)
    )
    destination = destination_result.scalars().first()

    image_info = None
    country = None

    if destination:
        # Check if destination.src already includes '/static/images/'
        if "/static/images/" in destination.src:
            file_name = destination.src  # Use the full path if already included
        else:
            file_name = f"/static/images/{destination.src.split('\\')[-1]}"  # Extract filename and prepend the path

        image_info = schemas.ImageBase(
            rawFile=destination.rawFile,
            src=f"https://server-app-zxcxm.ondigitalocean.app{file_name}",  # Correctly handle the URL construction
            title=destination.title,
        )
        country = destination.Country

    response_package = schemas.PackageInDB(
        PackageID=package.PackageID,
        PackageName=package.PackageName,
        Description=package.Description,
        Price=package.Price,
        Duration=package.Duration,
        StartDate=package.StartDate,
        EndDate=package.EndDate,
        DestinationID=package.DestinationID,
        Image=image_info,
        Country=country,
        StripeProductID=package.StripeProductID,
        StripePriceID=package.StripePriceID
    )
    
    print(f"Fetched package: {response_package}")
    return response_package


async def get_packages(db: AsyncSession, skip: int = 0, limit: int = 10) -> List[schemas.PackageInDB]:
    result = await db.execute(
        select(models.Package).offset(skip).limit(limit)
    )
    packages = result.scalars().all()
    total = await db.scalar(select(func.count()).select_from(models.Package))

    results = []
    for package in packages:
        destination_result = await db.execute(
            select(models.Destination).filter(models.Destination.DestinationID == package.DestinationID)
        )
        destination = destination_result.scalars().first()

        image_info = None
        country = None

        if destination:
            if "/static/images/" in destination.src:
                file_name = destination.src 
            else:
                file_name = f"/static/images/{destination.src.split('\\')[-1]}" 
            
            image_info = {
                "rawFile": destination.rawFile,
                "src": f"https://server-app-zxcxm.ondigitalocean.app{file_name}", 
                "title": destination.title,
            }
            country = destination.Country
        else:
            image_info = None
            country = None

        results.append(schemas.PackageInDB(
            PackageID=package.PackageID,
            PackageName=package.PackageName,
            Description=package.Description,
            Country=country,
            Price=package.Price,
            Duration=package.Duration,
            StartDate=package.StartDate,
            EndDate=package.EndDate,
            DestinationID=package.DestinationID,
            Image=image_info,
            StripeProductID=package.StripeProductID,
            StripePriceID=package.StripePriceID 
        ))

    return results, total

async def get_packages_by_destination_id(db: AsyncSession, destination_id: int) -> List[schemas.PackageInDB]:
    stmt = select(models.Package).filter(models.Package.DestinationID == destination_id)
    result = await db.execute(stmt)
    packages = result.scalars().all()

    results = []
    for package in packages:
        destination_result = await db.execute(
            select(models.Destination).filter(models.Destination.DestinationID == package.DestinationID)
        )
        destination = destination_result.scalars().first()

        image_info = None
        country = None

        if destination:
            # Check if destination.src already includes '/static/images/'
            if "/static/images/" in destination.src:
                file_name = destination.src  # Use the full path directly if it's already included
            else:
                file_name = f"/static/images/{destination.src.split('\\')[-1]}"  # Extract just the filename
            
            image_info = schemas.ImageBase(
                rawFile=destination.rawFile,
                src=f"https://server-app-zxcxm.ondigitalocean.app{file_name}",  # Prepend the base URL properly
                title=destination.title,
            )
            country = destination.Country
            
        results.append(schemas.PackageInDB(
            PackageID=package.PackageID,
            PackageName=package.PackageName,
            Description=package.Description,
            Country=country,
            Price=package.Price,
            Duration=package.Duration,
            StartDate=package.StartDate,
            EndDate=package.EndDate,
            DestinationID=package.DestinationID,
            Image=image_info,
            StripeProductID=package.StripeProductID,
            StripePriceID=package.StripePriceID 
        ))

    return results

async def update_package(db: AsyncSession, package_id: int, package_update: schemas.PackageUpdate) -> schemas.PackageInDB:
    result = await db.execute(select(models.Package).filter(models.Package.PackageID == package_id))
    db_package = result.scalars().first()
    if not db_package:
        raise HTTPException(status_code=404, detail=f"Package with ID {package_id} not found")
    
    try:
        # Update Stripe product details if changed
        if package_update.PackageName or package_update.Description:
            stripe.Product.modify(
                db_package.StripeProductID,
                name=package_update.PackageName or db_package.PackageName,
                description=package_update.Description or db_package.Description,
            )

        # Create a new price in Stripe if the price has changed
        if package_update.Price and package_update.Price != db_package.Price:
            stripe_price = stripe.Price.create(
                product=db_package.StripeProductID,
                unit_amount=int(package_update.Price * 100),  # amount in cents
                currency="usd",  # Adjust as needed
            )
            db_package.StripePriceID = stripe_price.id

        # Update other fields in the local database
        update_data = package_update.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_package, key, value)

        await db.commit()
        await db.refresh(db_package)

        # Fetch destination related to the package to include the Image field in the response
        destination_result = await db.execute(
            select(models.Destination).filter(models.Destination.DestinationID == db_package.DestinationID)
        )
        destination = destination_result.scalars().first()

        image_info = None
        country = None

        if destination:
            # Check if destination.src already includes '/static/images/'
            if "/static/images/" in destination.src:
                file_name = destination.src  # Use the full path if it's already included
            else:
                file_name = f"/static/images/{destination.src.split('\\')[-1]}"  # Extract the filename

            image_info = schemas.ImageBase(
                rawFile=destination.rawFile,
                src=f"https://server-app-zxcxm.ondigitalocean.app{file_name}",  # Construct the full URL
                title=destination.title,
            )
            country = destination.Country

        return schemas.PackageInDB(
            PackageID=db_package.PackageID,
            PackageName=db_package.PackageName,
            Description=db_package.Description,
            Price=db_package.Price,
            Duration=db_package.Duration,
            StartDate=db_package.StartDate,
            EndDate=db_package.EndDate,
            DestinationID=db_package.DestinationID,
            Image=image_info,
            Country=country,
            StripeProductID=db_package.StripeProductID,
            StripePriceID=db_package.StripePriceID
        )

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")


async def delete_package(db: AsyncSession, package_id: int):
    result = await db.execute(select(models.Package).filter(models.Package.PackageID == package_id).options(selectinload(models.Package.destination)))
    package = result.scalars().first()
    if not package:
        raise HTTPException(status_code=404, detail=f"Package with ID {package_id} not found")
    await db.delete(package)
    await db.commit()
    return package

async def delete_many_packages(db: AsyncSession, ids: list[int]) -> list[int]:
    query = select(models.Package).where(models.Package.PackageID.in_(ids))
    result = await db.execute(query)
    packages = result.scalars().all()
    if not packages:
        raise HTTPException(status_code=404, detail="Packages not found")
    
    for package in packages:
        if package.StripeProductID:
            try:
                # Archive the Stripe product
                stripe.Product.modify(
                    package.StripeProductID,
                    active=False
                )
            except stripe.error.StripeError as e:
                raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")
        
        # Delete the package from the database
        await db.delete(package)
    
    # Commit the transaction
    await db.commit()
    
    return ids

# End Of Package

# Bookings Cruds

async def get_bookings(db: AsyncSession, skip: int = 0, limit: int = 10):
    result = await db.execute(select(models.Booking).offset(skip).limit(limit))
    bookings = result.scalars().all()
    total = await db.scalar(select(func.count()).select_from(models.Booking))
    return bookings, total

async def get_booking(db: AsyncSession, booking_id: int):
    result = await db.execute(select(models.Booking).filter(models.Booking.BookingID == booking_id))
    booking = result.scalars().first()
    return booking

async def get_user_bookings(db: AsyncSession, user_id: int):
    result = await db.execute(
        select(models.Booking)
        .options(joinedload(models.Booking.user)) 
        .filter(models.Booking.UserID == user_id)
    )
    bookings = result.scalars().all() 
    return bookings

async def get_bookings_by_status(db: AsyncSession, status: models.BookingStatus, skip: int = 0, limit: int = 10):
    result = await db.execute(
        select(models.Booking)
        .options(joinedload(models.Booking.user))
        .filter(models.Booking.Status == status)
        .offset(skip)
        .limit(limit)
    )
    bookings = result.scalars().all()
    
    bookings_with_user_info = []
    for booking in bookings:
        user = booking.user
        bookings_with_user_info.append({
            "BookingID": booking.BookingID,
            "UserID": booking.UserID,
            "PackageID": booking.PackageID,
            "BookingDate": booking.BookingDate.isoformat(),
            "Status": booking.Status.value,  # Assuming Status is an enum
            "NumberOfPeople": booking.NumberOfPeople,
            "UserEmail": user.Email if user else booking.UserEmail,  # Fallback to booking if no user
            "UserFirstName": user.FirstName if user else booking.UserFirstName,
            "UserLastName": user.LastName if user else booking.UserLastName
        })
    
    return bookings_with_user_info

async def create_booking(db: AsyncSession, booking: schemas.BookingCreate):
    is_guest = booking.UserID is None

    db_booking = models.Booking(
        UserID=booking.UserID,
        PackageID=booking.PackageID,
        Status=booking.Status,
        NumberOfPeople=booking.NumberOfPeople,
        UserEmail=booking.UserEmail if is_guest else None,
        UserFirstName=booking.UserFirstName if is_guest else None,
        UserLastName=booking.UserLastName if is_guest else None
    )
    db.add(db_booking)
    await db.commit()
    await db.refresh(db_booking)

    user_email, user_first_name, user_last_name = None, None, None
    if not is_guest:
        result = await db.execute(select(models.User).where(models.User.UserID == booking.UserID))
        user = result.scalars().first()
        if user:
            user_email = user.Email
            user_first_name = user.FirstName
            user_last_name = user.LastName
    else:
        user_email = booking.UserEmail
        user_first_name = booking.UserFirstName
        user_last_name = booking.UserLastName
    return {
        "BookingID": db_booking.BookingID,
        "UserID": db_booking.UserID,
        "PackageID": db_booking.PackageID,
        "BookingDate": db_booking.BookingDate,
        "Status": db_booking.Status,
        "NumberOfPeople": db_booking.NumberOfPeople,
        "UserEmail": user_email,
        "UserFirstName": user_first_name,
        "UserLastName": user_last_name
    }

async def delete_many_bookings(db: AsyncSession, ids: List[int]) -> List[int]:
    print("Fetching bookings to delete:", ids)
    result = await db.execute(select(models.Booking).filter(models.Booking.BookingID.in_(ids)))
    bookings_to_delete = result.scalars().all()
    
    if not bookings_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bookings not found")

    for booking in bookings_to_delete:
        await db.delete(booking)

    await db.commit()

    return [booking.BookingID for booking in bookings_to_delete]


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

async def create_payment(db: AsyncSession, session_id: str, payment_intent_id: str, amount: int, booking_id: int):
    payment = models.Payment(
        BookingID=booking_id, 
        Amount=amount,
        PaymentMethod="card",
        Status="created",
        SessionID=session_id,
        PaymentIntentID=payment_intent_id
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)
    return payment

async def get_payments(db: AsyncSession,
        page: int = 0,
        limit: int = 10,
        sort: str = "PaymentID",
        order: str = "asc",):
    try:
        sort_field = getattr(models.Payment, sort)
        order_by = asc(sort_field) if order == "asc" else desc(sort_field)
        
        result = await db.execute(
            select(models.Payment)
            .order_by(order_by)
            .offset(page * limit)
            .limit(limit)
        )
        
        payments = result.scalars().all()
        payment_data = []
        
        return payments
    except AttributeError:
        raise ValueError(f"Invalid sort field: {sort}")
    except Exception as e:
        raise RuntimeError(f"Error querying the database: {e}")

async def get_payment_by_session_id(db: AsyncSession, session_id: str):
    async with db as session:
        result = await session.execute(
            select(models.Payment).where(models.Payment.SessionID == session_id)
        )
        payment_record = result.scalars().first()
        return payment_record

async def update_payment_intent_succeeded(db: AsyncSession, session_id: str, payment_intent_id: str, amount_received: float):
    payment = await db.execute(select(models.Payment).where(models.Payment.SessionID == session_id))
    payment = payment.scalar_one_or_none()
    if payment:
        payment.PaymentIntentID = payment_intent_id
        payment.Amount = amount_received
        payment.Status = 'completed'
        payment.PaymentDate = datetime.utcnow()
        await db.commit()

async def update_payment(db: AsyncSession, session_id: str, payment_intent_id: str, amount: float, booking_id: str):
    try:
        # Check if the payment record already exists
        result = await db.execute(select(models.Payment).where(models.Payment.SessionID == session_id))
        payment = result.scalar_one_or_none()

        if payment:
            # Update existing payment record
            payment.PaymentIntentID = payment_intent_id
            payment.Amount = amount
            payment.BookingID = booking_id
            payment.Status = 'completed'
            payment.PaymentDate = datetime.utcnow()
            logger.info("Existing payment record updated successfully.")
        else:
            # Create a new payment record if none exists
            new_payment = models.Payment(
                SessionID=session_id,
                PaymentIntentID=payment_intent_id,
                Amount=amount,
                BookingID=booking_id,
                Status='completed',
                PaymentDate=datetime.utcnow(),
            )
            db.add(new_payment)
            logger.info("New payment record created successfully.")

        # Commit changes to the database
        await db.commit()
        return True

    except SQLAlchemyError as e:
        logger.error(f"Database error during payment update: {str(e)}")
        await db.rollback()
        return False
    except Exception as e:
        logger.error(f"Unexpected error during payment update: {str(e)}")
        await db.rollback()
        return False

async def delete_many_payments(db: AsyncSession, ids: List[int]) -> List[int]:
    print("Fetching payments to delete:", ids)
    result = await db.execute(select(models.Payment).filter(models.Payment.PaymentID.in_(ids)))
    payments_to_delete = result.scalars().all()
    
    if not payments_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payments not found")

    for payment in payments_to_delete:
        await db.delete(payment)

    await db.commit()

    return [payment.PaymentID for payment in payments_to_delete]

async def handle_payment_intent_succeeded(event_data, db: AsyncSession):
    payment_intent = event_data['object']
    payment_intent_id = payment_intent['id']
    amount_received = payment_intent['amount_received'] / 100  # Convert to correct currency format
    booking_id = payment_intent['metadata'].get('booking_id')
    
    # Check if payment exists and update it
    payment = await db.execute(select(models.Payment).where(models.Payment.PaymentIntentID == payment_intent_id))
    payment = payment.scalar_one_or_none()
    
    if payment:
        if payment.Status == 'completed':
            return "Payment already processed and completed"
    
        payment.Amount = amount_received
        payment.Status = 'completed'
        payment.PaymentDate = datetime.utcnow()
        await db.commit()
        return "Payment updated successfully"
    else:
        new_payment = models.Payment(
            PaymentIntentID=payment_intent_id,
            Amount=amount_received,
            BookingID=booking_id,
            Status='completed',
            PaymentDate=datetime.utcnow()
        )
        db.add(new_payment)
        await db.commit()

    return "Payment updated successfully"

async def handle_payment_intent_failed(payment_intent, db: AsyncSession):
    # Extract necessary data from the payment_intent
    payment_intent_id = payment_intent['id']
    error_message = payment_intent['last_payment_error']['message'] if payment_intent['last_payment_error'] else 'Unknown error'
    booking_id = payment_intent['metadata'].get('booking_id')

    # Log the failure and potentially notify the user
    logger.error(f"Payment failed for PaymentIntent {payment_intent_id}: {error_message}")
    # Update database to reflect payment failure
    await mark_payment_as_failed(db, payment_intent_id, booking_id, error_message)
    return JSONResponse(status_code=200, content={"detail": "Payment failure processed"})

async def mark_payment_as_failed(db: AsyncSession, payment_intent_id: str, booking_id: str, error_message: str):
    # Check if a payment record already exists
    stmt = select(models.Payment).where(models.Payment.PaymentIntentID == payment_intent_id)
    result = await db.execute(stmt)
    payment = result.scalar_one_or_none()
    
    if payment:
        payment.Status = 'failed'
        payment.ErrorMessage = error_message
        payment.PaymentDate = datetime.utcnow()
    else:
        # Create a new payment record if it does not exist
        payment = models.Payment(
            PaymentIntentID=payment_intent_id,
            BookingID=booking_id,
            Amount=0.0,
            Status='failed',
            ErrorMessage=error_message,
            PaymentDate=datetime.utcnow()
        )
        db.add(payment)
    
    await db.commit()
    return "Payment status updated to failed"

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