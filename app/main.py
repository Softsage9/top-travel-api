import logging
import os
import uuid
import datetime
import sqlite3
import csv
from datetime import datetime, timedelta, timezone
import shutil
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv

from fastapi import BackgroundTasks, Depends, File, Form, UploadFile, FastAPI, HTTPException, Query
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette import status

from . import crud, models, schemas
from .database import SessionLocal, engine

models.Base.metadata.create_all(bind=engine)

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

def init_roles(db: Session):
    roles = ["admin", "user"]
    for role_name in roles:
        role = db.query(models.Role).filter_by(RoleName=role_name).first()
        if not role:
            new_role = models.Role(RoleName=role_name)
            db.add(new_role)
            db.commit()

with SessionLocal() as db:
    init_roles(db)

@app.get("/")
async def root():
    return {"message": "Top Travel"}

@app.post("/token", response_model=schemas.SessionToken)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(crud.get_db)):
    user = await crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    # if user.disabled:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Account is disabled",
    #     )
    # if not user.is_verified:
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="Account is not verified.",
    #     )
    jwt_token, session_token = crud.create_access_token(
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
async def logout(session_token: str = Query(None), google_token: str = Query(None), db: Session = Depends(crud.get_db)):
    if session_token:
        existing_token = crud.get_session_token(db, session_token)
        logging.info(f"Existing_token: {existing_token}")
        if existing_token is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session token not found")
        crud.delete_session_token(db, session_token)
        return {"message": "Logged out successfully"}

    elif google_token:
        existing_google_token = crud.get_session_token(db, google_token)
        if existing_google_token is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Google session token not found")
        crud.delete_session_token(db, google_token)
        return {"message": "Google session token deleted successfully"}

    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Neither session token nor Google token provided")


@app.get("/users/me/", response_model=schemas.UserInDB)
async def read_users_me(current_user: schemas.UserInDB = Depends(crud.get_current_active_user)):
    return current_user

@app.post("/users/create", response_model=schemas.UserInDB)
async def create_user_endpoint(user: schemas.UserCreate, db: Session = Depends(crud.get_db)):
    existing_user = db.query(models.User).filter(
        (models.User.username == user.username) | (models.User.Email == user.Email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username or email already taken"
        )
    try:
        new_user = await crud.create_user(db, user)
        # session_token = crud.create_session_token(db, new_user.id)
        # activation_token = session_token.activation_token
        # email_sender = os.getenv("EMAIL_SENDER")
        # email_password = os.getenv("EMAIL_PASSWORD")
        # await crud.send_verification_email(email_sender, email_password, user.email, activation_token)
        role = db.query(models.Role).filter_by(RoleName=user.Role).first()
        if not role:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Role not found")
    
        user_role = models.UserRole(
            UserID=new_user.UserID,
            RoleID=role.RoleID
        )
        db.add(user_role)
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

    return new_user

# Destination Endpoints

@app.post("/destinations/", response_model=schemas.DestinationInDB)
def create_destination(destination: schemas.DestinationCreate, db: Session = Depends(crud.get_db)):
    return crud.create_destination(db, destination)

@app.get("/destinations/", response_model=List[schemas.DestinationInDB])
def read_destinations(skip: int = 0, limit: int = 10, db: Session = Depends(crud.get_db)):
    destinations = crud.get_destinations(db, skip=skip, limit=limit)
    return destinations

@app.get("/destinations/{destination_id}", response_model=schemas.DestinationInDB)
def read_destination(destination_id: int, db: Session = Depends(crud.get_db)):
    db_destination = crud.get_destination(db, destination_id)
    if db_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return db_destination

@app.put("/destinations/{destination_id}", response_model=schemas.DestinationInDB)
def update_destination(destination_id: int, destination: schemas.DestinationCreate, db: Session = Depends(crud.get_db)):
    db_destination = crud.update_destination(db, destination_id, destination)
    if db_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return db_destination

@app.delete("/destinations/{destination_id}", response_model=schemas.DestinationInDB)
def delete_destination(destination_id: int, db: Session = Depends(crud.get_db)):
    db_destination = crud.delete_destination(db, destination_id)
    if db_destination is None:
        raise HTTPException(status_code=404, detail="Destination not found")
    return db_destination

# End of Destination Endpoints

# Package Endpoints

@app.post("/packages/", response_model=schemas.PackageInDB)
def create_package(package: schemas.PackageCreate, db: Session = Depends(crud.get_db)):
    return crud.create_package(db, package)

@app.get("/packages/", response_model=List[schemas.PackageInDB])
def read_packages(skip: int = 0, limit: int = 10, db: Session = Depends(crud.get_db)):
    packages = crud.get_packages(db, skip=skip, limit=limit)
    return packages

@app.get("/packages/{package_id}", response_model=schemas.PackageInDB)
def read_package(package_id: int, db: Session = Depends(crud.get_db)):
    db_package = crud.get_package(db, package_id)
    if db_package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return db_package

@app.put("/packages/{package_id}", response_model=schemas.PackageInDB)
def update_package(package_id: int, package: schemas.PackageCreate, db: Session = Depends(crud.get_db)):
    db_package = crud.update_package(db, package_id, package)
    if db_package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return db_package

@app.delete("/packages/{package_id}", response_model=schemas.PackageInDB)
def delete_package(package_id: int, db: Session = Depends(crud.get_db)):
    db_package = crud.delete_package(db, package_id)
    if db_package is None:
        raise HTTPException(status_code=404, detail="Package not found")
    return db_package

# End of Package Endpoints

# Booking Endpoints

@app.post("/bookings/", response_model=schemas.BookingInDB)
def create_booking(booking: schemas.BookingCreate, db: Session = Depends(crud.get_db)):
    return crud.create_booking(db, booking)

@app.get("/bookings/", response_model=List[schemas.BookingInDB])
def read_bookings(skip: int = 0, limit: int = 10, db: Session = Depends(crud.get_db)):
    bookings = crud.get_bookings(db, skip=skip, limit=limit)
    results = []
    for booking in bookings:
        user = db.query(models.User).filter(models.User.UserID == booking.UserID).first()
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
def read_pending_bookings(skip: int = 0, limit: int = 10, db: Session = Depends(crud.get_db)):
    db_bookings = crud.get_bookings_by_status(db, models.BookingStatus.PENDING, skip=skip, limit=limit)
    
    bookings_with_user_info = [
        schemas.BookingInDB(
            BookingID=booking.BookingID,
            BookingDate=booking.BookingDate,
            Status=booking.Status,
            NumberOfPeople=booking.NumberOfPeople,
            UserID=booking.UserID,
            PackageID=booking.PackageID,
            UserEmail=email,
            UserFirstName=first_name,
            UserLastName=last_name
        ) for booking, email, first_name, last_name in db_bookings
    ]
    
    return bookings_with_user_info

@app.get("/bookings/{booking_id}", response_model=schemas.BookingInDB)
def read_booking(booking_id: int, db: Session = Depends(crud.get_db)):
    db_booking = crud.get_booking(db, booking_id)
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
def update_booking(booking_id: int, booking: schemas.BookingCreate, db: Session = Depends(crud.get_db)):
    db_booking = crud.update_booking(db, booking_id, booking)
    if db_booking is None:
        raise HTTPException(status_code=404, detail="Booking not found")
    return db_booking

@app.put("/bookings/{booking_id}/status", response_model=schemas.BookingInDB)
def update_booking_status(booking_id: int, status: models.BookingStatus, db: Session = Depends(crud.get_db)):
    db_booking = crud.update_booking_status(db, booking_id, status)
    if db_booking is None:
        raise HTTPException(status_code=404, detail="Booking not found")
    user = db.query(models.User).filter(models.User.UserID == db_booking.UserID).first()
    return schemas.BookingInDB(
        BookingID=db_booking.BookingID,
        BookingDate=db_booking.BookingDate,
        Status=db_booking.Status,
        UserEmail=user.Email,
        UserFirstName=user.FirstName,
        UserLastName=user.LastName
    )

@app.delete("/bookings/{booking_id}", response_model=schemas.BookingInDB)
def delete_booking(booking_id: int, db: Session = Depends(crud.get_db)):
    db_booking = crud.delete_booking(db, booking_id)
    if db_booking is None:
        raise HTTPException(status_code=404, detail="Booking not found")
    return db_booking

# End Of Booking Endpoints

# Review Endpoints

@app.post("/reviews/", response_model=schemas.ReviewInDB)
def create_review(review: schemas.ReviewCreate, db: Session = Depends(crud.get_db)):
    return crud.create_review(db, review)

@app.get("/reviews/", response_model=List[schemas.ReviewInDB])
def read_reviews(skip: int = 0, limit: int = 10, db: Session = Depends(crud.get_db)):
    reviews = crud.get_reviews(db, skip=skip, limit=limit)
    return reviews

@app.get("/reviews/{review_id}", response_model=schemas.ReviewInDB)
def read_review(review_id: int, db: Session = Depends(crud.get_db)):
    db_review = crud.get_review(db, review_id)
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return db_review

@app.get("/reviews/package/{package_id}", response_model=schemas.PackageReviews)
def read_reviews_by_package(package_id: int, skip: int = 0, limit: int = 10, db: Session = Depends(crud.get_db)):
    avg_rating, reviews = crud.get_reviews_by_package(db, package_id, skip=skip, limit=limit)
    return schemas.PackageReviews(
        average_rating=avg_rating,
        reviews=reviews
    )

@app.put("/reviews/{review_id}", response_model=schemas.ReviewInDB)
def update_review(review_id: int, review: schemas.ReviewCreate, db: Session = Depends(crud.get_db)):
    db_review = crud.update_review(db, review_id, review)
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return db_review

@app.delete("/reviews/{review_id}", response_model=schemas.ReviewInDB)
def delete_review(review_id: int, db: Session = Depends(crud.get_db)):
    db_review = crud.delete_review(db, review_id)
    if db_review is None:
        raise HTTPException(status_code=404, detail="Review not found")
    return db_review

# End Of Review Endpoints
