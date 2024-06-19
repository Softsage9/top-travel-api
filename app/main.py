import logging
import os
import uuid
import datetime
from datetime import datetime, timedelta, timezone
import shutil
from pathlib import Path
from typing import Optional
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