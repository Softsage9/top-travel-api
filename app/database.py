from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from dotenv import load_dotenv
import os

load_dotenv()


SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    echo=True,
    pool_pre_ping=True,
    pool_recycle=1800, 
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
)

try:
    with engine.connect() as conn:
        print("Connection is OK!")
except Exception as e:
    print("Error connecting to the database:", e)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()