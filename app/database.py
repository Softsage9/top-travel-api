from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from dotenv import load_dotenv
import os
import asyncio

load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL, 
    echo=True,
    pool_pre_ping=True,
    pool_recycle=1800, 
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
)

async_session = sessionmaker(
    bind=engine, 
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()

async def get_db():
    async with async_session() as session:
        yield session

# Optional function to check the connection asynchronously
async def check_connection():
    try:
        async with engine.connect() as conn:
            await conn.execute("SELECT 1")
        print("Connection is OK!")
    except Exception as e:
        print("Error connecting to the database:", e)

# Run the connection check
if __name__ == "__main__":
    asyncio.run(check_connection())
