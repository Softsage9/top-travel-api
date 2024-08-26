from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from dotenv import load_dotenv
import os
import ssl
import asyncio
import aiomysql

load_dotenv()

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL")


ssl_context = ssl.create_default_context()
ssl_context.check_hostname = True  # Optional, depending on your setup
ssl_context.verify_mode = ssl.CERT_REQUIRED

cert_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../ca-certificate.crt'))

# Path to your CA certificate
ssl_context.load_verify_locations(cafile=cert_path)

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL, 
    echo=True,
   # connect_args={'ssl': ssl_context},
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
            result = await conn.execute(text("SELECT DATABASE()"))
            db_name = result.fetchone()
            print(f"Connected to database: {db_name[0]}")
    except Exception as e:
        print(f"Error connecting to the database: {e}")


# Run the connection check
if __name__ == "__main__":
    asyncio.run(check_connection())
