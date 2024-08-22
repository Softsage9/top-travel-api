from app.models import Base
from logging.config import fileConfig
import asyncio
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from alembic import context
from dotenv import load_dotenv
import os

load_dotenv() 

DATABASE_URL = os.getenv("DATABASE_URL")

target_metadata = Base.metadata

# Custom function to fetch the database URL
def get_db_url():
    # Ensure your database URL is appropriate for aiomysql
    # Example: mysql+aiomysql://user:password@host:port/dbname
    return DATABASE_URL

# Create an asynchronous engine instance
connectable: AsyncEngine = create_async_engine(
    get_db_url(),
    echo=True,  # Turn off in production
    future=True  # Use future flag to enable 2.0 style
)

# Load logging configuration
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Function to run migrations online
async def run_migrations_online():
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
        await connection.close()

def do_run_migrations(connection):
    context.configure(
        connection=connection,
        target_metadata=target_metadata
    )
    with context.begin_transaction():
        context.run_migrations()

def main():
    if context.is_offline_mode():
        raise NotImplementedError("Offline mode is not supported for asynchronous operation.")
    else:
        asyncio.run(run_migrations_online())

if __name__ == '__main__':
    main()
