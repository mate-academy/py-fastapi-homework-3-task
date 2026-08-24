from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import sessionmaker

from config import get_settings


settings = get_settings()


POSTGRESQL_DATABASE_URL = (
    f"postgresql+asyncpg://"
    f"{settings.POSTGRES_USER}:"
    f"{settings.POSTGRES_PASSWORD}@"
    f"{settings.POSTGRES_HOST}:"
    f"{settings.POSTGRES_DB_PORT}/"
    f"{settings.POSTGRES_DB}"
)


postgresql_engine = None
sync_postgresql_engine = None
AsyncPostgresqlSessionLocal = None


if settings.__class__.__name__ != "TestingSettings":
    postgresql_engine = create_async_engine(
        POSTGRESQL_DATABASE_URL,
        echo=False,
    )

    AsyncPostgresqlSessionLocal = sessionmaker(
        bind=postgresql_engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    sync_database_url = POSTGRESQL_DATABASE_URL.replace(
        "postgresql+asyncpg",
        "postgresql",
    )

    sync_postgresql_engine = create_engine(
        sync_database_url,
        echo=False,
    )


async def get_postgresql_db() -> AsyncGenerator[
    AsyncSession,
    None,
]:
    if AsyncPostgresqlSessionLocal is None:
        raise RuntimeError(
            "PostgreSQL database is not available in testing environment."
        )

    async with AsyncPostgresqlSessionLocal() as session:
        yield session


@asynccontextmanager
async def get_postgresql_db_contextmanager() -> AsyncGenerator[
    AsyncSession,
    None,
]:
    if AsyncPostgresqlSessionLocal is None:
        raise RuntimeError(
            "PostgreSQL database is not available in testing environment."
        )

    async with AsyncPostgresqlSessionLocal() as session:
        yield session
