from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from database import Base


def create_postgres_engine():
    from config.dependencies import get_settings  # Ленивая загрузка настроек
    settings = get_settings()
    db_url = settings.SQLALCHEMY_DATABASE_URL
    return create_async_engine(db_url, echo=False)


def get_postgres_sessionmaker():
    engine = create_postgres_engine()
    return sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def get_postgres_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    SessionLocal = get_postgres_sessionmaker()
    async with SessionLocal() as session:
        yield session


async def get_postgres_db() -> AsyncGenerator[AsyncSession, None]:
    SessionLocal = get_postgres_sessionmaker()
    async with SessionLocal() as session:
        yield session


async def reset_postgres_database() -> None:
    engine = create_postgres_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
