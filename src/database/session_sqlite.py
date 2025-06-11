from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from database import Base


def create_sqlite_engine():
    from config.dependencies import get_settings  # Импорт внутри функции, чтобы избежать цикла
    settings = get_settings()
    url = f"sqlite+aiosqlite:///{settings.PATH_TO_DB}"
    return create_async_engine(url, echo=False)


def get_sessionmaker():
    engine = create_sqlite_engine()
    return sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


@asynccontextmanager
async def get_sqlite_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    """
    Асинхронный контекстный менеджер для сессии SQLite.
    """
    SessionLocal = get_sessionmaker()
    async with SessionLocal() as session:
        yield session


async def get_sqlite_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Асинхронный генератор для FastAPI Depends.
    """
    SessionLocal = get_sessionmaker()
    async with SessionLocal() as session:
        yield session


async def reset_sqlite_database() -> None:
    """
    Полный сброс и пересоздание всех таблиц SQLite (для тестов).
    """
    engine = create_sqlite_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
