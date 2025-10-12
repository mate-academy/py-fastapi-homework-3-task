from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from config import get_settings
from .models.base import Base

_settings = get_settings()

SQLITE_DATABASE_URL = f"sqlite+aiosqlite:///{_settings.PATH_TO_DB}"
engine = create_async_engine(SQLITE_DATABASE_URL, echo=False, future=True)
AsyncSQLiteSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    future=True,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Основна залежність для FastAPI роутів."""
    async with AsyncSQLiteSessionLocal() as session:
        yield session


# Залишаємо сумісні синоніми, бо їх може використовувати існуючий код/тести.
async def get_sqlite_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSQLiteSessionLocal() as session:
        yield session


@asynccontextmanager
async def get_sqlite_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSQLiteSessionLocal() as session:
        yield session


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    await engine.dispose()


async def reset_database() -> None:
    """Скидає БД (для тестів)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
