# src/database/session_sqlite.py
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from config import get_settings
from database.models.base import Base

settings = get_settings()

SQLITE_DATABASE_URL = f"sqlite+aiosqlite:///{settings.PATH_TO_DB}"

engine = create_async_engine(SQLITE_DATABASE_URL, echo=False, future=True)

# Фабрика асинхронних сесій
AsyncSQLiteSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
    future=True,
)


# ---------------------- Dependency для FastAPI ----------------------
async def get_sqlite_db() -> AsyncGenerator[AsyncSession, None]:
    """Alias для get_db (залишено для сумісності)."""
    async with AsyncSQLiteSessionLocal() as session:
        yield session


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Основний dependency для отримання AsyncSession."""
    async with AsyncSQLiteSessionLocal() as session:
        yield session


@asynccontextmanager
async def get_sqlite_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    """Зручно використовувати в тестах: `async with get_sqlite_db_contextmanager() as db:`."""
    async with AsyncSQLiteSessionLocal() as session:
        yield session


# ---------------------- Ініціалізація / закриття ----------------------
async def init_db() -> None:
    """Створити всі таблиці (create_all). Викликається перед стартом застосунку/тестів."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Закрити engine (після завершення роботи)."""
    await engine.dispose()


# ---------------------- Скидання (для тестів) ----------------------
async def reset_database() -> None:
    """
    Повністю скинути SQLite базу: drop_all + create_all.
    Корисно для тестів, щоб мати чистий стан.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)


# Додатковий аліас для бек-сов сумісності, якщо десь чекають саме таку назву
reset_sqlite_database = reset_database
