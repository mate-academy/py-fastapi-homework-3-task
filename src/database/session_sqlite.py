# src/database/session_sqlite.py

from __future__ import annotations

import contextlib
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from .models.base import Base

# Використовуємо окремий файл бази для інтеграційних тестів.
# За потреби шлях можна змінити через ENV і підставити тут.
DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Створюємо async-двигун для SQLite
engine: AsyncEngine = create_async_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    poolclass=NullPool,  # уникаємо кешу конекшенів для більш передбачуваних тестів
)

# Фабрика асинхронних сесій
AsyncSQLiteSessionLocal = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    """
    FastAPI dependency-style генератор сесії.
    Використовується роутами як Depends(get_db).
    """
    async with AsyncSQLiteSessionLocal() as session:
        try:
            yield session
        finally:
            # Нічого особливого: контекст сам закриє з’єднання
            pass


@contextlib.asynccontextmanager
async def get_db_contextmanager() -> AsyncIterator[AsyncSession]:
    """
    Зручний async contextmanager для тестів/скриптів:
        async with get_db_contextmanager() as db:
            ...
    """
    async with AsyncSQLiteSessionLocal() as session:
        yield session


async def reset_sqlite_database() -> None:
    """
    Повний скидання схеми: DROP ALL + CREATE ALL.
    Корисно для інтеграційних тестів.
    """
    async with engine.begin() as conn:
        # Операції зі схемою виконуємо через run_sync
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
