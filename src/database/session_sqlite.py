from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from database import Base

_sqlite_engine = None
_AsyncSQLiteSessionLocal = None


def _ensure_sqlite_engine_created():
    global _sqlite_engine, _AsyncSQLiteSessionLocal

    if _sqlite_engine is None:
        from config import get_settings
        settings = get_settings()

        database_url = f"sqlite+aiosqlite:///{settings.PATH_TO_DB}"
        _sqlite_engine = create_async_engine(database_url, echo=False)
        _AsyncSQLiteSessionLocal = sessionmaker(
            bind=_sqlite_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )


async def get_sqlite_db() -> AsyncGenerator[AsyncSession, None]:
    _ensure_sqlite_engine_created()
    async with _AsyncSQLiteSessionLocal() as session:
        yield session


@asynccontextmanager
async def get_sqlite_db_contextmanager() -> AsyncGenerator[AsyncSession, None]:
    _ensure_sqlite_engine_created()
    async with _AsyncSQLiteSessionLocal() as session:
        yield session


async def reset_sqlite_database() -> None:
    _ensure_sqlite_engine_created()
    async with _sqlite_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
