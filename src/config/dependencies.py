import os
from typing import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import TestingSettings, Settings, BaseAppSettings
from database import get_db_contextmanager
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager


def get_settings() -> BaseAppSettings:
    environment = os.getenv("ENVIRONMENT", "developing")
    if environment == "testing":
        return TestingSettings()
    return Settings()


def get_jwt_auth_manager(settings: BaseAppSettings = Depends(get_settings)) -> JWTAuthManagerInterface:
    return JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM
    )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with get_db_contextmanager() as session:
        yield session
