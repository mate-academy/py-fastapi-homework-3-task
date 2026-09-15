import os
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseAppSettings(BaseSettings):
    BASE_DIR: Path = Path(__file__).parent.parent
    PATH_TO_DB: str = str(BASE_DIR / "database" / "source" / "theater.db")
    PATH_TO_MOVIES_CSV: str = str(BASE_DIR / "database" / "seed_data" / "imdb_movies.csv")
    LOGIN_TIME_DAYS: int = 7

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


class Settings(BaseAppSettings):
    POSTGRES_USER: str = "test_user"
    POSTGRES_PASSWORD: str = "test_password"
    POSTGRES_HOST: str = "test_host"
    POSTGRES_DB_PORT: int = 5432
    POSTGRES_DB: str = "test_db"

    SECRET_KEY_ACCESS: str = "default_secret_key_access"
    SECRET_KEY_REFRESH: str = "default_secret_key_refresh"
    JWT_SIGNING_ALGORITHM: str = "HS256"


class TestingSettings(BaseAppSettings):
    SECRET_KEY_ACCESS: str = "SECRET_KEY_ACCESS"
    SECRET_KEY_REFRESH: str = "SECRET_KEY_REFRESH"
    JWT_SIGNING_ALGORITHM: str = "HS256"

    def model_post_init(self, __context: dict[str, Any] | None = None) -> None:
        object.__setattr__(self, 'PATH_TO_DB', ":memory:")
        object.__setattr__(
            self,
            'PATH_TO_MOVIES_CSV',
            str(self.BASE_DIR / "database" / "seed_data" / "test_data.csv")
        )
