import os
import secrets
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings


class BaseAppSettings(BaseSettings):
    BASE_DIR: Path = Path(__file__).parent.parent
    # PATH_TO_DB: str = str(BASE_DIR / "database" / "source" / "theater.db")
    PATH_TO_DB: str = str(BASE_DIR / "theater.db")
    PATH_TO_MOVIES_CSV: str = str(BASE_DIR / "database" / "seed_data" / "imdb_movies.csv")
    LOGIN_TIME_DAYS: int = 7


class Settings(BaseAppSettings):
    SECRET_KEY_ACCESS: str = os.getenv("SECRET_KEY_ACCESS", secrets.token_urlsafe(32))
    SECRET_KEY_REFRESH: str = os.getenv("SECRET_KEY_REFRESH", secrets.token_urlsafe(32))

    JWT_SIGNING_ALGORITHM: str = os.getenv(
        "JWT_SIGNING_ALGORITHM",
        "HS256"
    )


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
