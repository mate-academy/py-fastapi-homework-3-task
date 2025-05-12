from pydantic_settings import BaseSettings
from functools import lru_cache


class BaseAppSettings(BaseSettings):
    SECRET_KEY_ACCESS: str
    SECRET_KEY_REFRESH: str
    LOGIN_TIME_DAYS: int

    class Config:
        env_file = ".env"


@lru_cache()
def get_settings() -> BaseAppSettings:
    return BaseAppSettings()
