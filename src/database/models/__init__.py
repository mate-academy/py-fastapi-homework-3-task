# src/database/models/__init__.py

# 1) База
from .base import Base

# 2) Моделі (акаунти)
from .accounts import (
    UserGroupModel,
    UserModel,
    UserProfileModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
)

# 3) Моделі (фільми)
from .movies import (
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
)

# 4) Сесія / утиліти SQLite (для тестів)
from ..session_sqlite import (
    get_db,
    get_sqlite_db_contextmanager,
    init_db,
    close_db,
    reset_database,
)

# Бек-сумісність: деякі імпорти можуть очікувати старі назви
reset_sqlite_database = reset_database

# 5) Seeder (опційно)
try:
    from ..populate import CSVDatabaseSeeder  # noqa: F401
except ImportError:
    CSVDatabaseSeeder = None  # type: ignore[assignment]

__all__ = [
    # база
    "Base",
    # акаунти
    "UserGroupModel",
    "UserModel",
    "UserProfileModel",
    "ActivationTokenModel",
    "PasswordResetTokenModel",
    "RefreshTokenModel",
    "UserGroupEnum",
    # фільми
    "MovieModel",
    "GenreModel",
    "ActorModel",
    "CountryModel",
    "LanguageModel",
    # сесія / ініт
    "get_db",
    "get_sqlite_db_contextmanager",
    "init_db",
    "close_db",
    "reset_database",
    "reset_sqlite_database",
    # сидер
    "CSVDatabaseSeeder",
]
