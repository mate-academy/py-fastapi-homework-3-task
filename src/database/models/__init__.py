# src/database/__init__.py

# 1) База
from database.models.base import Base

# 2) Моделі (акаунти)
from database.models.accounts import (
    UserGroupModel,
    UserModel,
    UserProfileModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

# 3) Моделі (фільми)
from database.models.movies import (
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
)

# 4) Сесія / утиліти SQLite (для тестів)
from database.session_sqlite import (
    get_db,
    get_sqlite_db_contextmanager,
    init_db,
    close_db,
    reset_database,  # фактична функція у session_sqlite.py
)

# Бек-сов сумісність: деякі тести/імпорти можуть очікувати reset_sqlite_database
reset_sqlite_database = reset_database

# 5) Seeder (опціонально)
try:
    from database.populate import CSVDatabaseSeeder  # noqa: F401
except Exception:
    CSVDatabaseSeeder = None

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
    "reset_sqlite_database",  # аліас для сумісності
    # сидер
    "CSVDatabaseSeeder",
]
