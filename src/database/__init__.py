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
    UserGroupEnum,
)

# 3) Моделі (фільми)
from database.models.movies import (
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
    MoviesGenresModel,
    ActorsMoviesModel,
    MoviesLanguagesModel,
)

# 4) Сесія / утиліти SQLite (для тестів)
from database.session_sqlite import (
    get_db,
    get_sqlite_db_contextmanager,
    init_db,
    close_db,
    reset_database,  # фактична функція у session_sqlite.py
)

# Аліаси для сумісності з тестами
reset_sqlite_database = reset_database
get_db_contextmanager = get_sqlite_db_contextmanager

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
    "UserGroupEnum",
    # фільми
    "MovieModel",
    "GenreModel",
    "ActorModel",
    "CountryModel",
    "LanguageModel",
    # таблиці-асоціації
    "MoviesGenresModel",
    "ActorsMoviesModel",
    "MoviesLanguagesModel",
    # сесія / ініт
    "get_db",
    "get_sqlite_db_contextmanager",
    "get_db_contextmanager",
    "init_db",
    "close_db",
    "reset_database",
    "reset_sqlite_database",
    # сидер
    "CSVDatabaseSeeder",
]
