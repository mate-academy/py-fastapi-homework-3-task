# src/database/__init__.py

from typing import TYPE_CHECKING, Any

# 1) Базова модель
from .models.base import Base

# 2) Моделі акаунтів
from .models.accounts import (
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    UserProfileModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

# 3) Моделі фільмів
from .models.movies import (
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
    MoviesGenresModel,
)

# 4) Сесія SQLite (для тестів)
from .session_sqlite import (
    get_db,
    get_db_contextmanager,
    reset_sqlite_database as reset_database,
)

__all__ = [
    # Base
    "Base",
    # Accounts
    "UserGroupEnum",
    "UserGroupModel",
    "UserModel",
    "UserProfileModel",
    "ActivationTokenModel",
    "PasswordResetTokenModel",
    "RefreshTokenModel",
    # Movies
    "MovieModel",
    "GenreModel",
    "ActorModel",
    "CountryModel",
    "LanguageModel",
    "MoviesGenresModel",
    # Session / utils
    "get_db",
    "get_db_contextmanager",
    "reset_database",
    # Seeder (lazy)
    "CSVDatabaseSeeder",
]


# Ліниве завантаження CSVDatabaseSeeder, щоб уникнути циклічного імпорту
def __getattr__(name: str) -> Any:
    if name == "CSVDatabaseSeeder":
        from .populate import CSVDatabaseSeeder
        return CSVDatabaseSeeder
    raise AttributeError(f"module {__name__} has no attribute {name}")


# Це для того, щоб IDE (PyCharm, mypy, pyright) бачили CSVDatabaseSeeder
if TYPE_CHECKING:
    from .populate import CSVDatabaseSeeder
