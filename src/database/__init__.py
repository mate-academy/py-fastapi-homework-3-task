# 1) Base
from database.models.base import Base

# 2) Account models
from database.models.accounts import (
    UserGroupModel,
    UserModel,
    UserProfileModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

# 3) Movie models
from database.models.movies import (
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
)

# 4) SQLite session / utils (tests)
from database.session_sqlite import (
    get_db,
    get_sqlite_db_contextmanager,
    init_db,
    close_db,
    reset_database,   # actual function
)

# Back-compat alias (some tests/imports may expect this name)
reset_sqlite_database = reset_database

# 5) Seeder (optional)
try:
    from database.populate import CSVDatabaseSeeder  # noqa: F401
except Exception:
    CSVDatabaseSeeder = None

__all__ = [
    "Base",
    # accounts
    "UserGroupModel",
    "UserModel",
    "UserProfileModel",
    "ActivationTokenModel",
    "PasswordResetTokenModel",
    "RefreshTokenModel",
    # movies
    "MovieModel",
    "GenreModel",
    "ActorModel",
    "CountryModel",
    "LanguageModel",
    # session / init
    "get_db",
    "get_sqlite_db_contextmanager",
    "init_db",
    "close_db",
    "reset_database",
    "reset_sqlite_database",
    # seeder
    "CSVDatabaseSeeder",
]
