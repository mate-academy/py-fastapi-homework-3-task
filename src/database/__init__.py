# Central exports for database package.
# IMPORTANT: do NOT import .populate here to avoid circular imports.
# If tests/fixtures need CSVDatabaseSeeder, we expose it lazily via __getattr__.

from .models.base import Base  # noqa: F401

# Accounts models
from .models.accounts import (  # noqa: F401
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    UserProfileModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

# Movies models (export everything seeders/tests might need)
from .models.movies import (  # noqa: F401
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
)
from .populate import CSVDatabaseSeeder

# Some templates/projects have this association model
try:  # noqa: SIM105
    from .models.movies import MoviesGenresModel  # type: ignore  # noqa: F401
except Exception:
    MoviesGenresModel = None  # type: ignore

# Primary async DB dependency expected by routes/tests
from .session_sqlite import get_db  # noqa: F401

# Some tests/fixtures may still import this helper; provide it if present
try:  # noqa: SIM105
    from .session_sqlite import get_db_contextmanager  # type: ignore  # noqa: F401
except Exception:
    get_db_contextmanager = None  # type: ignore


def __getattr__(name: str):
    """
    Lazy attribute loader to avoid circular import with database.populate.

    Usage in tests/fixtures is typically:
        from database import CSVDatabaseSeeder

    We only import .populate when CSVDatabaseSeeder is actually accessed.
    """
    if name == "CSVDatabaseSeeder":
        from .populate import CSVDatabaseSeeder  # type: ignore
        return CSVDatabaseSeeder
    raise AttributeError(f"module 'database' has no attribute {name!r}")


__all__ = [
    # base
    "Base",
    # accounts
    "UserGroupEnum",
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
    "MoviesGenresModel",
    # session helpers
    "get_db",
    "get_db_contextmanager",
    # seeder (lazy via __getattr__)
    "CSVDatabaseSeeder",
]
