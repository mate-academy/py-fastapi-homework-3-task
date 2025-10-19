# Re-export models, session helpers, and provide a lazy export for CSVDatabaseSeeder
# to avoid circular imports with database.populate.

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

# Movies models (export everything tests/seeders might need)
from .models.movies import (  # noqa: F401
    MovieModel,
    GenreModel,
    ActorModel,
    CountryModel,
    LanguageModel,
)
from .populate import CSVDatabaseSeeder

# Some templates also expose an association model; export if present
try:  # noqa: SIM105
    from .models.movies import MoviesGenresModel  # type: ignore  # noqa: F401
except Exception:  # not all templates have this
    MoviesGenresModel = None  # type: ignore

# Primary async DB dependency expected by routes/tests
from .session_sqlite import get_db  # noqa: F401

# Some fixtures import a contextmanager helper; provide if available
try:  # noqa: SIM105
    from .session_sqlite import get_db_contextmanager  # type: ignore  # noqa: F401
except Exception:
    get_db_contextmanager = None  # type: ignore


def __getattr__(name: str):
    """
    Lazy attribute loader to avoid circular import with database.populate.

    Tests/fixtures do: `from database import CSVDatabaseSeeder`.
    If we import populate at module import time, it imports `database` back and
    creates a cycle. Loading it lazily here breaks the cycle.
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
