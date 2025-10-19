# Make tests' imports happy by re-exporting models, session, and seeder.

from .models import (  # noqa: F401
    Base,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    UserProfileModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

# Primary session dependency the tests expect
from .session_sqlite import get_db  # noqa: F401

# Some tests/fixtures import a contextmanager helper; expose if present
try:  # noqa: SIM105
    from .session_sqlite import get_db_contextmanager  # type: ignore # noqa: F401
except Exception:  # if absent in this template, that's fine
    # Provide a dummy name so "from database import get_db_contextmanager" doesn't crash import time
    get_db_contextmanager = None  # type: ignore

# Seeder used by tests' fixtures to populate default groups, movies, etc.
# It MUST be importable from `database` so that fixtures can run.
from .populate import CSVDatabaseSeeder  # noqa: F401

__all__ = [
    "Base",
    "UserGroupEnum",
    "UserGroupModel",
    "UserModel",
    "UserProfileModel",
    "ActivationTokenModel",
    "PasswordResetTokenModel",
    "RefreshTokenModel",
    "get_db",
    "get_db_contextmanager",
    "CSVDatabaseSeeder",
]
