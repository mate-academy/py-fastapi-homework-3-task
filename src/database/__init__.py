import os

from .models.base import Base
from .models.accounts import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from .models.movies import (
    MovieModel,
    LanguageModel,
    ActorModel,
    GenreModel,
    CountryModel,
    MoviesGenresModel,
    ActorsMoviesModel,
    MoviesLanguagesModel
)
from .session_sqlite import reset_sqlite_database as reset_database
from .validators import accounts as accounts_validators

environment = os.getenv("ENVIRONMENT", "developing")

if environment == "testing":
    from .session_sqlite import (
        get_sqlite_db_contextmanager as get_db_contextmanager,
        get_sqlite_db as get_db
    )
else:
    from .session_postgresql import (
        get_postgresql_db_contextmanager as get_db_contextmanager,
        get_postgresql_db as get_db
    )
