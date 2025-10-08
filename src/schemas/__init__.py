from .movies import (
    MovieBriefSchema,
    MovieFullSchema,
    MovieDetailSchema,       # alias to MovieFullSchema
    MovieListItemSchema,     # alias to MovieBriefSchema
    MovieListResponseSchema,
    MoviesListResponse,      # legacy alias
    MovieCreateSchema,
    MovieUpdateSchema,
)

from .accounts import (
    UserRegistrationRequestSchema,
    UserResponseSchema,
    ActivateAccountRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    RefreshRequestSchema,
    RefreshResponseSchema,
    MessageResponse,
)

__all__ = [
    # movies
    "MovieBriefSchema",
    "MovieFullSchema",
    "MovieDetailSchema",
    "MovieListItemSchema",
    "MovieListResponseSchema",
    "MoviesListResponse",
    "MovieCreateSchema",
    "MovieUpdateSchema",
    # accounts
    "UserRegistrationRequestSchema",
    "UserResponseSchema",
    "ActivateAccountRequestSchema",
    "PasswordResetRequestSchema",
    "PasswordResetCompleteRequestSchema",
    "LoginRequestSchema",
    "LoginResponseSchema",
    "RefreshRequestSchema",
    "RefreshResponseSchema",
    "MessageResponse",
]
