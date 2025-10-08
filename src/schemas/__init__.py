from .movies import (
    MovieBriefSchema,
    MovieFullSchema,
    MovieListResponseSchema,
    MoviesListResponse,  # alias for compatibility
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
