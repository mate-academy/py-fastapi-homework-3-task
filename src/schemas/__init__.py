# src/schemas/__init__.py

# ---- Movies ----
from .movies import (
    MovieBriefSchema,
    MovieFullSchema,
    MoviesListResponse,
    MovieCreateSchema,
    MovieUpdateSchema,
)

# ---- Accounts ----
from .accounts import (
    UserRegistrationRequestSchema,
    UserResponseSchema,                     # фактична відповідь на реєстрацію
    ActivateAccountRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    RefreshRequestSchema,
    RefreshResponseSchema,
    MessageResponse,
)

# Алiас для сумісності з імпортами у тестах:
# Деякі місця (або попередній __init__) очікують UserRegistrationResponseSchema.
UserRegistrationResponseSchema = UserResponseSchema  # type: ignore

__all__ = [
    # Movies
    "MovieBriefSchema",
    "MovieFullSchema",
    "MoviesListResponse",
    "MovieCreateSchema",
    "MovieUpdateSchema",
    # Accounts
    "UserRegistrationRequestSchema",
    "UserResponseSchema",
    "UserRegistrationResponseSchema",  # аліас
    "ActivateAccountRequestSchema",
    "PasswordResetRequestSchema",
    "PasswordResetCompleteRequestSchema",
    "LoginRequestSchema",
    "LoginResponseSchema",
    "RefreshRequestSchema",
    "RefreshResponseSchema",
    "MessageResponse",
]
