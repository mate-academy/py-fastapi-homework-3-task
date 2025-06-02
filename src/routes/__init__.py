from schemas.movies import (
    MovieDetailSchema,
    MovieListResponseSchema,
    MovieListItemSchema,
    MovieCreateSchema,
    MovieUpdateSchema,
)
from schemas.accounts import (
    UserBase,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    UserResetPasswordRequestSchema,
    UserLoginRequestSchema,
    RefreshAccessTokenRequest,
    MessageResponseSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from routes.movies import router as movie_router
from routes.accounts import router as accounts_router

__all__ = [
    "movie_router",
    "accounts_router",
]
