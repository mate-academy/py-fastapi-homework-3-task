from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_settings, get_jwt_auth_manager
from crud.accounts import (
    create_user_with_hash_password,
    activate_user_account,
    reset_password,
    request_password_reset_token,
    login_logic, refresh_token_logic
)
from database import get_db
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema, TokenRefreshRequestSchema, TokenRefreshResponseSchema
)
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    new_user = await create_user_with_hash_password(db, user_data)
    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_account(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    return await activate_user_account(db, data.email, data.token)


@router.post("/reset-password/complete/",
             response_model=MessageResponseSchema,
             status_code=status.HTTP_200_OK
             )
async def reset_password_complete(user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    new_password = await reset_password(db, user_data)
    return MessageResponseSchema.model_validate(new_password)


@router.post("/password-reset/request/",
             response_model=MessageResponseSchema,
             status_code=status.HTTP_200_OK)
async def password_reset_request(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    return await request_password_reset_token(user_data, db)


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    return await login_logic(user_data, db, jwt_manager, settings)


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh(
        refresh_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
):
    return await refresh_token_logic(refresh_data, db, jwt_manager)
