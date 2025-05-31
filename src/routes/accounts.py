from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.accounts import create_user, activate_account, reset_password, complete_reset_password, login, refresh
from database import get_db
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    return await create_user(user=user, db=db)


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate(activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    return await activate_account(db=db, user_data=activation_data)


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset_token(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    return await reset_password(db=db, user_data=user_data)


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_password_complete(user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    return await complete_reset_password(user_data=user_data, db=db)


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    return await login(data=data, db=db, settings=settings, jwt_manager=jwt_manager)


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
    token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    return await refresh(token=token, db=db, jwt_manager=jwt_manager)
