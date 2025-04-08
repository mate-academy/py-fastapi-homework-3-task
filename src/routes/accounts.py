from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.crud import UserCRUD
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError
from schemas import UserRegistrationRequestSchema, UserActivationRequestSchema
from schemas.accounts import (
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager
from services.services import (
    UserService,
    ActivationTokenService,
    PasswordResetService,
    AuthService
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager)
) -> UserRegistrationResponseSchema:
    user_service = UserService(db, jwt_manager)
    try:
        new_user = await user_service.create_user(user_data)
        return UserRegistrationResponseSchema(
            id=new_user.id,
            email=new_user.email,
        )
    except HTTPException as e:
        raise e
    except Exception as error:
        print(error)
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate_user(
        activation_request: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    activation_service = ActivationTokenService(db)
    return await activation_service.activate_user(activation_request)


@router.post(
    "/password-reset/request/",
    response_model=dict,
    status_code=status.HTTP_200_OK
)
async def password_reset(
        request: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> dict:
    return await PasswordResetService(db).request_password_reset(
        cast(str, request.email)
    )


@router.post(
    "/reset-password/complete/",
    response_model=dict,
    status_code=status.HTTP_200_OK
)
async def password_reset_complete(
        request: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> dict:
    service = PasswordResetService(db)
    return await service.complete_password_reset(
        email=cast(str, request.email),
        token=request.token,
        password=request.password
    )


def get_user_crud(db: AsyncSession = Depends(get_db)) -> UserCRUD:
    return UserCRUD(db)


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201
)
async def login(
        request: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
        user_crud: UserCRUD = Depends(get_user_crud)
):
    service = AuthService(
        db=db,
        user_crud=user_crud,
        jwt_manager=jwt_manager,
        settings=settings
    )
    return await service.login(
        email=cast(str, request.email),
        password=request.password
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh(
    request: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    user_crud: UserCRUD = Depends(get_user_crud),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
) -> TokenRefreshResponseSchema:
    service = AuthService(db, user_crud, jwt_manager, settings)
    return await service.refresh_access_token(request.refresh_token)
