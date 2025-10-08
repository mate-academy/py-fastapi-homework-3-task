from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.activation_token_manager import activation_token_manager
from security.password_reset_token_manager import password_reset_token_manager
from schemas import (
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

router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema,
)
async def create_user(
    user_data: UserRegistrationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> UserRegistrationResponseSchema:
    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user_group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User group 'user' not found."
        )

    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_group.id
    )

    activation_token = ActivationTokenModel(user=user)

    db.add(user)
    db.add(activation_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema.model_validate(user)


@router.post(
    "/activate/",
)
async def activate_user(
    user_data: UserActivationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with the given email is not exist.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    activation_token = await db.scalar(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == user_data.token)
    )
    if not activation_token_manager.verify_token(
        token=user_data.token,
        token_obj=activation_token,
        user_id=user.id,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    db.add(user)
    try:
        await db.delete(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user activating.",
        )

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
)
async def password_reset(
    user_data: PasswordResetRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    answer = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )
    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    if not user or not user.is_active:
        return answer

    tokens = await db.scalars(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
    )

    if tokens:
        for token in tokens:
            await db.delete(token)

    token = PasswordResetTokenModel(user=user)

    db.add(token)
    await db.commit()
    return answer


@router.post(
    "/reset-password/complete/",
)
async def password_reset_completion(
    user_data: PasswordResetCompleteRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel)
        .where(UserModel.email == user_data.email)
        .options(
            joinedload(UserModel.password_reset_token)
        )
    )
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    token = user.password_reset_token

    if not password_reset_token_manager.verify_token(
        token=user_data.token,
        token_obj=token,
        user_id=user.id,
    ):
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    user.password = user_data.password

    db.add(user)
    try:
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id},
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": user.id},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
    )

    try:
        db.add(RefreshTokenModel.create(user_id=user.id, token=refresh_token, days_valid=settings.LOGIN_TIME_DAYS))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        token_data = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    user_id = token_data.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token payload.",
        )

    token_in_db = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    if not token_in_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
