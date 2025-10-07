from datetime import datetime, timezone
from typing import cast, Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
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

    token, expires_at = activation_token_manager.create_token()
    expires_at = cast(datetime, expires_at).replace(tzinfo=timezone.utc)
    activation_token = ActivationTokenModel(
        user=user,
        token=token,
        expires_at=expires_at,
    )

    db.add(user)
    db.add(activation_token)
    try:
        await db.commit()
    except SQLAlchemyError as e:
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
    except SQLAlchemyError as e:
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

    token, expires_at = password_reset_token_manager.create_token()
    expires_at = cast(datetime, expires_at).replace(tzinfo=timezone.utc)
    token = PasswordResetTokenModel(
        user=user,
        token=token,
        expires_at=expires_at,
    )

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
    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")
