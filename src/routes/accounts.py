from datetime import datetime, timezone
from typing import cast

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
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema, UserActivationRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        if existing_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user_data.email} already exists."
            )

        hashed_password = hash_password(user_data.password)
        group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER
            )
        )

        if group is None:
            raise HTTPException(
                status_code=500,
                detail="An error occurred during user creation."
            )

        db_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed_password,
            group=group
        )
        db.add(db_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            user_id=db_user.id
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    except HTTPException:
        await db.rollback()
        raise
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        ) from exc

@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    current_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if not current_user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if current_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    user_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == current_user.id,
            ActivationTokenModel.token == user_data.token,
        )
    )

    if user_token is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = user_token.expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    try:
        current_user.is_active = True

        await db.delete(user_token)
        await db.commit()
        return MessageResponseSchema(message="User account activated successfully.")

    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during account activation."
        ) from exc
