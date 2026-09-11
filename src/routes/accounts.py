from datetime import datetime, timezone
from http import HTTPStatus
from http.client import HTTPResponse
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.sql import crud

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
from security import passwords
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import UserCreate, UserRead, AccountActivation, UserBase, ResetPassword
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/", response_model=UserRead, status_code=status.HTTP_201_CREATED,)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    if await db.scalar(select(UserModel).where(UserModel.email == user.email)):
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")

    user_group = await db.scalar(
        select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )

    if user_group is None:
        raise HTTPException(
            status_code=500,
            detail="Default user group not found.",
        )

    try:
        new_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
    account: AccountActivation,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(
            UserModel.email == account.email
        )
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == account.token,
        )
    )

    if activation_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    expires_at = activation_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(activation_token)
        await db.commit()

    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        ) from error

    return {
        "message": "User account activated successfully."
    }


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    user_data: UserBase,
    db: AsyncSession = Depends(get_db),
):
    response = {
        "message": (
            "If you are registered, you will receive "
            "an email with instructions."
        )
    }

    try:
        user = await db.scalar(
            select(UserModel).where(
                UserModel.email == user_data.email
            )
        )

        if user is None or not user.is_active:
            return response

        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        new_token = PasswordResetTokenModel(
            user_id=user.id
        )
        db.add(new_token)

        await db.commit()

    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while requesting a password reset.",
        ) from error

    return response
@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
        reset_pass: ResetPassword,
        db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(
        select(UserModel).where(
            UserModel.email == reset_pass.email
        )
    )
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if token.token != reset_pass.token:
        await db.delete(token)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        if reset_pass.password:
            user.password = reset_pass.password
            await db.delete(token)
            await db.commit()
            await db.refresh(user)
            return {
                "message": "Password reset successfully."
            }

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )
