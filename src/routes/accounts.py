from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete, text
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
from security.passwords import hash_password
from src.schemas import accounts


router = APIRouter()


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == email)
        .options(joinedload(UserModel.group))
    )
    return result.unique().scalar_one_or_none()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=accounts.UserRegistrationResponseSchema
)
async def register_user(
    data: accounts.UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> UserModel:
    user = await get_user_by_email(db, data.email)

    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A user with this email {user.email}"
                " already exists."
            )
        )

    try:
        group_result = await db.execute(
            select(UserGroupModel)
            .where(UserGroupModel.name == UserGroupEnum.USER.value)
        )
        group = group_result.scalar_one()
        user = UserModel.create(
            email=data.email,
            raw_password=data.password,
            group_id=group.id
        )

        db.add(user)
        await db.commit()
        await db.refresh(user)

        activation_token = ActivationTokenModel(user_id=user.id)

        db.add(activation_token)
        await db.commit()

        return user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=accounts.MessageResponseSchema)
async def activate_user_account(
    data: accounts.UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(db, data.email)

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already activate."
        )

    activation_token_result = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == user.activation_token)
    )
    activation_token = activation_token_result.scalar_one_or_none()
    expires_at = cast(datetime, activation_token.expires_at).replace(
        tzinfo=timezone.utc
    )

    if (
        not activation_token
        or data.token != activation_token.token
        or datetime.now(timezone.utc) >= expires_at
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.commit()

    await db.delete(activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=accounts.MessageResponseSchema
)
async def reset_password_request(
    data: accounts.PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await get_user_by_email(db, data.email)

    if user:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        await db.commit()

        password_reset_token = PasswordResetTokenModel(user_id=user.id)

        db.add(password_reset_token)
        await db.commit()

    return {
        "message": (
            "If you are registered, you will receive "
            "an email with instructions."
        )
    }


@router.post(
    "/reset-password/complete/",
    response_model=accounts.MessageResponseSchema
)
async def reset_password_completion(
    data: accounts.PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> dict:
    user = await get_user_by_email(db, data.email)

    result = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
    )
    password_reset_token = result.scalar_one_or_none()
    expires_at = cast(datetime, password_reset_token.expires_at)

    if (
        not password_reset_token
        or password_reset_token.token != data.token
        or datetime.now(timezone.utc) >= expires_at
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        new_password_reset_token = PasswordResetTokenModel(user_id=user.id)

        db.add(new_password_reset_token)
        await db.commit()

        await db.delete(password_reset_token)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {
        "message": "Password reset successfully."
    }


@router.post(
    "/login/",
    response_model=accounts.UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def login(
    data: accounts.UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> dict:
    user = await get_user_by_email(db, data.email)

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_auth_manager.create_access_token(
            {"sub": user.email, "user_id": user.id}
        )
        refresh_token = jwt_auth_manager.create_refresh_token(
            {"sub": user.email, "user_id": user.id}
        )
        refresh_token_instance = RefreshTokenModel(
            token=refresh_token,
            user_id=user.id
        )

        db.add(refresh_token_instance)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    response_model=accounts.TokenRefreshResponseSchema
)
async def refresh_access_token(
    data: accounts.TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> dict:
    try:
        jwt_auth_manager.verify_refresh_token_or_raise(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    result = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == data.refresh_token)
    )
    refresh_token_instance = result.scalar_one_or_none()

    if not refresh_token_instance:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    expires_at = cast(datetime, refresh_token_instance.expires_at).replace(
        tzinfo=timezone.utc
    )
    if datetime.now(timezone.utc) >= expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    to_decode = jwt_auth_manager.decode_refresh_token(refresh_token_instance.token)
    user_result = await db.execute(
        select(UserModel)
        .where(UserModel.id == to_decode["user_id"])
    )
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_auth_manager.create_access_token(
        {"sub": user.email, "user_id": user.id}
    )
    return {"access_token": access_token}
