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
from security.interfaces import JWTAuthManagerInterface

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

router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema,
)
async def register(
    payload: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == payload.email.lower())
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {payload.email} already exists.",
        )

    stmt = select(UserGroupModel).where(
        UserGroupModel.name == UserGroupEnum.USER
    )
    result = await db.execute(stmt)
    user_group = result.scalars().first()

    if user_group is None:
        raise HTTPException(
            status_code=500,
            detail="Default user group not found."
        )

    user = UserModel.create(
        email=payload.email,
        raw_password=payload.password,
        group_id=user_group.id,
    )

    db.add(user)
    await db.flush()

    db.add(ActivationTokenModel(user_id=user.id))

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    await db.refresh(user)

    return user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
async def activate_account(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == payload.email.lower())
    )

    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token = user.activation_token

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if token.token != payload.token or expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True

    await db.delete(token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating the account.",
        )

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def request_password_reset(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == payload.email.lower())
    )

    result = await db.execute(stmt)
    user = result.scalars().first()

    message = "If you are registered, you will receive an email with instructions."

    if user is None or not user.is_active:
        return MessageResponseSchema(message=message)

    if user.password_reset_token:
        await db.delete(user.password_reset_token)
        await db.flush()

    db.add(PasswordResetTokenModel(user_id=user.id))

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while requesting password reset.",
        )

    return MessageResponseSchema(message=message)


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def complete_password_reset(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == payload.email.lower())
    )

    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    token = user.password_reset_token

    if token is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if token.token != payload.token:
        await db.delete(token)
        await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid email or token.",
        )

    user.password = payload.password

    await db.delete(token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema,
)
async def login(
    payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    stmt = select(UserModel).where(
        UserModel.email == payload.email.lower()
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or not user.verify_password(payload.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )

    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )

    db.add(
        RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
    )

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
)
async def refresh(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        data = jwt_manager.decode_refresh_token(
            payload.refresh_token
        )
    except BaseSecurityError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == payload.refresh_token
    )
    result = await db.execute(stmt)
    refresh_token = result.scalars().first()

    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    if refresh_token.user_id != data["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    if refresh_token is None:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found.",
        )

    stmt = select(UserModel).where(
        UserModel.id == data["user_id"]
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )

    return TokenRefreshResponseSchema(
        access_token=access_token
    )
