from datetime import timezone, datetime, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from starlette.status import HTTP_201_CREATED

import schemas.accounts as schemas
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
from exceptions import BaseSecurityError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


class UserCreationError(HTTPException):
    def __init__(self, detail: str = "An error occurred during user creation."):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
        )


class UserEmailError(HTTPException):
    def __init__(self, email: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {email} already exists.",
        )


class InvalidEmailOrToken(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )


class ServerPasswordError(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


class UserUnauthorized(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )


class UserForbidden(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=schemas.UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
        user_data: schemas.UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        user = await get_user_by_email(db, user_data.email)

        result = await db.execute(
            select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER)
        )

        user_group_id = result.scalar_one()

        if user:
            raise UserEmailError(user_data.email)

        hashed = hash_password(user_data.password)

        db_user = UserModel(
            email=user_data.email,
            _hashed_password=hashed,
            group_id=user_group_id,
            activation_token=ActivationTokenModel()
        )

        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
        return db_user

    except SQLAlchemyError:
        await db.rollback()
        raise UserCreationError()


@router.post("/activate/", response_model=schemas.MessageResponseSchema)
async def activate_token(
        activate_data: schemas.UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ActivationTokenModel)
        .join(UserModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(
            UserModel.email == activate_data.email,
            ActivationTokenModel.token == activate_data.token,
        )
    )
    token_record = result.scalar_one_or_none()

    if token_record is None or token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        if token_record is not None:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = token_record.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=schemas.MessageResponseSchema)
async def password_reset(data: schemas.PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):

    message = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    request = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = request.scalar_one_or_none()

    if user is None or not user.is_active:
        return message

    try:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        db.add(PasswordResetTokenModel(user_id=user.id))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()

    return message


@router.post("/reset-password/complete/", response_model=schemas.MessageResponseSchema)
async def reset_password_complete(
        data: schemas.PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(PasswordResetTokenModel)
        .join(UserModel)
        .options(joinedload(PasswordResetTokenModel.user))
        .where(UserModel.email == data.email)
    )
    token_record = result.scalar_one_or_none()

    if token_record is None or token_record.user.is_active is False:
        raise InvalidEmailOrToken()

    expires_at = token_record.expires_at.replace(tzinfo=timezone.utc)

    if token_record.token != data.token or expires_at < datetime.now(timezone.utc):
        try:
            await db.delete(token_record)
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            raise ServerPasswordError()
        raise InvalidEmailOrToken()

    token_record.user._hashed_password = hash_password(data.password)
    try:
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise ServerPasswordError()

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=schemas.UserLoginResponseSchema,
    status_code=HTTP_201_CREATED,
)
async def login(
        data: schemas.UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    request = await db.execute(select(UserModel).where(UserModel.email == data.email))

    user = request.scalar_one_or_none()

    if user is None or not verify_password(data.password, user._hashed_password):
        raise UserUnauthorized()

    if user.is_active is False:
        raise UserForbidden()

    payload_data = {
        "user_id": user.id
    }

    delta = timedelta(days=settings.LOGIN_TIME_DAYS)

    access_token = jwt_manager.create_access_token(payload_data)
    refresh_token = jwt_manager.create_refresh_token(payload_data, expires_delta=delta)

    try:
        db.add(
            RefreshTokenModel.create(
                user_id=user.id,
                token=refresh_token,
                days_valid=settings.LOGIN_TIME_DAYS,
            )
        )

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/", response_model=schemas.TokenRefreshResponseSchema)
async def refresh_access_token(
        data: schemas.TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    request = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    user = await db.get(UserModel, user_id)

    token = request.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    if token.user_id != user_id or not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return {"access_token": access_token}
