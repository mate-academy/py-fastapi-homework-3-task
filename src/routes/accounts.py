from datetime import datetime, timezone
from email import message
from typing import cast

from database.models.accounts import TokenBaseModel
from fastapi import APIRouter, Depends, status, HTTPException
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
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
    RefreshTokenModel,
)
from exceptions import BaseSecurityError, InvalidTokenError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
        )

    group_obj = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group = group_obj.scalar_one_or_none()

    if group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    db_user = UserModel.create(
        email=user.email, raw_password=user.password, group_id=group.id
    )
    try:
        db.add(db_user)
        await db.flush()

        token = ActivationTokenModel(user_id=db_user.id)
        db.add(token)

        await db.commit()
        await db.refresh(db_user)

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    return db_user


@router.post(
    "/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK
)
async def activate(
    user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_obj = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == user.token,
            ActivationTokenModel.user_id == db_user.id,
        )
    )
    token = token_obj.scalar_one_or_none()

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    db_user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset_request(
    user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user is not None and db_user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
        )

        token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset_complete(
    user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)

    if db_user is None or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )

    token = token_result.scalar_one_or_none()

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc) or token.token != user.token:
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    try:
        db_user.password = user.password

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
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await get_user_by_email(db, user.email)
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not db_user.verify_password(raw_password=user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": db_user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})
    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=db_user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    request: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(request.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    stmt = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == request.refresh_token
        )
    )
    token = stmt.scalar_one_or_none()

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user_id = payload.get("user_id")
    user_obj = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = user_obj.scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=access_token)
