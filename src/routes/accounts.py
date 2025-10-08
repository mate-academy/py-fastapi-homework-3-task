from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
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
from exceptions import BaseSecurityError
from schemas.accounts import (
    DetailResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "model": DetailResponseSchema,
            "description": "Conflict",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with this email already exists."},
                }
            },
        },
        500: {
            "model": DetailResponseSchema,
            "description": "Internal Server Error",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."},
                }
            },
        },
    },
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        if existing_user:
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
                detail="An error occurred during user creation.",
            )
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(user)
        token = ActivationTokenModel(user=user)
        db.add(token)
        await db.commit()
        return user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "model": DetailResponseSchema,
            "description": "Bad request",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_token": {
                            "summary": "Invalid or expired activation token",
                            "value": {"detail": "Invalid or expired activation token."},
                        },
                        "already_active": {
                            "summary": "User account is already active.",
                            "value": {"detail": "User account is already active."},
                        },
                    }
                }
            },
        }
    },
)
async def activate_user(
    user_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))

    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_record = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )

    if not token_record or token_record.token != user_data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(
        timezone.utc
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    path="/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema,
)
async def user_login(
    request_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == request_data.email)
    )
    if not user or not user.verify_password(request_data.password):
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
        data={"user_id": user.id, "email": user.email}
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": user.id, "email": user.email},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
    )
    try:
        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
        )
        db.add(refresh_token_obj)
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=200,
)
async def password_reset(
    request_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(
        select(UserModel).where(
            UserModel.email == request_data.email, UserModel.is_active
        )
    )

    if user:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        new_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200,
    responses={
        200: {
            "model": MessageResponseSchema,
            "description": "OK",
            "content": {
                "application/json": {
                    "example": {"detail": "Password reset successfully."},
                }
            },
        },
        400: {
            "model": MessageResponseSchema,
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "example": {"detail": "A user with this email already exists."},
                }
            },
        },
        500: {
            "model": MessageResponseSchema,
            "description": "Internal Server Error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while resetting the password."
                    },
                }
            },
        },
    },
)
async def password_reset_complete(
    request_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        user = await db.scalar(
            select(UserModel).where(
                UserModel.email == request_data.email, UserModel.is_active
            )
        )

        if not user:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        password_reset_token_record = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        if (
            not password_reset_token_record
            or password_reset_token_record.token != request_data.token
            or password_reset_token_record.expires_at.replace(tzinfo=timezone.utc)
            < datetime.now(timezone.utc)
        ):
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = request_data.password
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=200,
    responses={
        200: {
            "model": TokenRefreshResponseSchema,
            "description": "OK",
            "content": {
                "application/json": {
                    "example": {"access_token": "new_access_token"},
                }
            },
        },
        400: {
            "model": MessageResponseSchema,
            "description": "Bad Request",
            "content": {
                "application/json": {
                    "example": {"detail": "Token has expired."},
                }
            },
        },
        401: {
            "model": MessageResponseSchema,
            "description": "Unauthorized",
            "content": {
                "application/json": {
                    "example": {"detail": "Refresh token not found."},
                }
            },
        },
        404: {
            "model": MessageResponseSchema,
            "description": "Not Found",
            "content": {
                "application/json": {
                    "example": {"detail": "User not found."},
                }
            },
        },
    },
)
async def refresh_access_token(
    request_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(request_data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    token_exist = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == request_data.refresh_token
        )
    )

    if not token_exist:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = decoded_token.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Token has expired.")

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(
        data={"user_id": user.id, "email": user.email}
    )

    return TokenRefreshResponseSchema(access_token=new_access_token)
