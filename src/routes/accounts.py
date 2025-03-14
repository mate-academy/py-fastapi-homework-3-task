from datetime import datetime, timezone, timedelta
from typing import Dict, Any

from fastapi import APIRouter, Depends, status, HTTPException
from pydantic_settings import BaseSettings
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
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager
from security.utils import generate_secure_token

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Registers a new user with the provided email and password."
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        stmt = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(stmt)
        if result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        stmt_group = select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
        result_group = await db.execute(stmt_group)
        user_group = result_group.scalars().first()
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found."
            )

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user_id=new_user.id,
            token=generate_secure_token(),
        )
        db.add(activation_token)

        await db.commit()

        return UserRegistrationResponseSchema(
            id=new_user.id,
            email=new_user.email
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Activate a user account",
    description="Activates a user account using the provided email and activation token."
)
async def activate_user(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        stmt_user = select(UserModel).where(
            UserModel.email == activation_data.email
        )
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token."
            )

        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active."
            )

        stmt_token = select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == activation_data.token
        )
        result_token = await db.execute(stmt_token)
        activation_token = result_token.scalars().first()

        if not activation_token or activation_token.expires_at.replace(
                tzinfo=timezone.utc
        ) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token."
            )

        user.is_active = True

        await db.execute(
            delete(ActivationTokenModel).where(
                ActivationTokenModel.id == activation_token.id
            )
        )
        await db.commit()

        return MessageResponseSchema(
            message="User account activated successfully."
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Request a password reset token",
    description="Requests a password reset token for the provided email."
                " Always returns a success message to prevent information leaks."
)
async def password_reset_request(
        request_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        stmt_user = select(UserModel).where(
            UserModel.email == request_data.email
        )
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if user and user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            reset_token = PasswordResetTokenModel(
                user_id=user.id,
                token=generate_secure_token(),
            )
            db.add(reset_token)
            await db.commit()

        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    except SQLAlchemyError:
        await db.rollback()
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Complete password reset",
    description="Resets the user's password using a valid password reset token."
)
async def password_reset_complete(
        request_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        stmt_user = select(UserModel).where(
            UserModel.email == request_data.email
        )
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        stmt_token = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == request_data.token
        )
        result_token = await db.execute(stmt_token)
        reset_token = result_token.scalars().first()

        stmt_existing_tokens = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        result_existing_tokens = await db.execute(stmt_existing_tokens)
        existing_tokens = result_existing_tokens.scalars().all()

        current_time = datetime.now(timezone.utc)
        if not reset_token:
            if existing_tokens:
                await db.execute(
                    delete(PasswordResetTokenModel).where(
                        PasswordResetTokenModel.user_id == user.id
                    )
                )
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        expires_at = reset_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < current_time:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = request_data.password
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.id == reset_token.id
            )
        )
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Authenticate a user",
    description="Authenticates a user and returns access and refresh tokens."
)
async def login_user(
        request_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseSettings = Depends(get_settings),
):
    try:
        stmt_user = select(UserModel).where(
            UserModel.email == request_data.email
        )
        result_user = await db.execute(stmt_user)
        user = result_user.scalars().first()

        if not user or not user.verify_password(request_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        access_token = jwt_manager.create_access_token(
            data={"user_id": user.id}
        )
        refresh_token = jwt_manager.create_refresh_token(
            data={"user_id": user.id}
        )

        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS,
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Refreshes an access token using a valid refresh token."
)
async def refresh_user(
        request_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(
            request_data.refresh_token
        )
    except BaseSecurityError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    refresh_token = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == request_data.refresh_token
        )
    )
    refresh_token = refresh_token.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.execute(
        select(UserModel).where(UserModel.id == decoded_token.get("user_id"))
    )
    user = user.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(
        data={"user_id": decoded_token.get("user_id")}
    )

    return TokenRefreshResponseSchema(access_token=access_token)
