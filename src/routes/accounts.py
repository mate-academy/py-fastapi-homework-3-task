from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from starlette.responses import JSONResponse

from config.dependencies import (get_jwt_auth_manager, get_settings)
from config.settings import BaseAppSettings
from database.models.accounts import UserModel, UserGroupModel, ActivationTokenModel, UserGroupEnum, \
    RefreshTokenModel, PasswordResetTokenModel, TokenBaseModel
from database.session_sqlite import get_sqlite_db

from exceptions.security import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
    MessageResponseSchema
)
from schemas.accounts import UserLoginRequestSchema, UserLoginResponseSchema
from security.interfaces import JWTAuthManagerInterface
router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_sqlite_db),
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )
    user_group = await db.scalar(
        select(
            UserGroupModel
        ).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )
    if not user_group:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(
            user=new_user,
        )
        db.add(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    return new_user


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_sqlite_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if not user or not user.verify_password(user_data.password):
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
        {"user_id": user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )
    try:
        token_obj = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(token_obj)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    user_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_sqlite_db),
) -> MessageResponseSchema:
    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
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

    activation_token = await db.scalar(
        select(
            ActivationTokenModel
        ).where(
            ActivationTokenModel.user_id == user.id
        )
    )
    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    time_now = datetime.now(timezone.utc)
    expires = activation_token.expires_at

    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if expires < time_now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    try:

        result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
        db_activation_token = result.scalar_one_or_none()
        if not db_activation_token:
            return MessageResponseSchema(message="An error occurred during user activation.")
        await db.delete(db_activation_token)

        result = await db.execute(select(UserModel).where(UserModel.id == user.id))
        db_user = result.scalar_one_or_none()
        if not db_user:
            return MessageResponseSchema(message="An error occurred during user activation.")

        db_user.is_active = True
        await db.flush()
        await db.commit()
        await db.refresh(db_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user activation."
        )
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK
)
async def password_reset_request(
    user_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_sqlite_db),
) -> MessageResponseSchema:
    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )

    if not user or not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    try:
        result = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        password_reset_token = result.scalar_one_or_none()
        if password_reset_token:
            await db.delete(password_reset_token)

        new_token = PasswordResetTokenModel(
            user=user,
        )
        db.add(new_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during password reset request."
        )
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK
)
async def password_reset_complete(
    user_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_sqlite_db),
) -> MessageResponseSchema:
    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == user_data.token
        )
    )
    password_reset_token = result.scalar_one_or_none()
    if not password_reset_token:
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

    time_now = datetime.now(timezone.utc)
    expires = password_reset_token.expires_at

    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    if expires < time_now:
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

    try:
        user.password = user_data.password
        await db.delete(password_reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )
    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh Access Token",
    description="Refresh the access token using a valid refresh token.",
    status_code=status.HTTP_200_OK,
    responses={
        400: {
            "description": "Bad Request - The provided refresh token is invalid or expired.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Token has expired."
                    }
                }
            },
        },
        401: {
            "description": "Unauthorized - Refresh token not found.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Refresh token not found."
                    }
                }
            },
        },
        404: {
            "description": "Not Found - The user associated with the token does not exist.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User not found."
                    }
                }
            },
        },
    },
)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_sqlite_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    """
    Endpoint to refresh an access token.

    Validates the provided refresh token, extracts the user ID from it, and issues
    a new access token. If the token is invalid or expired, an error is returned.

    Args:
        token_data (TokenRefreshRequestSchema): Contains the refresh token.
        db (AsyncSession): The asynchronous database session.
        jwt_manager (JWTAuthManagerInterface): JWT authentication manager.

    Returns:
        TokenRefreshResponseSchema: A new access token.

    Raises:
        HTTPException:
            - 400 Bad Request if the token is invalid or expired.
            - 401 Unauthorized if the refresh token is not found.
            - 404 Not Found if the user associated with the token does not exist.
    """
    try:
        decoded_token = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = decoded_token.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    stmt = select(RefreshTokenModel).filter_by(token=token_data.refresh_token)
    result = await db.execute(stmt)
    refresh_token_record = result.scalars().first()
    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    stmt = select(UserModel).filter_by(id=user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
