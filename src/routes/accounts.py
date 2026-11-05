from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

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
    MessageResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


def is_expired(expires_at: datetime) -> bool:
    """SQLite stores naive datetimes, so make them timezone-aware (UTC) before comparing."""
    expires_at = cast(datetime, expires_at).replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="User registration",
    description="Register a new user with the default USER group and create an activation token.",
    responses={
        409: {"description": "A user with this email already exists."},
        500: {"description": "An error occurred during user creation."},
    },
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not found."
        )

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id),
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate user account",
    description="Activate the account using the email and the activation token.",
    responses={400: {"description": "Invalid or expired activation token / account already active."}},
)
async def activate_account(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    token_record = user.activation_token if user else None

    if (
            token_record is None
            or token_record.token != activation_data.token
            or is_expired(token_record.expires_at)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request password reset token",
    description="Always returns the same message to avoid leaking whether the user exists.",
)
async def request_password_reset_token(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email, UserModel.is_active.is_(True))
    )

    if user:
        try:
            await db.execute(
                delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
            )
            db.add(PasswordResetTokenModel(user_id=cast(int, user.id)))
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while processing the request."
            )

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete password reset",
    description="Set a new password using a valid password reset token.",
    responses={
        400: {"description": "Invalid email or token."},
        500: {"description": "An error occurred while resetting the password."},
    },
)
async def reset_password(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == data.email)
    )
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    token_record = user.password_reset_token
    if (
            token_record is None
            or token_record.token != data.token
            or is_expired(token_record.expires_at)
    ):
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="User login",
    description="Authenticate the user and return access and refresh tokens.",
    responses={
        401: {"description": "Invalid email or password."},
        403: {"description": "User account is not activated."},
        500: {"description": "An error occurred while processing the request."},
    },
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> UserLoginResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == login_data.email))
    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token,
        )
        db.add(refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Return a new access token for a valid refresh token.",
    responses={
        400: {"description": "Token is invalid or expired."},
        401: {"description": "Refresh token not found."},
        404: {"description": "User not found."},
    },
)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        decoded_token = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    user_id = decoded_token.get("user_id")

    refresh_token_record = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == token_data.refresh_token)
    )
    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user = await db.get(UserModel, user_id) if user_id is not None else None
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
