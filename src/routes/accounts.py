from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

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
from exceptions.accounts import (
    EmailAlreadyExistsError,
    UserGroupNotFoundError,
    InvalidActivationTokenError,
    AccountAlreadyActivatedError,
    UserNotFoundError,
    InvalidResetTokenError,
    InvalidCredentialsError,
    AccountNotActivatedError,
    RefreshTokenNotFoundError,
    TokenExpiredError,
    InvalidTokenError,
)

router = APIRouter(prefix="/api/v1/accounts", tags=["accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Create a new user account and return user id and email",
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    """Register a new user account."""

    email_check_query = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(email_check_query)
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise EmailAlreadyExistsError()

    user_group_query = select(UserGroupModel).where(
        UserGroupModel.name == UserGroupEnum.USER
    )
    result = await db.execute(user_group_query)
    user_group = result.scalar_one_or_none()

    if not user_group:
        raise UserGroupNotFoundError()

    new_user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_group.id,
    )

    activation_token = ActivationTokenModel(user_id=new_user.id)

    db.add(new_user)
    db.add(activation_token)

    try:
        await db.commit()
        await db.refresh(new_user)
        await db.refresh(activation_token)
    except IntegrityError:
        await db.rollback()
        raise EmailAlreadyExistsError()

    return UserRegistrationResponseSchema(
        id=new_user.id,
        email=new_user.email
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Activate user account",
    description="Activate a user account using email and activation token",
)
async def activate_account(
        token_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    """Activate a user account using email and activation token."""

    user_query = select(UserModel).where(UserModel.email == token_data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise InvalidActivationTokenError()

    token_query = (
        select(ActivationTokenModel)
        .where(
            ActivationTokenModel.token == token_data.activation_token,
            ActivationTokenModel.user_id == user.id
        )
    )
    token_result = await db.execute(token_query)
    activation_token = token_result.scalar_one_or_none()

    if not activation_token:
        raise InvalidActivationTokenError()

    current_time = datetime.now(timezone.utc)
    expires_at_aware = activation_token.expires_at.replace(tzinfo=timezone.utc)

    if expires_at_aware < current_time:
        await db.delete(activation_token)
        await db.commit()
        raise InvalidActivationTokenError()

    if user.is_active:
        await db.delete(activation_token)
        await db.commit()
        raise AccountAlreadyActivatedError()

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Request password reset token",
    description="Generate a password reset token for a user by email",
)
async def request_password_reset(
        reset_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    """Request a password reset token."""

    user_query = select(UserModel).where(UserModel.email == reset_data.email)
    result = await db.execute(user_query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return MessageResponseSchema(
            message="Password reset token has been sent to your email."
        )

    existing_token_query = (
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
    )
    result = await db.execute(existing_token_query)
    existing_token = result.scalar_one_or_none()

    if existing_token:
        await db.delete(existing_token)
        await db.flush()

    reset_token = PasswordResetTokenModel(user_id=user.id)
    db.add(reset_token)

    try:
        await db.commit()
        await db.refresh(reset_token)
    except Exception:
        await db.rollback()

    return MessageResponseSchema(
        message="Password reset token has been sent to your email."
    )


@router.post(
    "/password-reset/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Complete password reset",
    description="Reset user password using email, reset token and new password",
)
async def complete_password_reset(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    """Complete the password reset process."""

    user_query = select(UserModel).where(UserModel.email == reset_data.email)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise InvalidResetTokenError()

    if not user.is_active:
        raise InvalidResetTokenError()

    token_query = (
        select(PasswordResetTokenModel)
        .where(
            PasswordResetTokenModel.token == reset_data.reset_token,
            PasswordResetTokenModel.user_id == user.id
        )
    )
    token_result = await db.execute(token_query)
    reset_token = token_result.scalar_one_or_none()

    if not reset_token:
        raise InvalidResetTokenError()

    current_time = datetime.now(timezone.utc)
    expires_at_aware = reset_token.expires_at.replace(tzinfo=timezone.utc)

    if expires_at_aware < current_time:
        await db.delete(reset_token)
        await db.commit()
        raise InvalidResetTokenError()

    try:
        user.password = reset_data.new_password
    except ValueError as e:
        raise InvalidResetTokenError(detail=str(e))

    await db.delete(reset_token)

    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="User login",
    description="Authenticate user and return JWT access and refresh tokens",
)
async def login_user(
        login_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    """Authenticate user and return JWT tokens."""

    user_query = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(user_query)
    user = result.scalar_one_or_none()

    if not user:
        raise InvalidCredentialsError()

    if not user.verify_password(login_data.password):
        raise InvalidCredentialsError()

    if not user.is_active:
        raise AccountNotActivatedError()

    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id}
    )

    refresh_token_jwt = jwt_manager.create_refresh_token(
        data={"user_id": user.id}
    )

    refresh_token_model = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token_jwt,
    )

    db.add(refresh_token_model)

    try:
        await db.commit()
        await db.refresh(refresh_token_model)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token_jwt,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Get a new access token using a valid refresh token",
)
async def refresh_access_token(
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    """Refresh the access token using a valid refresh token."""

    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as e:
        if "expired" in str(e).lower():
            raise TokenExpiredError()
        else:
            raise InvalidTokenError()

    token_query = (
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == token_data.refresh_token)
    )
    result = await db.execute(token_query)
    refresh_token_model = result.scalar_one_or_none()

    if not refresh_token_model:
        raise RefreshTokenNotFoundError()

    user_id = payload.get("user_id")

    if not user_id:
        raise InvalidTokenError()

    user_query = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(user_query)
    user = result.scalar_one_or_none()

    if not user:
        await db.delete(refresh_token_model)
        await db.commit()
        raise UserNotFoundError()

    new_access_token = jwt_manager.create_access_token(
        data={"user_id": user.id}
    )

    return TokenRefreshResponseSchema(
        access_token=new_access_token
    )
