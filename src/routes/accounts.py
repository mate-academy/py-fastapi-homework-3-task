from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import InvalidTokenError, TokenExpiredError
from schemas.accounts import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    stmt = select(UserGroupModel).where(
        UserGroupModel.name == UserGroupEnum.USER
    )
    result = await db.execute(stmt)
    user_group = result.scalars().first()
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_group.id,
    )
    try:
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(
        id=user.id,
        email=user.email,
    )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    user_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    # Find user by email
    stmt = select(UserModel).where(
        UserModel.email == user_data.email
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    # Check whether the account is already active
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    # Find activation token
    stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == user_data.token,
    )
    result = await db.execute(stmt)
    activation_token = result.scalars().first()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    # Check token expiration
    expires_at = activation_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at <= datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    # Activate account and delete used token
    try:
        user.is_active = True
        await db.delete(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        )

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    user_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    stmt = select(UserModel).where(
        UserModel.email == user_data.email
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        try:
            stmt = select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
            result = await db.execute(stmt)
            existing_token = result.scalars().first()

            if existing_token:
                await db.delete(existing_token)

            reset_token = PasswordResetTokenModel(user_id=user.id)
            db.add(reset_token)

            await db.commit()

        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during password reset request.",
            )

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    user_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),  # noqa: B008
):
    stmt = select(UserModel).where(
        UserModel.email == user_data.email
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == user_data.token,
    )
    result = await db.execute(stmt)
    reset_token = result.scalars().first()

    if not reset_token:
        stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        result = await db.execute(stmt)
        existing_token = result.scalars().first()

        if existing_token:
            await db.delete(existing_token)
            await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = reset_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at <= datetime.now(UTC):
        try:
            await db.delete(reset_token)
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = user_data.password
        await db.delete(reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),  # noqa: B008
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),  # noqa: B008
    settings: BaseAppSettings = Depends(get_settings),  # noqa: B008
):
    stmt = select(UserModel).where(
        UserModel.email == user_data.email
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(user_data.password):
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
        {"user_id": user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )

    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
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
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),  # noqa: B008
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),  # noqa: B008
):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token.",
        )
    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == token_data.refresh_token
    )
    result = await db.execute(stmt)
    refresh_token_record = result.scalars().first()

    if not refresh_token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_id = payload.get("user_id")

    if refresh_token_record.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )

    return TokenRefreshResponseSchema(
        access_token=access_token
    )
