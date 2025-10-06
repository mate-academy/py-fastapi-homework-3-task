from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
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
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

# Write your code here


def _is_token_expired(expires_at: datetime) -> bool:
    expiration = expires_at
    if expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)
    return expiration <= datetime.now(timezone.utc)


async def _commit_or_raise(session: AsyncSession, detail: str) -> None:
    try:
        await session.commit()
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
    registration_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    existing_stmt = select(UserModel).where(UserModel.email == registration_data.email)
    existing_result = await db.execute(existing_stmt)
    if existing_result.scalars().first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {registration_data.email} already exists."
        )

    group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    group_result = await db.execute(group_stmt)
    user_group = group_result.scalars().first()
    if user_group is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group is not configured."
        )

    user = UserModel.create(
        email=registration_data.email,
        raw_password=registration_data.password,
        group_id=user_group.id
    )
    db.add(user)
    await db.flush()

    activation_token = ActivationTokenModel(user_id=user.id)
    db.add(activation_token)

    await _commit_or_raise(db, detail="An error occurred during user creation.")
    await db.refresh(user)

    return UserRegistrationResponseSchema.model_validate(user)


@router.post(
    "/activate/",
    response_model=MessageResponseSchema
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    token = user.activation_token
    if token is None or token.token != activation_data.token or _is_token_expired(token.expires_at):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)

    await _commit_or_raise(db, detail="An error occurred during account activation.")

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema
)
async def request_password_reset(
    reset_request: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == reset_request.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    message = "If you are registered, you will receive an email with instructions."

    if user is None or not user.is_active:
        return MessageResponseSchema(message=message)

    if user.password_reset_token is not None:
        await db.delete(user.password_reset_token)
        await db.flush()

    reset_token = PasswordResetTokenModel(user_id=user.id)
    db.add(reset_token)

    await _commit_or_raise(db, detail="An error occurred while requesting a password reset token.")

    return MessageResponseSchema(message=message)


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema
)
async def reset_password(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == reset_data.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or user.password_reset_token is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    token = user.password_reset_token
    if token.token != reset_data.token or _is_token_expired(token.expires_at):
        await db.delete(token)
        await _commit_or_raise(db, detail="An error occurred while resetting the password.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    user.password = reset_data.password
    await db.delete(token)

    await _commit_or_raise(db, detail="An error occurred while resetting the password.")

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    stmt = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user is None or not user.verify_password(login_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
    )

    await db.execute(delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id))

    refresh_token_record = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token
    )
    db.add(refresh_token_record)

    await _commit_or_raise(db, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema
)
async def refresh_access_token(
    refresh_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    try:
        token_payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
    except TokenExpiredError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    except InvalidTokenError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    except BaseSecurityError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_data.refresh_token)
    result = await db.execute(stmt)
    refresh_token_record = result.scalars().first()

    if refresh_token_record is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    if _is_token_expired(refresh_token_record.expires_at):
        await db.delete(refresh_token_record)
        await _commit_or_raise(db, detail="An error occurred while processing the request.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    user_id = token_payload.get("user_id")
    if user_id is None or refresh_token_record.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_stmt)
    user = user_result.scalars().first()

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
