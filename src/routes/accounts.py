from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager

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
from exceptions import BaseSecurityError
from schemas import (
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


def is_expired(expires_at: datetime) -> bool:
    # SQLite returns naive datetimes, so the stored UTC value gets its timezone back
    return expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    return await db.scalar(select(UserModel).where(UserModel.email == email))


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    if await get_user_by_email(db, user_data.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    group_id = await db.scalar(select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER))

    try:
        user = UserModel.create(email=user_data.email, raw_password=user_data.password, group_id=group_id)
        user.activation_token = ActivationTokenModel()
        db.add(user)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    token = await db.scalar(
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .options(contains_eager(ActivationTokenModel.user))
        .where(UserModel.email == activation_data.email, ActivationTokenModel.token == activation_data.token)
    )

    if token is None or is_expired(token.expires_at):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    if token.user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    token.user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(reset_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, reset_data.email)

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        db.add(PasswordResetTokenModel(user_id=user.id))
        await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(reset_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, reset_data.email)

    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    reset_token = await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )

    if reset_token is None or reset_token.token != reset_data.token or is_expired(reset_token.expires_at):
        if reset_token is not None:
            await db.delete(reset_token)
            await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    try:
        user.password = reset_data.password
        await db.delete(reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user = await get_user_by_email(db, login_data.email)

    if user is None or not user.verify_password(login_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        db.add(RefreshTokenModel.create(user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=jwt_manager.create_access_token({"user_id": user.id}),
        refresh_token=refresh_token,
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        user_id = jwt_manager.decode_refresh_token(token_data.refresh_token).get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    stored_token_id = await db.scalar(
        select(RefreshTokenModel.id).where(
            RefreshTokenModel.token == token_data.refresh_token,
            RefreshTokenModel.user_id == user_id,
        )
    )

    if stored_token_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    if await db.get(UserModel, user_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    return TokenRefreshResponseSchema(access_token=jwt_manager.create_access_token({"user_id": user_id}))
