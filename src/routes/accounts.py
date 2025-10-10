from datetime import timedelta, timezone, datetime
from fastapi import APIRouter, Depends, HTTPException
from jwt import InvalidTokenError
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_settings
from database import UserGroupModel, UserGroupEnum, PasswordResetTokenModel
from exceptions import TokenExpiredError
from security.interfaces import create_access_token
from src.database import get_db, UserModel, ActivationTokenModel, RefreshTokenModel

from schemas.accounts import (
    MessageResponseSchema,
    RefreshTokenResponseSchema,
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    RefreshTokenRequestSchema,
    ResetPasswordCompletionSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    ResetPasswordRequestSchema,
)
from security.passwords import verify_password, hash_password
from security.token_manager import JWTAuthManager

router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.post(
    "/register/", response_model=UserRegistrationResponseSchema, status_code=201
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        group = result.scalar_one_or_none()
        if not group:
            raise HTTPException(status_code=500, detail="User group not found.")
        db_user = UserModel(
            email=user.email,
            group_id=group.id,
        )

    except Exception:
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )

    try:
        db_user.password = user.password
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    db.add(db_user)
    await db.flush()
    activation_token = ActivationTokenModel(user_id=db_user.id)
    db.add(activation_token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )

    return UserRegistrationResponseSchema(id=db_user.id, email=db_user.email)


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
):
    jwt_manager = JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM,
    )
    email = data.email
    password = data.password
    db_user = await get_user_by_email(db, email)
    if not db_user or not verify_password(password, db_user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    try:
        data = {"email": db_user.email, "user_id": db_user.id}
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = jwt_manager.create_access_token(
            data=data, expires_delta=access_token_expires
        )
        refresh_token_expires = timedelta(minutes=REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = jwt_manager.create_refresh_token(
            data=data, expires_delta=refresh_token_expires
        )
        now = datetime.now(timezone.utc)
        refresh_record = RefreshTokenModel(
            user_id=db_user.id,
            token=refresh_token,
            expires_at=now + refresh_token_expires,
        )
        db.add(refresh_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/activate/")
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == data.token,
        )
    )
    token_record = result.scalar_one_or_none()
    if not token_record or token_record.token != data.token:
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
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while activating the user."
        )
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/")
async def reset_password(
    data: ResetPasswordRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )
    token_record = PasswordResetTokenModel(user=user)
    db.add(token_record)
    await db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/")
async def reset_password_completion(
    data: ResetPasswordCompletionSchema, db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    token_result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == data.token,
        )
    )
    token_record = token_result.scalar_one_or_none()
    if not token_record or token_record.expires_at < datetime.utcnow():
        result_tokens = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        all_tokens = result_tokens.scalars().all()
        for token in all_tokens:
            await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    user.password = data.password
    try:
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post("/refresh/")
async def refresh_access_token(
    data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
):
    jwt_manager = JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM,
    )
    try:
        encoded_token = jwt_manager.decode_refresh_token(token=data.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Token has expired.")

    token = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    user_id = encoded_token.get("user_id")
    if not user_id:
        raise HTTPException(status_code=404, detail="User not found.")
    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    new_token = jwt_manager.create_access_token(data={"user_id": user_id})
    return RefreshTokenResponseSchema(access_token=new_token)
