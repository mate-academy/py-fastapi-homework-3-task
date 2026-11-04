from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
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
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


async def get_user_by_email(email: str, db: AsyncSession) -> UserModel:
    user = await db.scalar(
        select(UserModel).where(UserModel.email == email)
    )

    return user


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(user.email, db)
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")

    group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )

    if not group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )

    try:
        create_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=group.id
        )
        db.add(create_user)
        await db.flush()
        token = ActivationTokenModel(user_id=create_user.id)
        db.add(token)
        await db.commit()
        await db.refresh(create_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    return create_user


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(data.email, db)

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == db_user.id,
            ActivationTokenModel.token == data.token
        )
    )

    if not activation_token or activation_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True
    try:
        await db.delete(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user activation.")

    return {
        "message": "User account activated successfully."
    }


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(data.email, db)
    if (not db_user) or (not db_user.is_active and db_user):
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )
    if token:
        db.delete(token)
        await db.commit()
        await db.refresh(token)

    create_token = PasswordResetTokenModel(user_id=db_user.id)

    try:
        db.add(create_token)
        await db.commit()
        await db.refresh(create_token)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during reset password.")

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def password_reset_complete(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(data.email, db)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )

    if not token or token.token != data.token or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(
            timezone.utc):
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_user._hashed_password = hash_password(data.password)
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {
        "message": "Password reset successfully."
    }


@router.post("/login/", status_code=status.HTTP_201_CREATED, response_model=UserLoginResponseSchema)
async def login(
        data: UserLoginRequestSchema,
        jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        settings: Annotated[BaseAppSettings, Depends(get_settings)],
        db: AsyncSession = Depends(get_db),
):
    db_user = await get_user_by_email(data.email, db)
    if not db_user or not verify_password(data.password, db_user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})
    access_token = jwt_manager.create_access_token({"user_id": db_user.id})

    try:
        refresh_token_create = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_create)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post("/refresh/", status_code=status.HTTP_200_OK, response_model=TokenRefreshResponseSchema)
async def refresh_token(
        data: TokenRefreshRequestSchema,
        jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        db: AsyncSession = Depends(get_db)
):
    try:
        decoded_refresh = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = decoded_refresh.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )
    db_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token,
        )
    )

    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    if db_token.user_id != user_id or db_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token."
        )

    db_user = await db.get(UserModel, db_token.user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": db_user.id})

    return TokenRefreshResponseSchema(
        access_token=new_access_token,
    )
