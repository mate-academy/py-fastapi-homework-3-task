from datetime import datetime, timezone
from typing import cast

from cryptography.hazmat.primitives.ciphers import aead
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.engine import default
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
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post("/register/", status_code=201, response_model=UserRegistrationResponseSchema)
async def create_user(user_data: UserRegistrationRequestSchema, session: AsyncSession = Depends(get_db)):
    user = await session.scalar(select(UserModel).where(UserModel.email == user_data.email))
    if user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

    hashed = hash_password(user_data.password)
    try:
        user = UserModel(email=user_data.email, _hashed_password=hashed)
        group = await session.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        if group is None:
            raise HTTPException(status_code=500, detail="Default user group not found.")
        user.group = group

        user.activation_token = ActivationTokenModel()
        session.add(user)
        await session.commit()
        await session.refresh(user)
    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    return user


@router.post("/activate/", status_code=200)
async def activate_user(user_data: UserActivationRequestSchema, session: AsyncSession = Depends(get_db)):
    user = await session.scalar(select(UserModel).where(UserModel.email == user_data.email))
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token = await session.scalar(select(ActivationTokenModel).where(ActivationTokenModel.token == user_data.token))
    if token is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.id != token.user_id or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await session.delete(token)
    await session.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=200, response_model=MessageResponseSchema)
async def reset_password_request(email: PasswordResetRequestSchema, session: AsyncSession = Depends(get_db)):
    user = await session.scalar(select(UserModel).where(UserModel.email == email.email))

    if user and user.is_active:
        token = await session.scalar(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        if token:
            await session.delete(token)

        password_reset_token = PasswordResetTokenModel(user_id=user.id)
        session.add(password_reset_token)

        await session.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=200)
async def reset_password_complete(
    user_data: PasswordResetCompleteRequestSchema,
    session: AsyncSession = Depends(get_db)
):
    user = await session.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    token = await session.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    if (
        token is None
        or token.token != user_data.token
        or token.user_id != user.id
        or not user.is_active
        or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
    ):
        if token is not None:
            await session.delete(token)
            await session.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    try:
        user.password = user_data.password
        await session.delete(token)
        await session.commit()

    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=201, response_model=UserLoginResponseSchema)
async def login_user(
        user_data: UserLoginRequestSchema,
        session: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = await session.scalar(
        select(UserModel)
        .where(
            UserModel.email == user_data.email
        )
    )
    if user is None or not user.verify_password(user_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
    access_token = jwt_manager.create_access_token({"user_id": user.id})

    try:
        token = RefreshTokenModel.create(token=refresh_token, user_id=user.id, days_valid=7)

        session.add(token)
        await session.commit()

    except SQLAlchemyError:
        await session.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post(
    "/refresh/",
    status_code=200,
    response_model=TokenRefreshResponseSchema
)
async def refresh_token(
    user_data: TokenRefreshRequestSchema,
    session: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    refresh_token = user_data.refresh_token

    try:
        payload = jwt_manager.decode_refresh_token(refresh_token)

    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    except InvalidTokenError:
        raise HTTPException(
            status_code=400,
            detail="Invalid refresh token."
        )

    token_record = await session.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_token
        )
    )

    if token_record is None:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    user = await session.scalar(
        select(UserModel).where(
            UserModel.id == payload.get("user_id")
        )
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    if token_record.user_id != user.id:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token."
        )

    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )

    return {"access_token": access_token}
