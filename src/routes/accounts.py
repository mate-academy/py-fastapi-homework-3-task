from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings, settings
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
    UserReadSchema,
    UserRegistrationRequestSchema,
    AccountActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    Token,
    UserLoginSchema,
    AccessTokenResponseSchema,
    RefreshTokenRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post("/register/", response_model=UserReadSchema, status_code=201)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    existing_user = await db.scalar(select(UserModel).where(UserModel.email == user.email))
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )

    try:
        db_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=UserGroupEnum.USER
        )

        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(db_user)

        return db_user
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def activate_account(data: AccountActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    token_record = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )

    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def reset_password_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if user and user.is_active:
        token_record = await db.scalar(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        if token_record:
            await db.delete(token_record)

        reset_token = PasswordResetTokenModel(user_id=user.id)

        db.add(reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/")
async def reset_password_complete(data: PasswordResetCompleteSchema, db: AsyncSession = Depends(get_db)):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    token_record = await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    if not token_record or token_record.token != data.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=Token, status_code=201)
async def login(
    data: UserLoginSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token(data={"sub": str(user.id), "user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token(data={"sub": str(user.id), "user_id": user.id})

        db_refresh = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=7,
            token=refresh_token
        )
        db.add(db_refresh)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=AccessTokenResponseSchema)
async def refresh_access_token(
    data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(token=data.refresh_token)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    if not payload:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )

    user_id = int(payload.get("sub") or payload.get("user_id"))

    token_record = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    if not token_record:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    if token_record.user_id != user_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid token."
        )

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(data={"sub": str(user.id), "user_id": user.id})

    return {"access_token": new_access_token}
