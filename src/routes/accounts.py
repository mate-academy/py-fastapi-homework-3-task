from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

import schemas
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
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post("/register/",
             response_model=schemas.accounts.UserRegistrationResponseSchema,
             status_code=status.HTTP_201_CREATED)
async def register_user(user_data: schemas.accounts.UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    email = user_data.email.lower()
    try:
        query = await db.execute(select(UserModel).where(UserModel.email == email))

        user = query.scalar_one_or_none()

        if user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {email} already exists."
            )
        user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        hashed_password = hash_password(user_data.password)
        obj_user = UserModel(
            email=email,
            _hashed_password=hashed_password,
            group_id=user_group.id,
        )
        db.add(obj_user)
        await db.flush()
        db.add(ActivationTokenModel(user_id=obj_user.id))
        await db.commit()
        await db.refresh(obj_user)

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    return obj_user


@router.post("/activate/",
             response_model=schemas.accounts.MessageResponseSchema,
             status_code=status.HTTP_200_OK)
async def activate_user(data_activate: schemas.accounts.UserActivationRequestSchema,
                        db: AsyncSession = Depends(get_db)):
    token = data_activate.token

    user = await db.scalar(select(UserModel).where(UserModel.email == data_activate.email.lower()))
    if user is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if user.is_active is True:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    token_obj = await db.scalar(select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
    if token_obj is None:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if token_obj.token != token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    expires_at = token_obj.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if token_obj.token != token or expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token_obj)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def pass_reset(data: schemas.accounts.PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    obj_user = await db.scalar(select(UserModel).where(UserModel.email == data.email))

    if obj_user and obj_user.is_active is True:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == obj_user.id))
        db.add(PasswordResetTokenModel(user_id=obj_user.id))
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def confirm_reset(
        data: schemas.accounts.PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        obj_user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
        if obj_user is None:
            alive_token = await db.scalar(
                select(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.token == data.token))
            if alive_token:
                await db.delete(alive_token)
                await db.commit()

            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        obj_token = (await db.scalar(select(
            PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == obj_user.id)))

        if obj_token is None:
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        expires_at = obj_token.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if obj_token.token != data.token or expires_at < datetime.now(timezone.utc):
            await db.delete(obj_token)
            await db.commit()

            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        obj_user._hashed_password = hash_password(data.password)
        alive_token = await db.scalar(select(
            PasswordResetTokenModel).where(
            PasswordResetTokenModel.token == data.token))
        await db.delete(alive_token)
        await db.commit()
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=schemas.accounts.UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(data: schemas.accounts.UserLoginRequestSchema,
                     jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                     db: AsyncSession = Depends(get_db),
                     settings: BaseAppSettings = Depends(get_settings),
                     ):
    user_obj = await db.scalar(select(UserModel).where(UserModel.email == data.email))

    if user_obj is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user_obj.verify_password(data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not user_obj.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    refresh_token = jwt_manager.create_refresh_token(data={"user_id": user_obj.id})
    access_token = jwt_manager.create_access_token(data={"user_id": user_obj.id})
    try:
        refresh_obj = RefreshTokenModel.create(
            user_id=user_obj.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_obj)
        await db.commit()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=schemas.accounts.TokenRefreshResponseSchema)
async def refresh_token(data: schemas.accounts.TokenRefreshRequestSchema,
                        db: AsyncSession = Depends(get_db),
                        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
                        ):
    try:
        ref_token = jwt_manager.decode_refresh_token(token=data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token.")

    obj_token = await db.scalar(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))

    if obj_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_id = ref_token["user_id"]

    obj_user = await db.scalar(select(UserModel).where(UserModel.id == user_id))

    if obj_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(data={"user_id": user_id})

    return {
        "access_token": new_access_token
    }
