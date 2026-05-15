from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
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
from exceptions import BaseSecurityError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, \
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema
from schemas.accounts import UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, \
    TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        group_query = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        group = group_query.scalar_one()

        user_query = await db.execute(select(UserModel).where(UserModel.email == user.email))
        existing_user = user_query.scalar_one_or_none()

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {existing_user.email} already exists."
            )

        new_user = UserModel.create(email=user.email, raw_password=user.password, group_id=group.id)
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return new_user

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user_account(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        query_token = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.token == user.token))
        token = query_token.scalar_one_or_none()
        if not token:
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

        query_user = await db.execute(select(UserModel).where(UserModel.email == user.email))
        user = query_user.scalar_one_or_none()

        if not user or token.user_id != user.id:
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

        expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(tz=timezone.utc):
            raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

        if user.is_active:
            raise HTTPException(status_code=400, detail="User account is already active.")

        user.is_active = True
        await db.delete(token)
        await db.commit()

        return {"message": "User account activated successfully."}

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user activation.")


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def reset_password_request(user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        query_user = await db.execute(select(UserModel).where(UserModel.email == user.email))
        user_data = query_user.scalar_one_or_none()

        if not user_data or user_data.is_active is False:
            return {"message": "If you are registered, you will receive an email with instructions."}

        query_token = await db.execute(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user_data.id)
        )
        existing_token = query_token.scalar_one_or_none()

        if existing_token:
            await db.delete(existing_token)

        new_token = PasswordResetTokenModel(user_id=user_data.id)
        db.add(new_token)
        await db.commit()

        return {"message": "If you are registered, you will receive an email with instructions."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during password reset.")


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK
)
async def reset_password_complete(user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        query_user = await db.execute(select(UserModel).where(UserModel.email == user.email))
        user_data = query_user.scalar_one_or_none()
        if not user_data or user_data.is_active is False:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        query_token = await db.execute(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user_data.id)
        )
        token = query_token.scalar_one_or_none()
        if not token:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        if token.token != user.token:
            await db.delete(token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        expires_at = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(tz=timezone.utc):
            await db.delete(token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user_data.password = user.password
        await db.flush()
        await db.delete(token)
        await db.commit()

        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    try:
        query_user = await db.execute(select(UserModel).where(UserModel.email == user.email))
        user_data = query_user.scalar_one_or_none()
        if not user_data:
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        verified_password = user_data.verify_password(user.password)

        if verified_password is False:
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        if user_data.is_active is False:
            raise HTTPException(status_code=403, detail="User account is not activated.")

        access_token = jwt_manager.create_access_token(data={"user_id": user_data.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user_data.id})

        new_refresh_token = RefreshTokenModel.create(
            user_id=user_data.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(new_refresh_token)
        await db.commit()

        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def update_token(
    user_token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        try:
            payload = jwt_manager.decode_refresh_token(user_token.refresh_token)
        except BaseSecurityError as error:
            raise HTTPException(status_code=400, detail=str(error))

        query = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == user_token.refresh_token))
        query_token = query.scalar_one_or_none()
        if not query_token:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

        user_id = payload["user_id"]

        if user_id != query_token.user_id:
            raise HTTPException(status_code=404, detail="User not found.")

        query_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
        user_data = query_user.scalar_one_or_none()
        if not user_data:
            raise HTTPException(status_code=404, detail="User not found.")

        access_token = jwt_manager.create_access_token(data={"user_id": user_data.id})

        return {"access_token": access_token}

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request")
