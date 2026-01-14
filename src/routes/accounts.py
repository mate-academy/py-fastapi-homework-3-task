from datetime import datetime, timezone, timedelta
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
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas import MessageResponseSchema, UserLoginResponseSchema
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
)
from crud.accounts import get_user_by_email, hash_user_password

router = APIRouter()


# Write your code here
@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def create_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        user_exist = await get_user_by_email(db, email=str(user.email))
        if user_exist is not None:
            raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")
        result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        group = result.scalar_one_or_none()
        new_user = await hash_user_password(db, user, group)
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(user_id=new_user.id, user=new_user)
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_account(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db, email=user_data.email)
    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )
    result = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == user_data.token)
    )
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if token.user_id != user.id:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    user.is_active = True
    await db.delete(token)

    await db.commit()
    return {
        "message": "User account activated successfully."
    }


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_password_request(email_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == email_data.email))
        user = result.scalar_one_or_none()
        if user is not None and user.is_active:
            await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
            await db.commit()
            reset_token = PasswordResetTokenModel(user_id=user.id, user=user)
            db.add(reset_token)
            await db.commit()
        return {"message": "If you are registered, you will receive an email with instructions."}
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_password_complete(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        user = await get_user_by_email(db, email=data.email)
        if not user or not user.is_active:
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        token = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        token = token.scalar_one_or_none()
        if token is None or token.token != data.token:
            if token:
                await db.delete(token)
                await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        if token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            await db.delete(token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        user.password = data.password
        await db.delete(token)
        await db.commit()

        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_request(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        user = await get_user_by_email(db, email=user_data.email)
        if not user or not user.verify_password(user_data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")
        data = {
            "sub": user.email,
            "user_id": user.id
        }
        access_token = jwt_manager.create_access_token(
            data,
            expires_delta=timedelta(days=1)
        )
        refresh_token = jwt_manager.create_refresh_token(
            data=data, expires_delta=timedelta(days=3)
        )
        db_token = RefreshTokenModel.create(user_id=user.id, token=refresh_token, days_valid=3)
        db.add(db_token)
        await db.commit()
        return_login_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
        return return_login_data
    except SQLAlchemyError:
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        request: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    try:
        jwt_manager.decode_refresh_token(request.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == request.refresh_token))
    refresh_token = result.scalar_one_or_none()
    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    result_user = await db.execute(select(UserModel).where(UserModel.id == refresh_token.user_id))
    user = result_user.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    data = {
        "sub": user.email,
        "user_id": user.id
    }
    new_access_token = jwt_manager.create_access_token(
        data,
        expires_delta=timedelta(days=1)
    )
    return {"access_token": new_access_token}
