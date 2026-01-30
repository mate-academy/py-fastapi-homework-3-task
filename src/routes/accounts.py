from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from config.dependencies import get_settings, get_jwt_auth_manager
from config.settings import BaseAppSettings
from database import get_db
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        email_exists = await db.execute(select(UserModel).filter_by(email=user_data.email))
        if email_exists.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )
        group_stmt = select(UserGroupModel).filter_by(name=UserGroupEnum.USER)
        group = (await db.execute(group_stmt)).scalar_one()
        new_user = UserModel.create(email=user_data.email, raw_password=user_data.password, group_id=group.id)
        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user_stmt = select(UserModel).filter_by(email=data.email)
    user = (await db.execute(user_stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    token_stmt = select(ActivationTokenModel).filter_by(user_id=user.id, token=data.token)
    token_record = (await db.execute(token_stmt)).scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user_stmt = select(UserModel).filter_by(email=data.email, is_active=True)
    user = (await db.execute(user_stmt)).scalar_one_or_none()
    if user:
        await db.execute(delete(PasswordResetTokenModel).filter_by(user_id=user.id))
        new_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(new_token)
        await db.commit()
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user_stmt = select(UserModel).filter_by(email=data.email, is_active=True)
    user = (await db.execute(user_stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    token_stmt = select(PasswordResetTokenModel).filter_by(user_id=user.id)
    token_record = (await db.execute(token_stmt)).scalar_one_or_none()
    if not token_record or token_record.token != data.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    try:
        user_stmt = select(UserModel).filter_by(email=data.email)
        user = (await db.execute(user_stmt)).scalar_one_or_none()
        if not user or not user.verify_password(data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")
        payload = {"user_id": user.id, "sub": user.email}
        access_token = jwt_manager.create_access_token(data=payload)
        refresh_token_str = jwt_manager.create_refresh_token(data=payload)
        new_refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_str
        )
        db.add(new_refresh_token)
        await db.commit()
        return {"access_token": access_token, "refresh_token": refresh_token_str, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    token_stmt = select(RefreshTokenModel).filter_by(token=data.refresh_token)
    token_record = (await db.execute(token_stmt)).scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_stmt = select(UserModel).filter_by(id=token_record.user_id)
    user = (await db.execute(user_stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id, "sub": user.email})
    return {"access_token": new_access_token}
