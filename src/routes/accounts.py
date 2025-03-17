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
from schemas import (
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


@router.post(
    "/register/",
    status_code=201,
    response_model=UserRegistrationResponseSchema
)
async def register_user(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).filter_by(email=user.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )

    try:
        new_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=UserGroupEnum.USER.value
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        db.add(ActivationTokenModel(user_id=new_user.id))
        await db.commit()
        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)
    except ValueError as e:
        raise HTTPException(
            status_code=422,
            detail=str(e)
        )
    except SQLAlchemyError as e:
        print(e)
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    status_code=200,
    response_model=MessageResponseSchema
)
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    if user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    result = await db.execute(select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == data.token
    )
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    if token.expires_at.tzinfo is None:
        token.expires_at = token.expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > token.expires_at:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.commit()
    await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.user == user))
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    status_code=200,
    response_model=MessageResponseSchema
)
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user == user))
        await db.commit()

        db.add(PasswordResetTokenModel(user=user))
        await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post(
    "/reset-password/complete/",
    status_code=200,
    response_model=MessageResponseSchema
)
async def complete_password_reset(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(select(UserModel).where(UserModel.email == data.email))
        user = result.scalar_one_or_none()
        result = await db.execute(select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user == user,
            PasswordResetTokenModel.token == data.token
        )
        )
        token = result.scalar_one_or_none()
        if not user or not token or token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            if user:
                await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user == user))
                await db.commit()
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )
        user.password = data.password
        await db.commit()
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user == user))
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    status_code=201,
    response_model=UserLoginResponseSchema
)
async def login_user(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()
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

    access_token = jwt_auth_manager.create_access_token(data={"user_id": user.id})
    refresh_token = jwt_auth_manager.create_refresh_token(data={"user_id": user.id})

    try:
        refresh_token_entry = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(refresh_token_entry)
        await db.commit()
        await db.refresh(refresh_token_entry)
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    status_code=200,
    response_model=TokenRefreshResponseSchema
)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_auth_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_token = jwt_auth_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )
    result = await db.execute(select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token,
    )
    )
    result_token = result.scalar_one_or_none()
    if not result_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    result = await db.execute(select(UserModel).where(UserModel.id == decoded_token["user_id"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    access_token = jwt_auth_manager.create_access_token(data={"user_id": user.id})
    return TokenRefreshResponseSchema(access_token=access_token)
