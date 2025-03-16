from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from exceptions import BaseSecurityError

import routes
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema, UserActivationRequestSchema,
    MessageResponseSchema, PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema,
    TokenRefreshResponseSchema, TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
async def register(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_exist_result = await db.execute(select(UserModel).where(
        UserModel.email == user.email))
    if user_exist_result.scalars().first():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )

    try:
        new_user = UserModel.create(
            email=str(user.email),
            raw_password=user.password,
            group_id=user.group_id
        )

        db.add(new_user)
        await db.flush()

        access_token = ActivationTokenModel(user_id=new_user.id)
        db.add(access_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema.model_validate(new_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema
)
async def activate(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    find_token_result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(
            ActivationTokenModel.token == data.token,
            ActivationTokenModel.user.has(UserModel.email == data.email)
        )
    )
    this_token = find_token_result.scalars().first()

    if not this_token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    this_user = this_token.user
    expires_date = (
        cast(datetime, this_token.expires_at).replace(tzinfo=timezone.utc)
    )
    if expires_date < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    await db.delete(this_token)
    await db.commit()

    if this_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    this_user.is_active = True
    await db.commit()
    await db.refresh(this_user)

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema
)
async def reset_password_request(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    find_user_result = await db.execute(select(UserModel).where(
        UserModel.email == data.email
    ))
    this_user = find_user_result.scalars().first()

    if this_user and this_user.is_active:
        find_password_reset_token = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == this_user.id
            )
        )
        password_reset_tokens = find_password_reset_token.scalars().all()
        for item in password_reset_tokens:
            await db.delete(item)
            await db.flush()

        new_refresh_password_token = PasswordResetTokenModel(user=this_user)
        db.add(new_refresh_password_token)
        await db.commit()
        await db.refresh(this_user)

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema
)
async def reset_password(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    find_user = await db.execute(select(UserModel).where(
        UserModel.email == data.email
    ))
    this_user = find_user.scalars().first()

    if not this_user or not this_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    find_password_reset_token = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == this_user.id)
    )
    this_token = find_password_reset_token.scalars().first()

    if not this_token or this_token.token != data.token:
        if this_token:
            await db.delete(this_token)
            await db.commit()

        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    expires_date = (
        cast(datetime, this_token.expires_at).replace(tzinfo=timezone.utc)
    )

    if expires_date < datetime.now(timezone.utc):
        await db.delete(this_token)
        await db.commit()
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    try:
        this_user.password = data.password
        await db.delete(this_token)

        await db.commit()
        await db.refresh(this_user, ["_hashed_password"])

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201
)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    find_user = await db.execute(select(UserModel).where(
        UserModel.email == data.email
    ))
    this_user = find_user.scalars().first()

    if not this_user or not this_user.verify_password(data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not this_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    try:
        refresh_token = jwt_manager.create_refresh_token({"user_id": this_user.id})

        refresh_token_to_db = RefreshTokenModel.create(
            user_id=this_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_to_db)
        await db.flush()
        await db.commit()
        await db.refresh(this_user)

        access_token = jwt_manager.create_access_token({"user_id": this_user.id})
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema
)
async def refresh(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        refresh_token_data = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id_data = refresh_token_data.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    find_refresh_token = await db.execute(select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token
    ))
    if not find_refresh_token.scalars().first():
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    find_user = await db.execute(
        select(UserModel).where(UserModel.id == user_id_data)
    )
    this_user = find_user.scalars().first()

    if not this_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    return TokenRefreshResponseSchema(
        access_token=jwt_manager.create_access_token({"user_id": this_user.id})
    )
