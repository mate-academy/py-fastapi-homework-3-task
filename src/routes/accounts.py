from datetime import datetime, timezone
from typing import cast

from sqlalchemy.exc import SQLAlchemyError

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
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
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    existing_user = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if existing_user.scalars().first():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group = group.scalars().first()

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group.id,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=422,
            detail=str(e),
        )
    try:
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)
        await db.commit()
        await db.refresh(activation_token)
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
        user_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    existing_user = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = existing_user.scalars().first()

    if existing_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    activation_token = await db.execute(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == existing_user.id)
    )
    activation_token = activation_token.scalars().first()

    if not activation_token or activation_token.token != user_data.token:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )

    token_expires = cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc)
    if token_expires < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token.",
        )
    existing_user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset(
        user_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    existing_user = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = existing_user.scalars().first()
    if not existing_user or not existing_user.is_active:
        return {"message": "If you are registered, you will receive an email with instructions."}
    await db.execute(
        delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == existing_user.id)
    )
    new_token = PasswordResetTokenModel(user_id=cast(int, existing_user.id))
    db.add(new_token)
    await db.commit()
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
        user_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        existing_user = await db.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        existing_user = existing_user.scalars().first()
        if existing_user is None or not existing_user.is_active:
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token.",
            )
        activate_token = await db.execute(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == existing_user.id)
        )
        activate_token = activate_token.scalars().first()

        if activate_token is None or activate_token.token != user_data.token:
            if activate_token:
                await db.delete(activate_token)
                await db.commit()
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token.",
            )
        token_expires = cast(datetime, activate_token.expires_at).replace(tzinfo=timezone.utc)
        if token_expires < datetime.now(timezone.utc):
            await db.delete(activate_token)
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token.",
            )
        existing_user.password = user_data.password
        await db.delete(activate_token)
        await db.commit()

        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
):
    existing_user = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    existing_user = existing_user.scalars().first()
    if existing_user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )
    if not existing_user.verify_password(user_data.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )
    if not existing_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token(data={"user_id": existing_user.id})
    refresh_token = jwt_manager.create_refresh_token(data={"user_id": existing_user.id})

    new_refresh_token = RefreshTokenModel.create(
        user_id=cast(int, existing_user.id),
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
    )
    try:
        db.add(new_refresh_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_token(
        token_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        )
    existing_token = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == token_data.refresh_token)
    )
    existing_token = existing_token.scalars().first()
    if not existing_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    user_id = payload.get("user_id")
    existing_user = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    existing_user = existing_user.scalars().first()
    if not existing_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": existing_user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
