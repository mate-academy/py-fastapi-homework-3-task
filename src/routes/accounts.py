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
from security.interfaces import JWTAuthManagerInterface
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
    MessageResponseSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == user_data.email.lower())
    result = await db.execute(stmt)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    try:
        group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        group_result = await db.execute(group_stmt)
        group = group_result.scalars().first()

        if not group:
            group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(group)
            await db.flush()

        new_user = UserModel.create(
            email=user_data.email.lower(),
            raw_password=user_data.password,
            group_id=cast(int, group.id)
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        return new_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_account(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_stmt = select(UserModel).where(UserModel.email == data.email.lower())
    user_res = await db.execute(user_stmt)
    user = user_res.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_stmt = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == data.token
    )
    token_res = await db.execute(token_stmt)
    token_record = token_res.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    success_response = {"message": "If you are registered, you will receive an email with instructions."}

    user_stmt = select(UserModel).where(UserModel.email == data.email.lower())
    user_res = await db.execute(user_stmt)
    user = user_res.scalars().first()

    if not user or not user.is_active:
        return success_response

    del_stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    await db.execute(del_stmt)

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return success_response


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def complete_password_reset(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user_stmt = select(UserModel).where(UserModel.email == data.email.lower())
    user_res = await db.execute(user_stmt)
    user = user_res.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_stmt = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == data.token
    )
    token_res = await db.execute(token_stmt)
    token_record = token_res.scalars().first()

    if not token_record:
        del_stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        await db.execute(del_stmt)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
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
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user_stmt = select(UserModel).where(UserModel.email == data.email.lower())
    user_res = await db.execute(user_stmt)
    user = user_res.scalars().first()

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        days_valid = getattr(settings, "LOGIN_TIME_DAYS", 7)

        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token_str = jwt_manager.create_refresh_token({"user_id": user.id})

        db_refresh_token = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=days_valid,
            token=refresh_token_str
        )
        db.add(db_refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_str
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_payload = jwt_manager.decode_refresh_token(data.refresh_token)
        if not decoded_payload:
            raise ValueError()
    except (BaseSecurityError, ValueError, Exception):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    token_stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    token_res = await db.execute(token_stmt)
    db_token = token_res.scalars().first()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    user_id = decoded_payload.get("user_id") or getattr(db_token, "user_id", None)

    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user_res = await db.execute(user_stmt)
    user = user_res.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return TokenRefreshResponseSchema(access_token=new_access_token)
