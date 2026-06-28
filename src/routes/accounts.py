import secrets
from datetime import datetime, timezone, timedelta
from typing import Annotated, cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

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
from security.passwords import hash_password

from schemas.accounts import (
    UserRegistrationRequestSchema, UserRegistrationResponseSchema,
    UserActivationRequestSchema, MessageResponseSchema,
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema, UserLoginResponseSchema,
    TokenRefreshRequestSchema, TokenRefreshResponseSchema
)

router = APIRouter()

SessionDep = Annotated[AsyncSession, Depends(get_db)]


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
        payload: UserRegistrationRequestSchema,
        db: SessionDep,
):
    stmt = select(UserModel).filter(UserModel.email == payload.email)
    res = await db.execute(stmt)
    if res.scalar():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {payload.email} already exists."
        )

    try:
        group_stmt = select(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER)
        group_res = await db.execute(group_stmt)
        group_obj = group_res.scalar()

        if not group_obj:
            group_obj = UserGroupModel(name=UserGroupEnum.USER)
            db.add(group_obj)
            await db.flush()

        active_group = cast(UserGroupModel, group_obj)

        new_user = UserModel.create(
            email=payload.email,
            raw_password=payload.password,
            group_id=active_group.id
        )
        db.add(new_user)
        await db.flush()

        token_value = secrets.token_urlsafe(32)
        expires = datetime.now(timezone.utc) + timedelta(days=1)

        activation_token = ActivationTokenModel(
            token=token_value,
            expires_at=expires.replace(tzinfo=None),
            user_id=cast(int, new_user.id)
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_user(payload: UserActivationRequestSchema, db: SessionDep):
    user_stmt = select(UserModel).filter(UserModel.email == payload.email)
    user_res = await db.execute(user_stmt)
    user_obj = user_res.scalar()

    if not user_obj:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    active_user = cast(UserModel, user_obj)

    if active_user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    token_stmt = select(ActivationTokenModel).filter(
        ActivationTokenModel.token == payload.token,
        ActivationTokenModel.user_id == active_user.id
    )
    token_res = await db.execute(token_stmt)
    token_obj = token_res.scalar()

    if not token_obj:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    valid_token = cast(ActivationTokenModel, token_obj)

    expires_at = cast(datetime, valid_token.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        await db.delete(valid_token)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    active_user.is_active = True
    await db.delete(valid_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(payload: PasswordResetRequestSchema, db: SessionDep):
    success_msg = {"message": "If you are registered, you will receive an email with instructions."}

    user_stmt = select(UserModel).filter(UserModel.email == payload.email)
    user_res = await db.execute(user_stmt)
    user_obj = user_res.scalar()

    if not user_obj:
        return success_msg

    active_user = cast(UserModel, user_obj)

    if not active_user.is_active:
        return success_msg

    await db.execute(delete(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == active_user.id))

    token_value = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)

    reset_token = PasswordResetTokenModel(
        token=token_value,
        expires_at=expires.replace(tzinfo=None),
        user_id=cast(int, active_user.id)
    )
    db.add(reset_token)
    await db.commit()

    return success_msg


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def complete_password_reset(
        payload: PasswordResetCompleteRequestSchema,
        db: SessionDep
):
    user_stmt = select(UserModel).filter(UserModel.email == payload.email)
    user_res = await db.execute(user_stmt)
    user_obj = user_res.scalar()

    invalid_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token."
    )

    if not user_obj:
        raise invalid_error

    active_user = cast(UserModel, user_obj)

    if not active_user.is_active:
        raise invalid_error

    token_stmt = select(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == active_user.id)
    token_res = await db.execute(token_stmt)
    token_obj = token_res.scalar()

    if not token_obj:
        raise invalid_error

    valid_token = cast(PasswordResetTokenModel, token_obj)

    async def invalidate_token_and_raise():
        await db.delete(valid_token)
        await db.commit()
        raise invalid_error

    if valid_token.token != payload.token:
        await invalidate_token_and_raise()

    expires_at = cast(datetime, valid_token.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        await invalidate_token_and_raise()

    try:
        active_user._hashed_password = hash_password(payload.password)
        await db.delete(valid_token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    payload: UserLoginRequestSchema,
    db: SessionDep,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    user_stmt = select(UserModel).filter(UserModel.email == payload.email)
    user_res = await db.execute(user_stmt)
    user_obj = user_res.scalar()

    if not user_obj:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    active_user = cast(UserModel, user_obj)

    if not active_user.verify_password(payload.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not active_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token(data={"user_id": active_user.id})
        refresh_token_jwt = jwt_manager.create_refresh_token(data={"user_id": active_user.id})

        refresh_store = RefreshTokenModel.create(
            user_id=active_user.id,
            days_valid=int(settings.LOGIN_TIME_DAYS),
            token=refresh_token_jwt
        )
        db.add(refresh_store)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_jwt,
            "token_type": "bearer"
        }
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    db: SessionDep,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_data = jwt_manager.decode_refresh_token(payload.refresh_token)
        user_id = decoded_data.get("user_id")
    except BaseSecurityError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")

    token_stmt = select(RefreshTokenModel).filter(RefreshTokenModel.token == payload.refresh_token)
    token_res = await db.execute(token_stmt)
    db_token_obj = token_res.scalar()

    if not db_token_obj:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    active_token = cast(RefreshTokenModel, db_token_obj)

    if active_token.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    user_stmt = select(UserModel).filter(UserModel.id == user_id)
    user_res = await db.execute(user_stmt)
    user_obj = user_res.scalar()

    if not user_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    active_user = cast(UserModel, user_obj)

    new_access_token = jwt_manager.create_access_token(data={"user_id": active_user.id})
    return {"access_token": new_access_token}
