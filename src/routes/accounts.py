from datetime import datetime, timezone
from typing import cast, Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload, selectinload

from config import (
    get_jwt_auth_manager,
    get_settings,
    BaseAppSettings,
    settings,
)
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
import schemas
from security.passwords import hash_password, verify_password
from security.token_manager import JWTAuthManager
from security.utils import generate_secure_token

router = APIRouter()


@router.post(
    "/register/",
    response_model=schemas.UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def user_registration(
    user_data: schemas.UserRegistrationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    exist = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user_group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )

    try:
        if user_group is None:
            user_group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(user_group)
            await db.flush()

        user = UserModel(**user_data.model_dump(exclude={"password"}))
        user._hashed_password = hash_password(user_data.password)
        user.group_id = user_group.id
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user_id=user.id,
            token=generate_secure_token(),
        )
        db.add(activation_token)

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    await db.refresh(user)
    return user


@router.post("/activate/", response_model=schemas.MessageResponseSchema)
async def user_activate(
    user_data: schemas.UserActivationRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
        )

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id
        )
    )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    if activation_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = activation_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if activation_token.token != user_data.token or expires_at < datetime.now(
        timezone.utc
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True

    await db.delete(activation_token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/", response_model=schemas.MessageResponseSchema
)
async def user_password_request_reset(
    user_data: schemas.PasswordResetRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if user is None or not user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }
    reset_token = PasswordResetTokenModel(
        user_id=user.id, token=generate_secure_token()
    )
    db.add(reset_token)
    await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/", response_model=schemas.MessageResponseSchema
)
async def user_reset_password(
    user_data: schemas.PasswordResetCompleteRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    reset_token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    expires_at = reset_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if (
        reset_token is None
        or reset_token.token != user_data.token
        or expires_at < datetime.now(timezone.utc)
    ):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    user._hashed_password = hash_password(user_data.password)
    await db.delete(reset_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )
    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=schemas.UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def user_login(
    user_data: schemas.UserLoginRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
    jwt_auth_manager: Annotated[JWTAuthManager, Depends(get_jwt_auth_manager)],
):
    user = await db.scalar(
        select(UserModel).where(
            UserModel.email == user_data.email,
        )
    )
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    data = {"user_id": user.id}
    jwt_refresh_token = jwt_auth_manager.create_refresh_token(data=data)
    db_refresh_token = RefreshTokenModel(
        user_id=user.id, token=jwt_refresh_token
    )
    db.add(db_refresh_token)
    jwt_access_token = jwt_auth_manager.create_access_token(data=data)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
    return schemas.UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
        token_type="bearer",
    )


@router.post("/refresh/", response_model=schemas.TokenRefreshResponseSchema)
async def access_token_refresh(
    user_data: schemas.TokenRefreshRequestSchema,
    db: Annotated[AsyncSession, Depends(get_db)],
    jwt_auth_manager: Annotated[JWTAuthManager, Depends(get_jwt_auth_manager)],
):
    try:
        payload = jwt_auth_manager.decode_refresh_token(
            user_data.refresh_token
        )
        user_id = payload.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)
        )

    db_refresh_token = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.user_id == user_id)
    )
    if db_refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )
    if db_refresh_token.token != user_data.refresh_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    expires_at = db_refresh_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    data = {"user_id": user.id}
    access_token = jwt_auth_manager.create_access_token(data=data)
    return schemas.TokenRefreshResponseSchema(access_token=access_token)
