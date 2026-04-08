from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete, ColumnElement
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
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
from security.interfaces import JWTAuthManagerInterface


from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.passwords import hash_password

router = APIRouter()


async def get_one_user(
    db: AsyncSession,
    model: type,
    filters: list[ColumnElement[bool]],
    options: list | None = None,
):
    query = select(model)
    if options:
        query = query.options(*options)
    if filters:
        query = query.where(*filters)

    result = await db.execute(query)
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    existing_user = await get_one_user(
        db, model=UserModel, filters=[UserModel.email == user_data.email]
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        group = await get_one_user(
            db, UserGroupModel, filters=[UserGroupModel.name == UserGroupEnum.USER]
        )

        if not group:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not configured.",
            )

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group.id,
        )

        activation_token = ActivationTokenModel(user=new_user)

        db.add(new_user)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await get_one_user(
        db,
        model=UserModel,
        options=[joinedload(UserModel.activation_token)],
        filters=[UserModel.email == user_data.email],
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_record = user.activation_token
    is_token_invalid = (
        not token_record
        or token_record.token != user_data.token
        or datetime.now(timezone.utc)
        > cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    )

    if is_token_invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occurred during user activation.",
        )

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(
    user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await get_one_user(
        db,
        model=UserModel,
        options=[joinedload(UserModel.password_reset_token)],
        filters=[UserModel.email == user_data.email],
    )

    if user and user.is_active:
        try:
            if user.password_reset_token:
                await db.delete(user.password_reset_token)
                await db.flush()

            db.add(PasswordResetTokenModel(user=user))
            await db.commit()
        except Exception:
            await db.rollback()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def password_reset_complete(
    user_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await get_one_user(
        db,
        model=UserModel,
        options=[joinedload(UserModel.password_reset_token)],
        filters=[UserModel.email == user_data.email],
    )

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    token_record = user.password_reset_token
    is_token_invalid = (
        not token_record
        or token_record.token != user_data.token
        or datetime.now(timezone.utc)
        > cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    )

    if is_token_invalid:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        user._hashed_password = hash_password(user_data.password)
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_request(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await get_one_user(
        db,
        model=UserModel,
        filters=[UserModel.email == user_data.email],
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

    try:
        token_data = {"sub": str(user.id)}
        user_access_token = jwt_manager.create_access_token(data=token_data)
        user_refresh_token = jwt_manager.create_refresh_token(data=token_data)

        db.add(
            RefreshTokenModel.create(
                user_id=user.id,
                days_valid=settings.LOGIN_TIME_DAYS,
                token=user_refresh_token,
            )
        )
        await db.commit()

        return {
            "access_token": user_access_token,
            "refresh_token": user_refresh_token,
            "token_type": "bearer",
        }

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_201_CREATED)
async def refresh_access_token(
    user_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token_data = jwt_manager.decode_refresh_token(user_data.refresh_token)
        user_id = decoded_token_data.get("user_id")
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    refresh_token = await get_one_user(db, RefreshTokenModel,
                                     filters=[RefreshTokenModel.token == user_data.refresh_token])

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    user = await get_one_user(db, UserModel, filters=[UserModel.id == user_id])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return {
        "access_token": new_access_token
    }

