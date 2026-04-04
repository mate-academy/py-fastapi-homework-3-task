from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete, ColumnElement
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
import schemas

router = APIRouter()


async def get_one_by(
        db: AsyncSession,
        model: type,
        filters: list[ColumnElement[bool]] | None = None,
        options: list | None = None
):
    query = select(model)
    if options:
        for opt in options:
            query = query.options(opt)
    if filters:
        for f in filters:
            query = query.filter(f)
    result = await db.execute(query)
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=schemas.UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(
        user_data: schemas.UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        user = await get_one_by(db, UserModel, filters=[UserModel.email == user_data.email])

        if user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )
        group = await get_one_by(db, UserGroupModel, filters=[UserGroupModel.name == UserGroupEnum.USER])

        new_user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=group.id
        )
        await db.flush()
        ActivationTokenModel(user=new_user)
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    response_model=schemas.MessageResponseSchema
)
async def user_activation(
        data: schemas.UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user = await get_one_by(db, UserModel,
                            filters=[UserModel.email == data.email],
                            options=[joinedload(UserModel.activation_token)]
                            )
    if not user or not user.activation_token or user.activation_token.token != data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    token_record = user.activation_token
    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(user.activation_token)
    await db.commit()

    return {
        "message": "User account activated successfully."
    }


@router.post(
    "/password-reset/request/",
    response_model=schemas.MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def password_reset(
        data: schemas.PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await get_one_by(db, UserModel,
                            filters=[UserModel.email == data.email],
                            options=[joinedload(UserModel.password_reset_token)])

    if user and user.is_active:
        if user.password_reset_token is not None:
            query_delete = delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.token == user.password_reset_token)
            await db.execute(query_delete)
        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        user.password_reset_token = reset_token
        await db.commit()
        await db.refresh(user)

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=schemas.MessageResponseSchema
)
async def password_reset(
        data: schemas.PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    try:
        user = await get_one_by(db, UserModel,
                                filters=[UserModel.email == data.email],
                                options=[joinedload(UserModel.password_reset_token)])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        token_record = user.password_reset_token
        is_invalid = not token_record or data.token != token_record.token
        is_expired = token_record and cast(datetime, token_record.expires_at).replace(
            tzinfo=timezone.utc) < datetime.now(timezone.utc)

        if is_invalid or is_expired:
            if token_record:
                await db.delete(token_record)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = data.password
        await db.delete(token_record)
        await db.commit()
        return {
            "message": "Password reset successfully."
        }
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=schemas.UserLoginResponseSchema
)
async def login(
        data: schemas.UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    try:
        user = await get_one_by(db, UserModel,
                                filters=[UserModel.email == data.email])
        if not user or user and not user.verify_password(data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        user_credentials = data.model_dump()
        user_credentials["user_id"] = user.id
        refresh_token_value = jwt_manager.create_refresh_token(data=user_credentials)

        user_refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_value
        )
        access_token = jwt_manager.create_access_token(data=user_credentials)

        db.add(user_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_value,
            "token_type": "bearer"
        }
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=schemas.TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh_jwt_token(
        data: schemas.TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_token_data = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = decoded_token_data.get("user_id")
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    refresh_token = await get_one_by(db, RefreshTokenModel,
                                     filters=[RefreshTokenModel.token == data.refresh_token])

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    user = await get_one_by(db, UserModel, filters=[UserModel.id == user_id])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(data=decoded_token_data)

    return {
        "access_token": new_access_token
    }
