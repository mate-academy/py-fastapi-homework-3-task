from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import get_db, ActivationTokenModel, PasswordResetTokenModel, RefreshTokenModel
from database.crud.accounts import (
    get_user_by_email,
    get_user_by_id,
    get_user_with_activation_token,
    get_user_group_by_name,
    create_user,
    get_password_reset_token,
    get_refresh_token
)
from database.models.accounts import UserGroupEnum
from exceptions import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        existing_user = await get_user_by_email(db, user_data.email)

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        user_group = await get_user_group_by_name(db, UserGroupEnum.USER)

        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation."
            )

        new_user = await create_user(
            db=db,
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, user_group.id)
        )

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema(
            id=new_user.id,
            email=new_user.email
        )

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_with_activation_token(db, activation_data.email)

    if not user or not user.activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    if user.activation_token.token != activation_data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, user.activation_token.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(user.activation_token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(
    reset_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(db, reset_data.email)

    if user and user.is_active:
        stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        await db.execute(stmt)

        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
        db.add(reset_token)
        await db.commit()

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def reset_password_complete(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    try:
        user = await get_user_by_email(db, reset_data.email)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        token_record = await get_password_reset_token(db, user.id)

        if not token_record or token_record.token != reset_data.token:
            if token_record:
                await db.delete(token_record)
                await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        expires_at = cast(datetime, token_record.expires_at)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

        user.password = reset_data.password
        await db.delete(token_record)
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    try:
        user = await get_user_by_email(db, login_data.email)

        if not user or not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        token_data = {"user_id": user.id}
        refresh_token = jwt_manager.create_refresh_token(token_data)
        access_token = jwt_manager.create_access_token(token_data)

        refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
        )

    except HTTPException:
        raise
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_token(
    refresh_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        try:
            payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token."
            )

        user_id = payload.get("user_id")

        token_record = await get_refresh_token(db, refresh_data.refresh_token)

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        user = await get_user_by_id(db, user_id)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found."
            )

        access_token = jwt_manager.create_access_token({"user_id": user.id})

        return TokenRefreshResponseSchema(access_token=access_token)

    except HTTPException:
        raise
