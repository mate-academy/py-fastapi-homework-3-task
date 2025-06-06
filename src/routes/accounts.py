from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from exceptions import TokenExpiredError

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
from exceptions.security import InvalidTokenError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    try:
        query = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(query)
        db_user = result.scalar_one_or_none()

        if db_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"A user with this email {user_data.email} already exists."
                )
            )

        db_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=1
        )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_user)

        return db_user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
    user_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    query = (
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User doesn't exist"
        )

    query = (
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == db_user.id)
    )
    token_result = await db.execute(query)
    user_activation_token = token_result.scalar_one_or_none()

    if user_activation_token:
        expires_at = cast(
            datetime, user_activation_token.expires_at
        ).replace(tzinfo=timezone.utc)

    if (
        not user_activation_token
        or expires_at < datetime.now(timezone.utc)
        or user_activation_token.token != user_data.token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    db_user.is_active = True
    await db.execute(
        delete(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == db_user.id)
    )
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(
    user_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    query = (
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if db_user and db_user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == db_user.id)
        )
        password_reset_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(password_reset_token)
        await db.commit()

    return MessageResponseSchema(
        message=(
            "If you are registered, you will receive "
            "an email with instructions."
        )
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema
)
async def password_reset_complete(
    user_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    query = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == user_data.email)
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_obj = db_user.password_reset_token

    token_invalid = (
        not token_obj
        or token_obj.token != user_data.token
        or token_obj.expires_at.replace(tzinfo=timezone.utc)
        < datetime.now(timezone.utc)
    )

    delete_query = (
        delete(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == db_user.id)
    )

    if token_invalid:
        if token_obj:
            await db.execute(delete_query)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

    try:
        db_user.password = user_data.password
        db.add(db_user)
        await db.execute(delete_query)
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201
)
async def login(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> UserLoginResponseSchema:
    try:
        query = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(query)
        db_user = result.scalar_one_or_none()

        if not db_user or not db_user.verify_password(user_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not db_user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        refresh_token = jwt_manager.create_refresh_token(
            data={"sub": db_user.email, "user_id": db_user.id}
        )

        refresh_token_obj = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=3,
            token=refresh_token
        )
        db.add(refresh_token_obj)
        await db.commit()

        access_token = jwt_manager.create_access_token(
            data={"sub": db_user.email, "user_id": db_user.id}
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh(
    user_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    try:
        refresh_token_data = jwt_manager.decode_refresh_token(
            user_data.refresh_token
        )
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    query = (
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == user_data.refresh_token)
    )
    result = await db.execute(query)
    refresh_token = result.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    query = (
        select(UserModel)
        .where(UserModel.id == refresh_token_data["user_id"])
    )
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(
        data={"sub": db_user.email, "user_id": db_user.id}
    )

    return TokenRefreshResponseSchema(
        access_token=access_token
    )
