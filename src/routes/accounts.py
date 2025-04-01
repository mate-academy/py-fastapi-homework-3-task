from datetime import datetime, timezone
from typing import cast

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
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema
)
from schemas.accounts import (
    UserBaseSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


# Implement User Registration Endpoint
@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):

    response = await db.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    user = response.scalar_one_or_none()
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    response_user_group = await db.execute(
        select(UserGroupModel)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user_group = response_user_group.scalar_one_or_none()
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="You can not register user to the default user group"
        )

    try:

        user_create = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(user_create)
        await db.flush()

        token = ActivationTokenModel(user_id=user_create.id)
        db.add(token)
        await db.commit()
        await db.refresh(user_create)

    except SQLAlchemyError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )
    else:
        return UserRegistrationResponseSchema.model_validate(user_create)


# Implement User Account Activation Endpoint
@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK)
async def account_activation(
        user_data_activation: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(
            UserModel.email == user_data_activation.email,
            ActivationTokenModel.token == user_data_activation.token
        ))

    token = result.scalar_one_or_none()
    date_now = datetime.now(timezone.utc)

    if not token or cast(datetime, token.expires_at).replace(tzinfo=timezone.utc) < date_now:
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = token.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


# Implement Password Reset Token Request Endpoint
@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def password_reset_request(
        data: UserBaseSchema,
        db: AsyncSession = Depends(get_db),
):

    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")

    await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


# Implement Password Reset Completion Endpoint
@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK)
async def password_reset_complete(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    request = await db.execute(
        select(UserModel)
        .where(UserModel.email == data.email)
    )
    user = request.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_reset_request = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
    )
    token_reset_response = token_reset_request.scalar_one_or_none()
    if not token_reset_response or token_reset_response.token != data.token:
        if token_reset_response:
            await db.run_sync(lambda s: s.delete(token_reset_response))
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token."
            )

    expires_at = cast(
        datetime,
        token_reset_response.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.run_sync(lambda s: s.delete(token_reset_response))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = data.password
        await db.run_sync(lambda s: s.delete(token_reset_response))
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return MessageResponseSchema(message="Password reset successfully.")


# Implement User Login Endpoint
@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def login(
        data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    request = await db.execute(
        select(UserModel)
        .where(UserModel.email == data.email)
    )
    user = request.scalar_one_or_none()
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

    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        token_refresh = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(token_refresh)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def create_new_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):

    try:
        decode_token = jwt_manager.decode_refresh_token(data.refresh_token)
        user_id = decode_token.get("user_id")
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    request = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == data.refresh_token)
    )
    token_refresh = request.scalar_one_or_none()
    if not token_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_request = await db.execute(select(UserModel).filter_by(id=user_id))
    user = user_request.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema(access_token=access_token)
