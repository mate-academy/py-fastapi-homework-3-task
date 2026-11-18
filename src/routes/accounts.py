from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

INVALID_RESET = "Invalid email or token."


def is_expired(expires_at: datetime) -> bool:
    expires = cast(datetime, expires_at).replace(tzinfo=timezone.utc)
    return expires < datetime.now(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        existing_user = await db.scalar(
            select(UserModel).where(
                UserModel.email == user_data.email.lower()
            )
        )
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"A user with this email {user_data.email} "
                    f"already exists."
                ),
            )

        group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER
            )
        )
        if group is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation.",
            )

        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, group.id),
        )
        db.add(user)
        await db.flush()
        db.add(ActivationTokenModel(user_id=cast(int, user.id)))
        await db.commit()
        await db.refresh(user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    token_record = await db.scalar(
        select(ActivationTokenModel)
        .join(UserModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(
            UserModel.email == data.email.lower(),
            ActivationTokenModel.token == data.token,
        )
    )

    if token_record is None or is_expired(token_record.expires_at):
        if token_record is not None:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = token_record.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email.lower())
    )

    if user is not None and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        db.add(PasswordResetTokenModel(user_id=cast(int, user.id)))
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email "
                   "with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def complete_password_reset(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email.lower())
    )
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_RESET
        )

    token_record = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    if (
            token_record is None
            or token_record.token != data.token
            or is_expired(token_record.expires_at)
    ):
        if token_record is not None:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=INVALID_RESET
        )

    try:
        user.password = data.password
        await db.delete(token_record)
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
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(
            get_jwt_auth_manager
        ),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email.lower())
    )
    if user is None or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    token_data = {"user_id": user.id}
    access_token = jwt_manager.create_access_token(token_data)
    refresh_token = jwt_manager.create_refresh_token(token_data)

    try:
        db.add(
            RefreshTokenModel.create(
                user_id=cast(int, user.id),
                days_valid=settings.LOGIN_TIME_DAYS,
                token=refresh_token,
            )
        )
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(
            get_jwt_auth_manager
        ),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)
        )

    user_id = payload.get("user_id")

    token_record = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token,
            RefreshTokenModel.user_id == user_id,
        )
    )
    if token_record is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user = await db.get(UserModel, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": access_token}
