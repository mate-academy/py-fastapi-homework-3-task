from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
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
from exceptions.security import InvalidTokenError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
import schemas


router = APIRouter()


async def get_user_by_email(email: str, db: AsyncSession):
    user = await db.scalars(select(UserModel).where(UserModel.email == email))
    return user.first()


@router.post("/register/", response_model=schemas.UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_account(
    account: schemas.UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    existing_user = await get_user_by_email(email=account.email, db=db)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {account.email} already exists."
        )

    group = await db.scalars(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    group = group.first()

    try:
        new_user = UserModel(
            email=account.email,
            _hashed_password=hash_password(account.password),
            is_active=False,
            group=group,
        )
        activation_token = ActivationTokenModel(user=new_user)

        db.add(new_user)
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)

        return schemas.UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        ) from e


@router.post("/activate/", response_model=schemas.MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_account(
    activation_request: schemas.UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    activation_token = await db.scalars(
        select(ActivationTokenModel).where(ActivationTokenModel.token == activation_request.token)
    )
    activation_token = activation_token.first()
    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = await get_user_by_email(email=activation_request.email, db=db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )
    try:
        user.is_active = True
        db.add(user)
        await db.delete(activation_token)
        await db.commit()
        await db.refresh(user)

        return schemas.MessageResponseSchema(message="User account activated successfully.")
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation."
        ) from e


@router.post("/password-reset/request/", response_model=schemas.MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset(
    password_reset_request: schemas.PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(email=password_reset_request.email, db=db)
    if user and user.is_active:
        password_reset_token = await db.scalars(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user == user)
        )
        password_reset_token = password_reset_token.first()
        try:
            if password_reset_token:
                await db.delete(password_reset_token)
            new_password_reset_token = PasswordResetTokenModel(user=user)
            db.add(new_password_reset_token)
            await db.commit()
        except Exception:
            await db.rollback()

    return schemas.MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post(
    "/reset-password/complete/",
    response_model=schemas.MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def complete_password_reset(
    password_reset_complete_request: schemas.PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(email=password_reset_complete_request.email, db=db)
    stored_reset_password_token = await db.scalars(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user == user,
        )
    )
    stored_reset_password_token = stored_reset_password_token.first()
    if not stored_reset_password_token or not (user and user.is_active):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = cast(datetime, stored_reset_password_token.expires_at).replace(tzinfo=timezone.utc)
    if (
        stored_reset_password_token.token != password_reset_complete_request.token
        or expires_at < datetime.now(timezone.utc)
    ):
        await db.delete(stored_reset_password_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user._hashed_password = hash_password(password_reset_complete_request.password)
        await db.delete(stored_reset_password_token)
        await db.commit()

        return schemas.MessageResponseSchema(message="Password reset successfully.")
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        ) from e


@router.post("/login/", response_model=schemas.UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    login: schemas.UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await get_user_by_email(email=login.email, db=db)
    if not user or not user.verify_password(login.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if user and user.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token(
            {"user_id": user.id}
        )
        refresh_token = jwt_manager.create_refresh_token(
            {"user_id": user.id}
        )
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token)
        await db.commit()
        await db.refresh(refresh_token)

        return schemas.UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token.token,
            token_type="bearer"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        ) from e


# Mounted in main.py under /api/v1/accounts.
@router.post("/refresh/", response_model=schemas.TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh(
    refresh_request: schemas.TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(refresh_request.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=400,
            detail="Token has expired."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )
    stored_token = await db.scalars(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_request.refresh_token
        )
    )
    stored_token = stored_token.first()

    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    if payload.get("user_id") != stored_token.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )

    user = await db.scalars(select(UserModel).where(UserModel.id == stored_token.user_id))
    user = user.first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    new_access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )

    return schemas.TokenRefreshResponseSchema(access_token=new_access_token)
