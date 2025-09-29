import secrets
from datetime import datetime, timezone, timedelta
from typing import cast


from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, selectinload

from src.config import get_jwt_auth_manager, get_settings, BaseAppSettings
from src.database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from src.schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    ActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from src.exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from src.security.interfaces import JWTAuthManagerInterface
from src.security.passwords import hash_password
from src.database.models.accounts import verify_password
from pydantic import ValidationError

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == user.email.lower())
        )
        existing_user = result.scalars().first()

        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user.email} already exists.",
            )

        result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        user_group = result.scalars().first()
        if not user_group:
            user_group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(user_group)
            await db.flush()

        new_user = UserModel.create(
            email=user.email, raw_password=user.password, group_id=user_group.id
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user=new_user)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/")
async def activate_account(
    data: ActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.activation_token))
        .where(UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This user does not exist.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_obj = user.activation_token if user.activation_token else None

    if (
        not token_obj
        or token_obj.token != data.token
        or token_obj.expires_at < datetime.now(timezone.utc).replace(tzinfo=None)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token_obj)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
    data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):

    result = await db.execute(
        select(UserModel).where(UserModel.email == data.email.lower())
    )
    user = result.scalars().first()

    success_response = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    if not user or not user.is_active:
        return success_response

    await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
        .execution_options(synchronize_session="fetch")
    )
    await db.execute(
        PasswordResetTokenModel.__table__.delete().where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

    new_token = PasswordResetTokenModel(
        user_id=user.id, token=token, expires_at=expires_at
    )
    db.add(new_token)
    await db.commit()

    return success_response


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == data.token,
        )
    )
    reset_token = result.scalar_one_or_none()

    if not reset_token or reset_token.expires_at < datetime.now(timezone.utc).replace(
        tzinfo=None
    ):

        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        user._hashed_password = hash_password(data.password)
        await db.delete(reset_token)
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
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):

    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalars().first()

    if not user or not verify_password(data.password, user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    token_data = {"user_id": user.id, "email": user.email}
    access_token_value = jwt_manager.create_access_token(data=token_data)
    refresh_token_value = jwt_manager.create_refresh_token(data=token_data)

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_value,
        )
        db.add(refresh_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token_value, refresh_token=refresh_token_value
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    try:
        jwt_manager.verify_refresh_token_or_raise(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token."
        )

    token_data = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    refresh_token = token_data.scalars().first()
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user_data = await db.execute(
        select(UserModel).where(UserModel.id == RefreshTokenModel.user_id)
    )
    user = user_data.scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    token_data = {"user_id": user.id, "email": user.email}
    access_token_value = jwt_manager.create_access_token(data=token_data)

    return TokenRefreshResponseSchema(access_token=access_token_value)
