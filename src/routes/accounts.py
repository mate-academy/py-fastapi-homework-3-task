from datetime import datetime, timedelta, timezone

from src.exceptions import InvalidTokenError, TokenExpiredError
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.dependencies import get_jwt_auth_manager, get_settings
from src.config.settings import BaseAppSettings
from src.database import PasswordResetTokenModel, ActivationTokenModel
from src.database import (
    UserModel,
    RefreshTokenModel,
)
from src.database import get_db

from src.security.interfaces import JWTAuthManagerInterface

from src.schemas.accounts import (
    UserCreate,
    UserRead,
    UserActivate,
    UserLogin,
    RefreshTokenRequest,
    LoginResponse,
    AccessTokenResponse,
    PasswordResetRequest,
    PasswordResetComplete,
    MessageResponse,
)

from src.crud.crud import (
    create_user,
    activate_user,
    create_password_reset_token,
    reset_password,
)


router = APIRouter(tags=["Authentication"])


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {data.email} already exists.",
        )

    try:
        user = await create_user(
            db=db,
            email=data.email,
            password=data.password,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error
    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        ) from error

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id
        )
    )

    return {
        "id": user.id,
        "email": user.email,
        "activation_token": (
            activation_token.token if activation_token else None
        ),
    }


@router.post(
    "/activate/",
    response_model=MessageResponse,
)
async def activate(
    data: UserActivate,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if user is not None and user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    activated = await activate_user(
        db=db,
        email=data.email,
        token=data.token,
    )

    if not activated:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    return {"message": "User account activated successfully."}


@router.post(
    "/login/",
    response_model=LoginResponse,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    data: UserLogin,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(
        get_jwt_auth_manager
    ),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if user is None or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    refresh_expires_delta = timedelta(
        days=settings.LOGIN_TIME_DAYS
    )

    token_payload = {
        "sub": str(user.id),
        "user_id": user.id,
    }

    access_token = jwt_manager.create_access_token(
        token_payload,
    )

    refresh_token = jwt_manager.create_refresh_token(
        token_payload,
        expires_delta=refresh_expires_delta,
    )

    try:
        db.add(
            RefreshTokenModel.create(
                user_id=user.id,
                days_valid=settings.LOGIN_TIME_DAYS,
                token=refresh_token,
            )
        )
        await db.commit()
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from exc

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    response_model=AccessTokenResponse,
)
async def refresh_access_token(
    data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(
        get_jwt_auth_manager
    ),
):
    stored_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
    )

    if stored_token is not None:
        expires_at = stored_token.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(
                tzinfo=timezone.utc
            )

        if expires_at <= datetime.now(timezone.utc):
            await db.delete(stored_token)
            await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired.",
            )

    try:
        payload = jwt_manager.decode_refresh_token(
            data.refresh_token
        )
    except TokenExpiredError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        ) from error
    except InvalidTokenError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        ) from error

    subject = payload.get("user_id", payload.get("sub"))

    if subject is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload.",
        )

    try:
        user_id = int(subject)
    except (TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token payload.",
        ) from error

    if (
            stored_token is None
            or stored_token.user_id != user_id
    ):
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

    user = await db.get(UserModel, user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if (
            stored_token is None
            or stored_token.user_id != user_id
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    new_access_token = jwt_manager.create_access_token(
        {
            "sub": str(user.id),
            "user_id": user.id,
        }
    )

    return {"access_token": new_access_token}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponse,
)
async def request_password_reset(
    data: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email)
    )

    if user is not None and user.is_active:
        await create_password_reset_token(db, user)

    return {
        "message": (
            "If you are registered, you will receive an email "
            "with instructions."
        )
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponse,
)
async def complete_password_reset(
    data: PasswordResetComplete,
    db: AsyncSession = Depends(get_db),
):
    try:
        success = await reset_password(
            db=db,
            email=data.email,
            token=data.token,
            new_password=data.password,
        )
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        ) from exc

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    return {"message": "Password reset successfully."}
