import secrets
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
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
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email.lower()),
    )
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {data.email} already exists.",
        )

    try:
        group_id = await db.scalar(
            select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER),
        )
        if group_id is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred during user creation.",
            )
        new_user = UserModel.create(
            email=data.email,
            raw_password=data.password,
            group_id=group_id,
        )
        new_user.activation_token = ActivationTokenModel()
        db.add(new_user)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return new_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .options(contains_eager(ActivationTokenModel.user))
        .where(
            UserModel.email == data.email.lower(),
            ActivationTokenModel.token == data.token,
        )
    )
    token = await db.scalar(stmt)

    expires_at = token.expires_at if token else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if token is None or expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if token.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    try:
        token.user.is_active = True
        await db.delete(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        )

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email.lower()),
    )

    if user is not None and user.is_active:
        try:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            db.add(PasswordResetTokenModel(user_id=user.id))
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while processing the request.",
            )

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    invalid_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token.",
    )

    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email.lower()),
    )
    if user is None or not user.is_active:
        raise invalid_error

    reset_token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    if reset_token is None:
        raise invalid_error

    expires_at = reset_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    token_is_valid = secrets.compare_digest(
        reset_token.token.encode(), data.token.encode()
    )

    try:
        if not token_is_valid or expires_at < datetime.now(timezone.utc):
            await db.delete(reset_token)
            await db.commit()
            raise invalid_error

        user.password = data.password
        await db.delete(reset_token)
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
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
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

    token_payload = {"user_id": user.id}
    access_token = jwt_manager.create_access_token(token_payload)
    refresh_token = jwt_manager.create_refresh_token(
        token_payload,
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
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


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    user_id = payload.get("user_id")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        )

    stored_token = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    )
    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )
    if stored_token.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        )

    user = await db.get(UserModel, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    return {"access_token": jwt_manager.create_access_token({"user_id": user.id})}
