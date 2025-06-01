from datetime import datetime

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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
from database.validators.accounts import validate_password_strength, validate_email
from exceptions import BaseSecurityError, TokenExpiredError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"description": "User registered successfully."},
        409: {"description": "A user with the same email already exists."},
        500: {"description": "An error occurred during user creation."},
    },
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    existing = await db.scalar(select(UserModel).where((UserModel.email == user.email)))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        hashed = hash_password(user.password)
        group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        db_user = UserModel(
            email=user.email, _hashed_password=hashed, group_id=group.id
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)
        await db.commit()
        return UserRegistrationResponseSchema(
            id=db_user.id,
            email=db_user.email
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "User account activated successfully."},
        400: {"description": "Invalid or expired activation token."},
    },
)
async def activate_user(
    data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    user_stmt = (
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(selectinload(UserModel.activation_token))
    )
    user = (await db.execute(user_stmt)).scalar_one_or_none()

    if not user or not user.activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_obj = user.activation_token
    if token_obj.token != data.token or token_obj.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token_obj)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        200: {
            "description": "If you are registered, you will receive an email with instructions."
        },
    },
)
async def reset_password(
    data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    user_stmt = (
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(selectinload(UserModel.password_reset_token))
    )
    user = (await db.execute(user_stmt)).scalar_one_or_none()

    if not user or not user.is_active:
        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    if user.password_reset_token:
        await db.delete(user.password_reset_token)
        await db.commit()

    reset_token = PasswordResetTokenModel(user_id=user.id)
    db.add(reset_token)
    await db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "Password reset successfully."},
        400: {"description": "Invalid email or token."},
        500: {"description": "An error occurred while resetting the password."},
    },
)
async def reset_password_complete(
    data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    stmt = (
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(selectinload(UserModel.password_reset_token))
    )
    user = await db.scalar(stmt)

    if not user or not user.is_active or not user.password_reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    token_obj = user.password_reset_token

    if token_obj.token != data.token or token_obj.expires_at < datetime.utcnow():
        await db.delete(token_obj)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        validate_password_strength(data.password)
        user._hashed_password = hash_password(data.password)
        await db.delete(token_obj)

        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
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
    responses={
        401: {"description": "Invalid email or password."},
        403: {"description": "User account is not activated."},
        500: {"description": "An error occurred while processing the request."},
    },
)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    try:
        validate_email(data.email)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    stmt = select(UserModel).where(UserModel.email == data.email)
    user = await db.scalar(stmt)

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token_str = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token_str = jwt_manager.create_refresh_token({"user_id": user.id})
    try:
        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_str,
        )
        db.add(refresh_token_obj)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token_str,
        refresh_token=refresh_token_str,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"description": "new_access_token"},
        400: {"description": "Token has expired."},
        401: {"description": "Refresh token not found."},
        404: {"description": "User not found."},
    },
)
async def refresh(
    data: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
) -> TokenRefreshResponseSchema:
    try:
        token = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token
    )
    refresh_token = await db.scalar(stmt)
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    try:
        user_id = int(token["user_id"])
    except (KeyError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user = await db.scalar(user_stmt)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return TokenRefreshResponseSchema(access_token=access_token)
