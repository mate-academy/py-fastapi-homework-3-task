import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

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
from exceptions import TokenExpiredError
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema
from schemas.accounts import (
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    responses={
        201: {"detail": "User registered successfully."},
        409: {"detail": "A user with this email test@example.com already exists."},
        500: {"detail": "An error occurred during user creation."},
    },
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    existing_user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )
    user_group = await db.scalar(
        select(
            UserGroupModel
        ).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )
    if not user_group:
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    try:
        new_user = UserModel(
            email=user_data.email,
            password=hash_password(user_data.password),
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user=new_user,
        )
        db.add(activation_token)

        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )
    return new_user


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"detail": "User account activated successfully."},
        400: {"detail": "Invalid or expired activation token."},
    },
)
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

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

    result = await db.execute(
        select(ActivationTokenModel)
        .where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == data.token
        )
    )
    token = result.scalar_one_or_none()

    if not token or token.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"message": "If you are registered, you will receive an email with instructions."},
    }
)
async def reset_password(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(
            PasswordResetTokenModel.__table__.delete()
            .where(PasswordResetTokenModel.user_id == user.id)
        )
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=1)

        new_token = PasswordResetTokenModel(
            user_id=user.id,
            token=token,
            expires_at=expires_at,
        )
        db.add(new_token)

    await db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"message": "Password reset successfully."},
        400: {"detail": "Invalid email or token."},
        500: {"detail": "An error occurred while resetting the password."},
    },
)
async def reset_password_complete(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    stmt = (
        select(UserModel)
        .where(UserModel.email == data.email)
        .options(selectinload(UserModel.password_reset_token))
    )
    user = await db.scalar(stmt)

    if not user or not user.is_active or not user.password_reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    token_obj = user.password_reset_token

    if token_obj.token != data.token or token_obj.expires_at < datetime.utcnow():
        await db.delete(token_obj)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = data.password
        await db.delete(token_obj)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/",
             status_code=status.HTTP_201_CREATED
             )
async def login_user(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
) -> UserLoginResponseSchema:
    user = await db.scalar(
        select(
            UserModel
        ).where(
            UserModel.email == user_data.email
        )
    )
    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    access_token = jwt_manager.create_access_token(
        {"user_id": user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}
    )
    try:
        token_obj = RefreshTokenModel(
            user_id=user.id,
            token=refresh_token,
            expires_at=datetime.utcnow() + timedelta(days=settings.LOGIN_TIME_DAYS)
        )
        db.add(token_obj)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token
    )


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK,
    responses={
        200: {"access_token": "new_access_token"},
        400: {"detail": "Token has expired."},
        401: {"detail": "Refresh token not found."},
        404: {"detail": "User not found."},
    },
)
async def refresh(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
) -> TokenRefreshResponseSchema:
    try:
        token = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    refresh_token = await db.scalar(stmt)
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    try:
        user_id = int(token["user_id"])
    except (TypeError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    user_stmt = select(UserModel).where(UserModel.id == user_id)
    user = await db.scalar(user_stmt)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return TokenRefreshResponseSchema(access_token=access_token)
