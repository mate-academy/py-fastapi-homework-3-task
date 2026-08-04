from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload


from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
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
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    group_id = await db.scalar(
        select(UserGroupModel.id).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )

    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=group_id,
    )

    activation_token = ActivationTokenModel(user=user)
    try:
        db.add(activation_token)
        db.add(user)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def user_account_activate(
    user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_token = (
        select(UserModel)
        .where(UserModel.email == user_data.email)
        .options(joinedload(UserModel.activation_token))
    )
    user = await db.scalar(user_token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    if (
        not user.activation_token
        or user.activation_token.token != user_data.token
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = user.activation_token.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(user.activation_token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset(
    user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_stmt = (
        select(UserModel)
        .where(UserModel.email == user_data.email)
        .options(joinedload(UserModel.password_reset_token))
    )

    user = await db.scalar(user_stmt)

    if user and user.is_active:
        if user.password_reset_token:
            await db.delete(user.password_reset_token)

        password_reset_token = PasswordResetTokenModel(user=user)
        db.add(password_reset_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def password_reset_complete(
    user_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    db_user = (
        select(UserModel)
        .where(UserModel.email == user_data.email)
        .options(
            joinedload(UserModel.password_reset_token),
        )
    )
    user = await db.scalar(db_user)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if (
        not user.password_reset_token
        or user.password_reset_token.token != user_data.token
        or user.password_reset_token.expires_at.replace(tzinfo=timezone.utc)
        < datetime.now(timezone.utc)
    ):
        if user.password_reset_token:
            await db.delete(user.password_reset_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    user.password = user_data.password
    await db.delete(user.password_reset_token)
    try:
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
async def user_login(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user_stmt = select(UserModel).where(
        UserModel.email == user_data.email,
    )
    user = await db.scalar(user_stmt)

    if not user or user.verify_password(user_data.password) is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    new_token_refresh = jwt_manager.create_refresh_token(
        data={"user_id": user.id}
    )
    token_refresh_for_user = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=new_token_refresh,
    )

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    try:
        db.add(token_refresh_for_user)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": access_token,
        "refresh_token": new_token_refresh,
        "token_type": "bearer",
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def token_refresh(
    user_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager=Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(user_data.refresh_token)
    except BaseSecurityError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    db_token = select(RefreshTokenModel).where(
        RefreshTokenModel.token == user_data.refresh_token
    )
    token = await db.scalar(db_token)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    db_user = await db.scalar(
        select(UserModel).where(UserModel.id == payload["user_id"])
    )
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": db_user.id}
    )

    return {"access_token": access_token}
