from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    RefreshTokenModel,
    UserGroupModel,
    UserModel,
    get_db,
)
from database.models.accounts import PasswordResetTokenModel, UserGroupEnum
from exceptions import BaseSecurityError
from schemas import MessageResponseSchema, PasswordResetRequestSchema
from schemas.accounts import (
    PasswordResetCompleteRequestSchema,
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


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Returns a user information.",
    description=(
        "<h3>This endpoint registers a user in the system and return his id and email</h3>"
    ),
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user_query = select(UserModel).where(UserModel.email == user_data.email)

    if (await db.execute(user_query)).scalars().first():
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    group_query = select(UserGroupModel).where(
        UserGroupModel.name == UserGroupEnum.USER
    )
    group = (await db.execute(group_query)).scalars().first()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group does not exist in database. Seed user_groups table.",
        )
    try:
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=group.id,
        )
        user.activation_token = ActivationTokenModel()
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return UserRegistrationResponseSchema(id=user.id, email=user.email)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(err),
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activates a user account.",
    description="This endpoint activates user account using activation token.",
)
async def activate_user(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    activation_status_query = (
        select(UserModel)
        .where(UserModel.email == activation_data.email)
        .options(selectinload(UserModel.activation_token))
    )
    user = (await db.execute(activation_status_query)).scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )
    token_model = user.activation_token

    if not token_model or token_model.token != activation_data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = token_model.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    user.is_active = True
    await db.delete(token_model)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Password reset request",
    description=("User requests for password reset."),
)
async def password_reset_request(
    password_reset_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    email_query = (
        select(UserModel)
        .where(UserModel.email == password_reset_data.email)
        .options(selectinload(UserModel.password_reset_token))
    )
    user = (await db.execute(email_query)).scalars().first()
    if user and user.is_active:
        try:
            if user.password_reset_token:
                await db.delete(user.password_reset_token)
            user.password_reset_token = PasswordResetTokenModel()

            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while generating the password reset token.",
            )
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Password reset complete",
    description=("User requests for password reset completion."),
)
async def password_reset_complete(
    password_reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user_query = (
        select(UserModel)
        .where(UserModel.email == password_reset_data.email)
        .options(selectinload(UserModel.password_reset_token))
    )
    user = (await db.execute(user_query)).scalars().first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    token_model = user.password_reset_token
    if not token_model:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    expires_at = token_model.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if token_model.token != password_reset_data.token:
        await db.delete(token_model)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_model)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    try:
        user.password = password_reset_data.password
        await db.delete(token_model)
        await db.commit()
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    summary="Endpoint for user login",
    description=(
        "User requests for login with email and password and gets the access_token and refresh_token"
    ),
)
async def user_login(
    user_login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user_query = select(UserModel).where(UserModel.email == user_login_data.email)
    user = (await db.execute(user_query)).scalars().first()
    if not user or not user.verify_password(user_login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )
    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Refreshes access token using valid refresh token.",
)
async def user_refresh(
    refresh_token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    try:
        payload = jwt_manager.decode_refresh_token(refresh_token_data.refresh_token)
    except (BaseSecurityError, Exception):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    user_id = payload.get("user_id")

    token_query = select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_token_data.refresh_token
    )
    token_record = (await db.execute(token_query)).scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_query = select(UserModel).where(UserModel.id == user_id)
    user = (await db.execute(user_query)).scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    new_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(
        access_token=new_access_token,
        token_type="bearer",
    )
