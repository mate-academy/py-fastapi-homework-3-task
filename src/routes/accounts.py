from datetime import datetime, timezone
from typing import cast, Annotated

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
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()

DB = Annotated[AsyncSession, Depends(get_db)]


@router.post(
    path="/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
    responses={
        201: {"description": "User registered successfully."},
        409: {"description": "A user with the same email already exists."},
        500: {"description": "An error occurred during user creation."},
    },
)
async def register_user(user_data: UserRegistrationRequestSchema, db: DB):
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    existing_user = result.scalar()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result_group = await db.execute(stmt_group)
    user_group = result_group.scalars().first()

    try:
        new_user = UserModel.create(
            email=str(user_data.email),
            raw_password=user_data.password,
            group_id=user_group.id,
        )

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return new_user


@router.post(
    path="/activate/",
    response_model=MessageResponseSchema,
    status_code=200,
    responses={
        200: {"description": "The user's account was successfully activated."},
        409: {
            "description": "If the activation token is invalid or expired, "
            "or if the account is already active."
        },
    },
)
async def activate_account(
    activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .where(
            UserModel.email == activation_data.email,
            ActivationTokenModel.token == activation_data.token,
        )
    )
    result = await db.execute(stmt)
    activation_token = result.scalars().first()

    if not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(
        tzinfo=timezone.utc
    )

    if expires_at < datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = activation_token.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    path="/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=200,
    responses={
        200: {
            "description": "The request was successful. This response is always "
            "returned regardless of the user's existence or status."
        },
    },
)
async def request_password_reset_token(
    data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalar()

    success_message = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    if not user or not user.is_active:
        return success_message

    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return success_message


@router.post(
    path="/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200,
    responses={
        200: {"description": "Password reset successfully."},
        400: {
            "description": "The provided email, token, or password is invalid, "
            "or the token has expired."
        },
        500: {
            "description": "An unexpected error occurred while resetting the password."
        },
    },
)
async def reset_password(
    data: PasswordResetCompleteRequestSchema,
    db: DB,
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalar()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    result = await db.execute(stmt_token)
    reset_token = result.scalar()

    expires_at = cast(datetime, reset_token.expires_at).replace(tzinfo=timezone.utc)

    if (
        not reset_token
        or reset_token.token != data.token
        or expires_at < datetime.now(timezone.utc)
    ):
        if reset_token:
            await db.delete(reset_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    try:
        user.password = data.password
        await db.delete(reset_token)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    path="/login/",
    response_model=UserLoginResponseSchema,
    status_code=201,
    responses={
        401: {"description": "Invalid email or password."},
        403: {"description": "User account is not activated."},
        500: {"description": "An error occurred while processing the request."},
    },
)
async def login(
    data: UserLoginRequestSchema,
    db: DB,
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalar()

    if not user or not user.verify_password(raw_password=data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
        db.add(refresh_token_record)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token, refresh_token=refresh_token, token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    path="/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=200,
    responses={
        200: {"description": "Access token successfully refreshed."},
        400: {"description": "The provided refresh token is invalid or expired."},
        401: {
            "description": "The provided refresh token does not exist in the database."
        },
        404: {
            "description": "The user associated with the refresh token does not exist."
        },
    },
)
async def accounts_refresh(
    token_data: TokenRefreshRequestSchema,
    db: DB,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded_refresh_token = jwt_manager.decode_refresh_token(
            token_data.refresh_token
        )
    except BaseSecurityError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    user_id = decoded_refresh_token.get("user_id")

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == token_data.refresh_token
    )
    result = await db.execute(stmt)
    refresh_token = result.scalar()

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt_user)
    user = result.scalar()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
