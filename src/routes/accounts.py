from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from config import get_jwt_auth_manager
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    AccountActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    RefreshTokenRequestSchema,
    RefreshTokenResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.utils import generate_secure_token

router = APIRouter()
refresh_router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(stmt)
    if result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result_group = await db.execute(stmt_group)
    user_group = result_group.scalars().first()
    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(
            user_id=cast(int, new_user.id),
            token=generate_secure_token(),
        )
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return new_user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_account(
    data: AccountActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

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

    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset_token(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        reset_token = PasswordResetTokenModel(
            user_id=cast(int, user.id),
            token=generate_secure_token(),
        )
        db.add(reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
    data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    stmt_token = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record or token_record.token != data.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, token_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=LoginResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def login_user(
    credentials: LoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    stmt = select(UserModel).where(UserModel.email == credentials.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(credentials.password):
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
        refresh_token_str = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=7,
            token=refresh_token_str,
        )
        db.add(refresh_token_record)
        await db.commit()

        return LoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@refresh_router.post(
    "/api/v1/accounts/refresh/",
    response_model=RefreshTokenResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        )

    stmt_token = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user_id = payload.get("user_id")
    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if not user or user.id != token_record.user_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return RefreshTokenResponseSchema(access_token=new_access_token)
