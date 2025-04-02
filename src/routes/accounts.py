from datetime import datetime, timezone
from tokenize import group
from typing import cast
from starlette import status
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema, UserLoginResponseSchema, TokenRefreshRequestSchema, TokenRefreshResponseSchema
)
from security.passwords import hash_password
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED, response_model=UserRegistrationResponseSchema)
async def create_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    query = await db.execute(select(UserModel).filter(UserModel.email == user.email))
    existing_user = query.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            detail=f"A user with this email {user.email} already exists.",
            status_code=status.HTTP_409_CONFLICT
        )

    user_group_query = await db.execute(select(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER))
    user_group = user_group_query.scalar_one_or_none()

    if not user_group:
        raise HTTPException(
            detail="An error occurred during user creation",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    try:
        hashed = hash_password(user.password)
        new_user = UserModel(email=str(user.email), _hashed_password=hashed, group_id=user_group.id)
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            detail="An error occurred during user creation",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    return UserRegistrationResponseSchema.model_validate(new_user)


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    token_query = await db.execute(
        select(ActivationTokenModel).join(ActivationTokenModel.user).options(
            joinedload(ActivationTokenModel.user)
        ).filter(
            UserModel.email == user.email,
            ActivationTokenModel.token == user.token)
    )
    activate_token = token_query.scalar_one_or_none()

    if not activate_token or cast(datetime, activate_token.expires_at).replace(
            tzinfo=timezone.utc) < datetime.now(timezone.utc):
        if activate_token:
            await db.delete(activate_token)
            await db.commit()
        raise HTTPException(
            detail="Invalid or expired activation token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    user_model = activate_token.user

    if user_model.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user_model.is_active = True
    await db.commit()
    await db.refresh(user_model)

    await db.delete(activate_token)
    await db.commit()

    return {
        "message": "User account activated successfully."
    }


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset(user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user_query = await db.execute(select(UserModel).filter(UserModel.email == user.email))
    result = user_query.scalar_one_or_none()
    if not result or not result.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }

    existing_token_query = await db.execute(
        select(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == result.id))
    existing_token = existing_token_query.scalar_one_or_none()

    if existing_token:
        await db.delete(existing_token)
        await db.commit()

    reset_token = PasswordResetTokenModel(user_id=result.id)
    db.add(reset_token)
    await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def password_reset_complete(user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user_query = await db.execute(select(UserModel).filter(UserModel.email == user.email))
    user_result = user_query.scalar_one_or_none()

    if not user_result:
        raise HTTPException(
            detail="Invalid email or token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    token_query = await db.execute(
        select(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user_result.id))
    token_result = token_query.scalar_one_or_none()

    if not token_result or token_result.token != user.token:
        raise HTTPException(
            detail="Invalid email or token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    token_expiration = cast(datetime, token_result.expires_at).replace(
        tzinfo=timezone.utc)
    if token_expiration < datetime.now(timezone.utc):
        await db.delete(token_result)
        await db.commit()
        raise HTTPException(
            detail="Invalid email or token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    try:
        user_result.password = hash_password(user.password)
        db.add(user_result)
        await db.delete(token_result)
        await db.commit()


    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            detail="An error occurred while resetting the password.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    return {
        "message": "Password reset successfully."
    }


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def user_login(
        user: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        settings_manager: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    query = await db.execute(select(UserModel).filter(UserModel.email == user.email))
    result = query.scalar_one_or_none()

    if not result or not result.verify_password(user.password):
        raise HTTPException(
            detail="Invalid email or password.",
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    if not result.is_active:
        raise HTTPException(
            detail="User account is not activated.",
            status_code=status.HTTP_403_FORBIDDEN
        )
    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": result.id})

    try:
        create_refresh_token = RefreshTokenModel.create(
            user_id=result.id,
            days_valid=settings_manager.LOGIN_TIME_DAYS,
            token=jwt_refresh_token,
        )
        db.add(create_refresh_token)
        await db.flush()
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            detail="An error occurred while processing the request.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    jwt_access_token = jwt_manager.create_access_token({"user_id": result.id})
    return UserLoginResponseSchema.model_validate({
        "access_token": jwt_access_token,
        "refresh_token": jwt_refresh_token
    })


router.post("/api/v1/accounts/refresh/", status_code=status.HTTP_200_OK)


async def refresh_token(
        user: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decode_token = jwt_manager.decode_refresh_token(user.refresh_token)
        user_id = decode_token.get("user_id")
    except BaseSecurityError:
        raise HTTPException(
            detail="Token has expired.",
            status_code=status.HTTP_400_BAD_REQUEST,

        )
    query = await db.execute(select(RefreshTokenModel).filter(RefreshTokenModel.token == user.refresh_token))
    token_result = query.scalar_one_or_none()
    if not token_result:
        raise HTTPException(
            detail="Refresh token not found.",
            status_code=status.HTTP_401_UNAUTHORIZED

        )
    user_query = await db.execute(select(UserModel).filter(UserModel.id == user_id))
    user_result = user_query.scalar_one_or_none()
    if not user_result:
        raise HTTPException(
            detail="User not found.",
            status_code=status.HTTP_404_NOT_FOUND

        )
    new_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema.model_validate({"access_token": new_access_token})
