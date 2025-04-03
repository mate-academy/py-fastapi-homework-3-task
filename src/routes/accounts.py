from datetime import datetime, timezone
from typing import cast
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
    RefreshTokenModel
)
from database.validators.accounts import validate_password_strength
from exceptions import BaseSecurityError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.passwords import hash_password
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    user_query = await db.execute(select(UserModel).filter(UserModel.email == user.email))
    user_exists = user_query.scalar_one_or_none()

    if user_exists:
        raise HTTPException(
            detail=f"A user with this email {user.email} already exists.",
            status_code=status.HTTP_409_CONFLICT
        )

    try:
        validate_password_strength(user.password)
    except ValueError as e:
        raise HTTPException(
            detail=str(e),
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )

    hashed_psw = hash_password(user.password)

    user_group_query = await db.execute(select(UserGroupModel).filter(UserGroupModel.name == UserGroupEnum.USER))
    user_group = user_group_query.scalar_one_or_none()
    try:
        new_user = UserModel(
            email=cast(str, user.email),
            _hashed_password=hashed_psw,
            group_id=cast(int, user_group.id)
        )
        db.add(new_user)
        await db.flush()
        activate_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activate_token)
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        raise HTTPException(
            detail="An error occurred during user creation.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    return UserRegistrationResponseSchema.model_validate({
        "id": new_user.id,
        "email": new_user.email
    })


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def account_activate(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    query = await db.execute(
        select(ActivationTokenModel).options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .filter(ActivationTokenModel.token == user.token)
        .filter(UserModel.email == user.email)
    )
    activation_token = query.scalar_one_or_none()

    if not activation_token:
        raise HTTPException(
            detail="Invalid or expired activation token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    if cast(datetime, activation_token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await db.delete(activation_token)
        await db.commit()
        raise HTTPException(
            detail="Invalid or expired activation token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    user_activation = activation_token.user

    if user_activation.is_active:
        raise HTTPException(
            detail="User account is already active.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    user_activation.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset(input_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user_query = await db.execute(select(UserModel).filter(UserModel.email == input_data.email))
    user = user_query.scalar_one_or_none()

    if not user or not user.is_active:
        return {
            "message": "If you are registered, you will receive an email with instructions."
        }
    await db.execute(delete(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id))
    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def password_reset_complete(input_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user_query = await db.execute(select(UserModel).filter(UserModel.email == input_data.email))
    user = user_query.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            detail="Invalid email or token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    token_query = await db.execute(select(PasswordResetTokenModel).filter(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == input_data.token)
    )
    token = token_query.scalar_one_or_none()

    existing_tokens_query = await db.execute(
        select(PasswordResetTokenModel).filter(PasswordResetTokenModel.user_id == user.id))
    existing_tokens = existing_tokens_query.scalars().all()

    if not token:
        if existing_tokens:
            for existing_token in existing_tokens:
                await db.delete(existing_token)
            await db.commit()
        raise HTTPException(
            detail="Invalid email or token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    token_expires = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    current_time = datetime.now(timezone.utc)

    if token_expires < current_time:
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            detail="Invalid email or token.",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    try:
        user._hashed_password = hash_password(input_data.password)
        await db.delete(token)
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
async def login(
        input_data: UserLoginRequestSchema,
        settings_manager: BaseAppSettings = Depends(get_settings),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db)
):
    user_query = await db.execute(select(UserModel).filter(UserModel.email == input_data.email))
    user = user_query.scalar_one_or_none()

    if not user or not user.verify_password(input_data.password):
        raise HTTPException(
            detail="Invalid email or password.",
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    if not user.is_active:
        raise HTTPException(
            detail="User account is not activated.",
            status_code=status.HTTP_403_FORBIDDEN
        )

    access_token = jwt_manager.create_access_token({
        "user_id": user.id
    })
    refresh_token = jwt_manager.create_refresh_token({
        "user_id": user.id
    })
    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token,
            days_valid=settings_manager.LOGIN_TIME_DAYS
        )
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            detail="An error occurred while processing the request.",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
    return UserLoginResponseSchema.model_validate(
        {"access_token": access_token,
         "refresh_token": refresh_token
         }
    )


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(
        input_data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db)
):
    try:
        jwt_decode = jwt_manager.decode_refresh_token(input_data.refresh_token)
        user_id = jwt_decode.get("user_id")
    except BaseSecurityError:
        raise HTTPException(
            detail="Token has expired.",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    refresh_token_query = await db.execute(
        select(RefreshTokenModel).filter(RefreshTokenModel.token == input_data.refresh_token))
    refresh_token = refresh_token_query.scalar_one_or_none()

    if not refresh_token:
        raise HTTPException(
            detail="Refresh token not found.",
            status_code=status.HTTP_401_UNAUTHORIZED
        )
    user_query = await db.execute(select(UserModel).filter(UserModel.id == user_id))
    user = user_query.scalar_one_or_none()

    if not user:
        raise HTTPException(
            detail="User not found.",
            status_code=status.HTTP_404_NOT_FOUND
        )
    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return TokenRefreshResponseSchema.model_validate({"access_token": access_token})
