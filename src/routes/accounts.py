from typing import cast
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import IntegrityError

from config import get_jwt_auth_manager
from database import (
    PasswordResetTokenModel,
    ActivationTokenModel,
    UserModel,
    RefreshTokenModel,
    get_db,
    UserGroupEnum, UserGroupModel,
)
from schemas.accounts import (
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
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    group_result = await db.execute(
        select(UserGroupModel).filter(UserGroupModel.name == "user")
    )
    user_group = group_result.scalars().first()

    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User group not found.",
        )

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id
        )

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        return UserRegistrationResponseSchema.model_validate(new_user)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == activation_data.email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found.",
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    result = await db.execute(
        select(ActivationTokenModel).filter(
            ActivationTokenModel.token == activation_data.token,
            ActivationTokenModel.user_id == user.id,
        )
    )
    token_record = result.scalars().first()
    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(token_record)
        await db.commit()
        return MessageResponseSchema(message="User account activated successfully.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate account.",
        )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
    reset_request: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == reset_request.email))
    user = result.scalars().first()

    success_message = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )
    if not user or not user.is_active:
        return success_message

    await db.execute(
        PasswordResetTokenModel.__table__.delete().where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    reset_token = PasswordResetTokenModel(user_id=user.id)
    db.add(reset_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
    return success_message


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel).filter(UserModel.email == reset_data.email)
    )
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    result = await db.execute(
        select(PasswordResetTokenModel).filter(
            PasswordResetTokenModel.token == reset_data.token,
            PasswordResetTokenModel.user_id == user.id,
        )
    )
    token_record = result.scalars().first()

    if not token_record:
        existing_token_stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        existing_token_result = await db.execute(existing_token_stmt)
        existing_token = existing_token_result.scalars().first()

        if existing_token:
            await db.delete(existing_token)
            await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = token_record.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    try:
        user.password = reset_data.password

        await db.delete(token_record)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(select(UserModel).filter(UserModel.email == login_data.email))
    user = result.scalars().first()

    if not user or not verify_password(login_data.password, user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token(data={"user_id": cast(int, user.id)})
    refresh_token_str = jwt_manager.create_refresh_token(data={"user_id": cast(int, user.id)})

    try:
        refresh_token_record = RefreshTokenModel(user_id=user.id, token=refresh_token_str)
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token_str, token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid refresh token payload.")

    result = await db.execute(
        select(RefreshTokenModel).filter(
            RefreshTokenModel.token == token_data.refresh_token,
            RefreshTokenModel.user_id == user_id,
        )
    )
    token_in_db = result.scalars().first()
    if not token_in_db:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    result = await db.execute(select(UserModel).filter(UserModel.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(data={"user_id": user.id})

    return TokenRefreshResponseSchema(access_token=new_access_token)
