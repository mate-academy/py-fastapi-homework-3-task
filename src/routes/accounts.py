from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

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
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from security.hashing import hash_password
from database.validators.accounts import validate_password_strength
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    MessageResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

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
    try:
        validate_password_strength(user_data.password)

        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        user_group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )

        hashed_pw = hash_password(user_data.password)
        new_user = UserModel(
            email=user_data.email,
            password=hashed_pw,
            is_active=False,
            group_id=cast(int, user_group.id) if user_group else None,
        )

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema(id=new_user.id, email=new_user.email)

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_record = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )

    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    message = "If you are registered, you will receive an email with instructions."

    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user or not user.is_active:
        return MessageResponseSchema(message=message)

    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    reset_token = PasswordResetTokenModel(user_id=cast(int, user.id))
    db.add(reset_token)
    await db.commit()

    return MessageResponseSchema(message=message)


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        validate_password_strength(data.password)

        user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
        if not user or not user.is_active:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        token_record = await db.scalar(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )

        if not token_record or token_record.token != data.token:
            if token_record:
                await db.delete(token_record)
                await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
        if expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = data.password
        db.add(user)
        await db.commit()
        await db.refresh(user)

        await db.delete(token_record)
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except HTTPException:
        raise
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
)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token_str = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_token = RefreshTokenModel(user_id=user.id, token=refresh_token_str)
        db.add(refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_str,
            token_type="bearer",
        )
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        if payload is None:
            raise HTTPException(status_code=400, detail="Token has expired.")

        token_record = await db.scalar(
            select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
        )
        if not token_record:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

        user = await db.scalar(
            select(UserModel).where(UserModel.id == token_record.user_id)
        )
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        new_access_token = jwt_manager.create_access_token({"user_id": user.id})

        return TokenRefreshResponseSchema(
            access_token=new_access_token,
            refresh_token=token_record.token,
            token_type="bearer",
        )

    except BaseSecurityError as e:
        if "expired" in str(e).lower():
            raise HTTPException(status_code=400, detail="Token has expired.")
        raise HTTPException(status_code=400, detail=str(e))
