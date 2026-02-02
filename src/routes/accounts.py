from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from config.dependencies import get_db, get_settings, get_jwt_auth_manager
from config.settings import BaseAppSettings
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from database.validators.accounts import validate_password
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    MessageResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.passwords import hash_password, verify_password
from security.interfaces import JWTAuthManagerInterface

router = APIRouter(prefix="/api/v1/accounts", tags=["Accounts"])


@router.post(
    "/register/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserRegistrationResponseSchema,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    existing = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        validate_password(user_data.password)

        group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == "USER")
        )

        user = UserModel(
            email=user_data.email,
            hashed_password=hash_password(user_data.password),
            group=group,
            is_active=False,
        )
        db.add(user)
        await db.flush()

        token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(token)

        await db.commit()
        return user

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    token = await db.scalar(
        select(ActivationTokenModel)
        .join(UserModel)
        .where(
            UserModel.email == data.email,
            ActivationTokenModel.token == data.token,
        )
    )

    if not token:
        raise HTTPException(400, "Invalid or expired activation token.")

    expires = cast(datetime, token.expires_at).replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(400, "Invalid or expired activation token.")

    user = token.user
    if user.is_active:
        raise HTTPException(400, "User account is already active.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        db.add(PasswordResetTokenModel(user_id=cast(int, user.id)))
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))

    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(401, "Invalid email or password.")

    if not user.is_active:
        raise HTTPException(403, "User account is not activated.")

    refresh = jwt_manager.create_refresh_token(user.id)
    db.add(RefreshTokenModel.create(user.id, refresh, settings.LOGIN_TIME_DAYS))
    await db.commit()

    return {
        "access_token": jwt_manager.create_access_token(user.id),
        "refresh_token": refresh,
        "token_type": "bearer",
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    payload = jwt_manager.decode_refresh_token(data.refresh_token)

    token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
    )
    if not token:
        raise HTTPException(401, "Refresh token not found.")

    user = await db.get(UserModel, payload["user_id"])
    if not user:
        raise HTTPException(404, "User not found.")

    return {
        "access_token": jwt_manager.create_access_token(user.id)
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(
    body: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    """
    Complete password reset by verifying the token and updating the user's password.
    """
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == body.email))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found or inactive"
            )

        token_entry = await db.scalar(
            select(PasswordResetTokenModel)
            .where(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == body.token
            )
        )
        if not token_entry:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired token"
            )

        if token_entry.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired"
            )

        user.hashed_password = hash_password(body.password)
        await db.commit()

        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.id == token_entry.id)
        )
        await db.commit()

        return {"message": "Password reset successful"}

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
