from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from config.dependencies import get_jwt_auth_manager
from database.session_sqlite import get_db
from database.models.accounts import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupModel,
    UserModel,
)
from schemas.accounts import (
    ActivateAccountRequestSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    MessageResponse,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    RefreshRequestSchema,
    RefreshResponseSchema,
    UserRegistrationRequestSchema,
    UserResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

router = APIRouter(prefix="/accounts", tags=["Accounts"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _gen_token() -> str:
    return uuid.uuid4().hex


# ----------------------------- Registration ----------------------------- #
@router.post(
    "/register/",
    response_model=UserResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserResponseSchema:
    # Email already exists?
    res = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    # Default group USER (pre-seeded by migrations/fixtures)
    res_group = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == "USER")
    )
    default_group = res_group.scalar_one_or_none()

    try:
        user = UserModel(
            email=user_data.email,
            _hashed_password=hash_password(user_data.password),
            is_active=False,
            group=default_group,
        )
        db.add(user)
        await db.flush()  # get user.id

        # Create activation token (24h lifetime)
        token = ActivationTokenModel(
            user_id=cast(int, user.id),
            token=_gen_token(),
            expires_at=_utcnow() + timedelta(hours=24),
        )
        db.add(token)

        await db.commit()
        await db.refresh(user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserResponseSchema(id=cast(int, user.id), email=user.email)


# ------------------------------ Activation ------------------------------ #
@router.post("/activate/", response_model=MessageResponse)
async def activate_account(
    payload: ActivateAccountRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    res_user = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    user = res_user.scalar_one_or_none()
    if user is None:
        # Do not leak user existence
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    res_token = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == cast(int, user.id)
        )
    )
    token_rec = res_token.scalar_one_or_none()
    if token_rec is None or token_rec.token != payload.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    # SQLite stores naive datetimes — make it tz-aware for comparison
    expires = cast(datetime, token_rec.expires_at).replace(tzinfo=timezone.utc)
    if expires <= _utcnow():
        await db.delete(token_rec)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token_rec)
    await db.commit()
    return MessageResponse(message="User account activated successfully.")


# ------------------------ Password reset: request ------------------------ #
@router.post("/password-reset/request/", response_model=MessageResponse)
async def request_password_reset(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    # Always respond with success, but if user exists and is active — reissue token
    res_user = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    user = res_user.scalar_one_or_none()

    if user and user.is_active:
        # Invalidate existing tokens
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == cast(int, user.id)
            )
        )
        # Issue a new one (2h)
        reset_token = PasswordResetTokenModel(
            user_id=cast(int, user.id),
            token=_gen_token(),
            expires_at=_utcnow() + timedelta(hours=2),
        )
        db.add(reset_token)
        await db.commit()

    return MessageResponse(
        message="If you are registered, you will receive an email with instructions."
    )


# ---------------------- Password reset: complete ------------------------ #
@router.post("/reset-password/complete/", response_model=MessageResponse)
async def complete_password_reset(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    res_user = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    user = res_user.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    res_token = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == cast(int, user.id)
        )
    )
    token_rec = res_token.scalar_one_or_none()
    if token_rec is None or token_rec.token != payload.token:
        if token_rec:
            await db.delete(token_rec)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires = cast(datetime, token_rec.expires_at).replace(tzinfo=timezone.utc)
    if expires <= _utcnow():
        await db.delete(token_rec)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user._hashed_password = hash_password(payload.password)
        await db.delete(token_rec)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )

    return MessageResponse(message="Password reset successfully.")


# --------------------------------- Login --------------------------------- #
@router.post(
    "/login/",
    response_model=LoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    payload: LoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
) -> LoginResponseSchema:
    # Find user & verify password
    res_user = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    user = res_user.scalar_one_or_none()
    if user is None or not verify_password(
        payload.password, getattr(user, "_hashed_password")
    ):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        # Create tokens
        access_token = jwt_manager.create_access_token(user_id=cast(int, user.id))
        refresh_token = jwt_manager.create_refresh_token(user_id=cast(int, user.id))

        # Save refresh via model factory; use naive UTC for SQLite
        expires_at_naive = datetime.utcnow() + timedelta(days=7)
        await RefreshTokenModel.create(
            db,
            user_id=cast(int, user.id),
            token=refresh_token,
            expires_at=expires_at_naive,
        )
        await db.flush()
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )

    return LoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


# -------------------------------- Refresh -------------------------------- #
@router.post("/refresh/", response_model=RefreshResponseSchema)
async def refresh_access_token(
    payload: RefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db),
) -> RefreshResponseSchema:
    # Validate / decode refresh
    try:
        decoded = jwt_manager.decode_refresh_token(payload.refresh_token)
    except Exception as e:
        # tests expect 400 for invalid/expired
        raise HTTPException(status_code=400, detail=str(e))

    user_id = cast(int, decoded.get("user_id"))

    # Ensure such refresh exists in DB
    res_rt = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == payload.refresh_token
        )
    )
    rt = res_rt.scalar_one_or_none()
    if rt is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    # Ensure user exists
    res_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = res_user.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    # Issue new access
    access = jwt_manager.create_access_token(user_id=user_id)
    return RefreshResponseSchema(access_token=access)
