import secrets
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.accounts import get_user_by_email, create_user, get_activation_token
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)
from security.passwords import hash_password, verify_password

router = APIRouter()


# ---------------- REGISTER ----------------

@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, user.email)

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )

    return await create_user(db, email=user.email, password=user.password)


# ---------------- ACTIVATE ----------------

@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def activate(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, data.email)

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_record = await get_activation_token(db, db_user.id)

    if not token_record or token_record.token != data.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True

    db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


# ---------------- PASSWORD RESET REQUEST ----------------

@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def password_reset_request(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    db_user = await get_user_by_email(db, data.email)

    try:
        if db_user and db_user.is_active:
            await db.execute(
                delete(PasswordResetTokenModel)
                .where(PasswordResetTokenModel.user_id == db_user.id)
            )

            token = secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(hours=1)

            new = PasswordResetTokenModel(
                user_id=cast(int, db_user.id),
                token=token,
                expires_at=expires
            )

            db.add(new)
            await db.commit()

    except Exception:
        await db.rollback()

    return {"message": "If you are registered, you will receive an email with instructions."}


# ---------------- PASSWORD RESET COMPLETE ----------------

@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema
)
async def password_reset_complete(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, reset_data.email)

    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )

    token_record = result.scalar_one_or_none()

    if not token_record or token_record.token != reset_data.token:
        if token_record:
            db.delete(token_record)
            await db.commit()

        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    db_user._hashed_password = hash_password(reset_data.password)

    db.delete(token_record)
    await db.commit()

    return {"message": "Password reset successfully."}


# ---------------- LOGIN ----------------

@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED   # ⚠️ tests require 201
)
async def login(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager=Depends(get_jwt_auth_manager)
):
    db_user = await get_user_by_email(db, login_data.email)

    if not db_user or not verify_password(login_data.password, db_user._hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(
        {"sub": db_user.email, "user_id": db_user.id}
    )

    refresh_token = jwt_manager.create_refresh_token(
        {"sub": db_user.email, "user_id": db_user.id}
    )

    new_refresh = RefreshTokenModel(user_id=db_user.id, token=refresh_token)
    db.add(new_refresh)
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# ---------------- REFRESH ----------------

@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_201_CREATED  # ⚠️ tests require 201
)
async def refresh(
    data: TokenRefreshRequestSchema,
    jwt_manager=Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db)
):
    payload = jwt_manager.decode_refresh_token(data.refresh_token)

    user_id = payload.get("user_id")

    if user_id is None:
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token
    )

    result = await db.execute(stmt)
    token_record = result.scalar_one_or_none()

    if not token_record or token_record.user_id != user_id:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )

    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(
        {"sub": user.email, "user_id": user.id}
    )

    return {"access_token": new_access_token}
