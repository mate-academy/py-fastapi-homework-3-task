import secrets

from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import cast
from datetime import timezone, datetime, timedelta

from sqlalchemy.orm import joinedload
from sqlalchemy.sql.expression import delete

from config import get_jwt_auth_manager, BaseAppSettings, get_settings, settings
from database import get_db
from database.models.accounts import UserModel, UserGroupModel, ActivationTokenModel, UserGroupEnum, \
    PasswordResetTokenModel, RefreshTokenModel
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import UserLoginRequestSchema
from schemas.accounts import UserRegistrationRequestSchema, UserResponseSchema, UserActivationRequestSchema, \
    PasswordResetRequestSchema, PasswordResetResponseSchema, PasswordResetCompleteSchema, UserLoginResponseSchema, \
    TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password
from security.token_manager import JWTAuthManager
from security.utils import generate_secure_token

router = APIRouter()


@router.post("/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    try:
        existing_user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
        if existing_user.scalar():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        user_group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        group = user_group.scalar_one_or_none()
        if not group:
            raise HTTPException(status_code=500, detail="Default user group not found.")

        user = UserModel.create(email=user_data.email, raw_password=user_data.password, group_id=group.id)
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, user.id))
        db.add(activation_token)
        await db.commit()

        return {"id": user.id, "email": user.email}

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK
)
async def activate_user(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == payload.email)
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.activation_token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token_record = user.activation_token

    if token_record.token != payload.token:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
)
async def reset_password_complete(
    payload: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    stmt_tokens = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_tokens = await db.execute(stmt_tokens)
    tokens = result_tokens.scalars().all()

    token_record = next((t for t in tokens if t.token == payload.token), None)

    if not token_record:
        for t in tokens:
            await db.delete(t)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    user.password = payload.password

    try:
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return {"message": "Password reset successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK
)
async def request_password_reset_token(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return {"message": "If you are registered, you will receive an email with instructions."}

    stmt_tokens = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_tokens = await db.execute(stmt_tokens)
    old_tokens = result_tokens.scalars().all()
    for t in old_tokens:
        await db.delete(t)

    token = generate_secure_token()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

    reset_token = PasswordResetTokenModel.create(
        user_id=cast(int, user.id),
        token=token,
        expires_at=expires_at
    )

    db.add(reset_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create password reset token.")

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201
)
async def login_user(
    payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({
        "sub": str(user.id),
        "user_id": user.id
    })
    refresh_token = jwt_manager.create_refresh_token({
        "sub": str(user.id),
        "user_id": user.id
    })

    try:
        refresh_token_entry = RefreshTokenModel.create(
            user_id=user.id, token=refresh_token, days_valid=settings.LOGIN_TIME_DAYS
        )
        db.add(refresh_token_entry)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=200
)
async def refresh_access_token(
        payload: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        token_data = jwt_manager.decode_refresh_token(payload.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid refresh token.")

    user_id = token_data.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload.")

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    result = await db.execute(stmt)
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    stmt = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({
        "sub": str(user.id),
        "user_id": user.id
    })

    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
