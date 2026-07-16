from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

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
from exceptions import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    MessageResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201
)
async def register(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )

    result = await db.execute(
        select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
    )
    user_group = result.scalar_one_or_none()

    if not user_group:
        raise HTTPException(
            status_code=500,
            detail="Default user group not found."
        )

    try:
        db_user = UserModel.create(
            email=str(user.email),
            raw_password=user.password,
            group_id=user_group.id
        )
        db.add(db_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=db_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(db_user)
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )

    return db_user


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=200
)
async def activate(
        payload: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == payload.email)
    )
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    if db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="User account is already active."
        )

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == payload.token
        )
    )
    db_activation_token = result.scalar_one_or_none()

    if (
        not db_activation_token
        or db_activation_token.user_id != db_user.id
        or cast(datetime, db_activation_token.expires_at).replace(tzinfo=timezone.utc)
            < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    await db.execute(
        delete(ActivationTokenModel).where(
            ActivationTokenModel.user_id == db_user.id
        )
    )
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=200
)
async def password_reset_request(
        request: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):

    result = await db.execute(
        select(UserModel).where(UserModel.email == request.email)
    )
    db_user = result.scalar_one_or_none()

    if db_user and db_user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
        )

        password_reset_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(password_reset_token)

        await db.commit()

    return {
        "message": "If you are registered, "
                   "you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=200
)
async def password_reset_complete(
        request: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == request.email)
    )
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Invalid email or token."
        )

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
    )
    db_password_reset_token = result.scalar_one_or_none()

    try:
        if (
            not db_password_reset_token
            or db_password_reset_token.token != request.token
            or cast(datetime, db_password_reset_token.expires_at).
                replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        ):
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == db_user.id
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )
        else:
            db_user.password = request.password  # password.setter handles validation and hashing
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == db_user.id
                )
            )
            await db.commit()
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )
    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201
)
async def login(
    request: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == request.email)
    )
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.verify_password(request.password):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="User account is not activated."
        )

    access_token_str = jwt_manager.create_access_token(
        data={"user_id": db_user.id}
    )
    refresh_token_str = jwt_manager.create_refresh_token(
        data={"user_id": db_user.id}
    )

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token_str
        )
        db.add(refresh_token)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token_str,
        "refresh_token": refresh_token_str,
        "token_type": "bearer"
    }


@router.post(
    "/api/v1/accounts/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=200
)
async def refresh(
        request: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(request.refresh_token)
        user_id = int(payload["user_id"])
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Token has expired.")

    result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == request.refresh_token
        )
    )
    old_refresh_token = result.scalar_one_or_none()

    if not old_refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Refresh token not found."
        )

    result = await db.execute(
        select(UserModel).where(UserModel.id == user_id)
    )
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token(
        data={"user_id": db_user.id}
    )
    return {"access_token": new_access_token}
