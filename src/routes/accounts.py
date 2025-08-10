from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


async def get_user_by_email(
    email: str, db: AsyncSession = Depends(get_db)
) -> UserModel:
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    user = result.scalar_one_or_none()
    return user


@router.post(
    "/register/", status_code=201, response_model=UserRegistrationResponseSchema
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    email = cast(str, user_data.email)
    db_user = await get_user_by_email(email, db)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    try:
        group_result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == user_data.group)
        )
        group = group_result.scalar_one_or_none()

        new_user = UserModel(email=email, group=group)
        new_user.password = user_data.password
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        await db.commit()
        await db.refresh(new_user)
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    email = cast(str, activation_data.email)
    db_user = await get_user_by_email(email, db)

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == activation_data.token
        )
    )
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)
    if db_token.user != db_user or expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    db.add(db_user)
    await db.delete(db_token)
    await db.commit()
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
    request_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    email = cast(str, request_data.email)
    db_user = await get_user_by_email(email, db)
    if db_user and db_user.is_active:
        result = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user == db_user
            )
        )
        db_pwd_reset_token = result.scalar_one_or_none()
        if db_pwd_reset_token:
            await db.delete(db_pwd_reset_token)
            await db.refresh(db_user)
            await db.commit()

        new_pwd_reset_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(new_pwd_reset_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(
    reset_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    email = cast(str, reset_data.email)
    db_user = await get_user_by_email(email, db)
    bad_request_message = "Invalid email or token."
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail=bad_request_message)

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.token == reset_data.token
        )
    )
    db_token = result.scalar_one_or_none()
    if not db_token:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user == db_user
            )
        )
        await db.commit()
        raise HTTPException(status_code=400, detail=bad_request_message)
    expires_at = cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user == db_user
            )
        )
        await db.commit()
        raise HTTPException(status_code=400, detail=bad_request_message)

    if db_token.user != db_user:
        raise HTTPException(status_code=400, detail=bad_request_message)

    try:
        db_user.password = reset_data.password
        db.add(db_user)
        await db.delete(db_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )
    return {"message": "Password reset successfully."}


@router.post("/login/", status_code=201, response_model=UserLoginResponseSchema)
async def login(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    email = cast(str, user_data.email)
    db_user = await get_user_by_email(email, db)
    if not db_user or not db_user.verify_password(user_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        data = {"sub": email, "user_id": db_user.id}
        access_token = jwt_manager.create_access_token(data)
        refresh_token = jwt_manager.create_refresh_token(data)
        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )

    return {"access_token": access_token, "refresh_token": refresh_token}


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    request: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(request.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Token has expired.")

    result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == request.refresh_token
        )
    )
    db_token = result.scalar_one_or_none()
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    result = await db.execute(
        select(UserModel).where(UserModel.id == payload["user_id"])
    )
    db_user = result.scalar_one_or_none()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(
        {"sub": db_user.email, "user_id": db_user.id}
    )
    return {"access_token": new_access_token}
