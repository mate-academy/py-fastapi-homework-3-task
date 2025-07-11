from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, BaseAppSettings, get_settings
from database import (
    get_db,
    ActivationTokenModel,
    UserModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from database.crud import create_user, get_user_by_email
from exceptions import TokenExpiredError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.token_manager import JWTAuthManager

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=201,
)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    try:
        db_user = await get_user_by_email(db, user.email)
        if db_user:
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {db_user.email} already exists.",
            )
        return await create_user(db, user)
    except ValueError as msg:
        raise HTTPException(
            status_code=422,
            detail=str(msg),
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
)
async def activate(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    db_user = await get_user_by_email(db, data.email)

    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == db_user.id)
    )

    if (
        not token
        or token.token != data.token
        or datetime.now(timezone.utc) > token.expires_at.replace(tzinfo=timezone.utc)
    ):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    db_user.is_active = True
    await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
)
async def password_reset_request(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    db_user = await get_user_by_email(db, data.email)
    if db_user and db_user.is_active:
        existing_token_stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
        existing_token_result = await db.execute(existing_token_stmt)
        existing_token = existing_token_result.scalar_one_or_none()
        if existing_token:
            await db.delete(existing_token)
            await db.commit()
        new_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(new_token)
        await db.commit()
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
)
async def password_reset_complete(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    try:
        db_user = await get_user_by_email(db, data.email)

        if not db_user:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        token_stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        )
        token_result = await db.execute(token_stmt)
        token = token_result.scalar_one_or_none()
        await db.delete(token)

        if (
            not token
            or token.token != data.token
            or datetime.now(timezone.utc)
            > token.expires_at.replace(tzinfo=timezone.utc)
        ):
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        db_user.password = data.password
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=201,
)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> UserLoginResponseSchema:
    try:
        db_user = await get_user_by_email(db, data.email)

        if not db_user or not db_user.verify_password(data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        if not db_user.is_active:
            raise HTTPException(
                status_code=403, detail="User account is not activated."
            )

        token_data = {"user_id": db_user.id}

        access_token = jwt_manager.create_access_token(token_data)
        refresh_token = jwt_manager.create_refresh_token(token_data)

        refresh_token_to_save = RefreshTokenModel.create(
            db_user.id, settings.LOGIN_TIME_DAYS, refresh_token
        )
        db.add(refresh_token_to_save)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token, refresh_token=refresh_token
        )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
)
async def refresh(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_auth_manager),
) -> TokenRefreshResponseSchema:
    try:
        token_data = jwt_manager.decode_refresh_token(data.refresh_token)

        db_token_stmt = select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token
        )
        db_token_result = await db.execute(db_token_stmt)
        db_token = db_token_result.scalar_one_or_none()

        if not db_token:
            raise HTTPException(
                status_code=401,
                detail="Refresh token not found.",
            )

        db_user_stmt = (
            select(UserModel)
            .options(joinedload(UserModel.refresh_tokens))
            .where(UserModel.id == token_data["user_id"])
        )
        db_user_result = await db.execute(db_user_stmt)
        db_user = db_user_result.unique().scalar_one_or_none()

        if not db_user:
            raise HTTPException(status_code=404, detail="User not found.")

        access_token = jwt_manager.create_access_token({"user_id": db_user.id})
        return TokenRefreshResponseSchema(access_token=access_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
