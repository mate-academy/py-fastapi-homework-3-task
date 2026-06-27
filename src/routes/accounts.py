from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
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

router = APIRouter()


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel:
    return await db.scalar(select(UserModel).where(UserModel.email == email))


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
) -> UserModel:
    db_user = await get_user_by_email(db, user_data.email)

    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user_group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )

    db_user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=user_group.id,
    )
    db.add(db_user)
    await db.flush()

    activation_token = ActivationTokenModel(user_id=db_user.id)
    db.add(activation_token)

    try:
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation."
        )

    return db_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    token_record: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    db_user = await get_user_by_email(db, token_record.email)

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == token_record.token,
            ActivationTokenModel.user_id == db_user.id,
        )
    )

    if not db_user or not activation_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, activation_token.expires_at).replace(
        tzinfo=timezone.utc
    )

    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    db_user.is_active = True
    await db.delete(activation_token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def reset_password_token(
    request_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    db_user = await get_user_by_email(db, request_data.email)

    if db_user and db_user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
        )
        reset_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(reset_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def resert_password(
    data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    db_user = await get_user_by_email(db, data.email)

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    password_token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id,
        )
    )

    expires_at = cast(datetime, password_token.expires_at).replace(tzinfo=timezone.utc)

    if password_token.token != data.token or expires_at < datetime.now(timezone.utc):
        await db.delete(password_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    db_user.password = data.password

    try:
        await db.delete(password_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
) -> dict[str, str]:
    db_user = await get_user_by_email(db, login_data.email)

    if not db_user or not db_user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": db_user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=db_user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token
    )
    try:
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def access_token_refresh(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
) -> dict[str, str]:
    try:
        token_payload = jwt_manager.decode_refresh_token(  # noqa F841
            token_data.refresh_token
        )
    except BaseSecurityError as error:
        raise HTTPException(status_code=400, detail=str(error))

    refresh_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
    )

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user_id = jwt_manager.decode_refresh_token(token_data.refresh_token)["user_id"]
    db_user = await db.get(UserModel, user_id)

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    access_token = jwt_manager.create_access_token({"user_id": user_id})

    return {"access_token": access_token}
