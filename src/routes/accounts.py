from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

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
from exceptions import TokenExpiredError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    UserRegistrationResponseSchema,
    PasswordResetRequestSchema,
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


def as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    hashed = hash_password(user.password)
    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    default_group = result.scalar_one_or_none()
    db_user = UserModel(
        email=str(user.email), _hashed_password=hashed, group=default_group
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


async def get_user_by_email(db: AsyncSession, email: str):
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(db, str(user.email))
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
        )

    try:
        new_user = await create_user(db, user)
        activation_token = ActivationTokenModel(user=new_user)
        db.add(activation_token)
        await db.commit()

        return new_user
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(
    user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.activation_token))
        .where(UserModel.email == str(user.email))
    )
    db_user = result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email."
        )

    activation_token = db_user.activation_token
    if (
        not activation_token
        or activation_token.token != user.token
        or as_utc(activation_token.expires_at) < datetime.now(timezone.utc)
    ):
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
async def password_reset(
    user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == str(user.email))
    )
    db_user = result.scalar_one_or_none()

    if db_user and db_user.is_active:
        if db_user.password_reset_token is not None:
            await db.delete(db_user.password_reset_token)
            await db.flush()

        new_token = PasswordResetTokenModel(user=db_user)
        db.add(new_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


def raise_invalid_email_or_token() -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(
    user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel)
        .options(selectinload(UserModel.password_reset_token))
        .where(UserModel.email == str(user.email))
    )
    db_user = result.scalar_one_or_none()

    if not db_user or not db_user.is_active or not db_user.password_reset_token:
        raise_invalid_email_or_token()

    reset_token = db_user.password_reset_token

    if (
        as_utc(reset_token.expires_at) < datetime.now(timezone.utc)
        or reset_token.token != user.token
    ):
        await db.delete(reset_token)
        await db.commit()
        raise_invalid_email_or_token()

    try:
        db_user.password = user.password
        await db.delete(db_user.password_reset_token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
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
async def login(
    user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    db_user = await get_user_by_email(db, str(user.email))

    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    user_access_token = jwt_manager.create_access_token({"user_id": db_user.id})
    user_refresh_token = jwt_manager.create_refresh_token({"user_id": db_user.id})

    try:
        refresh_token_record = RefreshTokenModel.create(
            user_id=db_user.id,
            token=user_refresh_token,
            days_valid=settings.LOGIN_TIME_DAYS,
        )
        db.add(refresh_token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return {
        "access_token": user_access_token,
        "refresh_token": user_refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):

    try:
        decoded_refresh_token = jwt_manager.decode_refresh_token(token.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    result = await db.execute(
        select(RefreshTokenModel)
        .options(selectinload(RefreshTokenModel.user))
        .where(RefreshTokenModel.token == token.refresh_token)
    )
    db_refresh_token = result.scalar_one_or_none()

    if not db_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    if decoded_refresh_token["user_id"] != db_refresh_token.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    db_user = db_refresh_token.user
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token({"user_id": db_user.id})
    return {
        "access_token": new_access_token,
    }
