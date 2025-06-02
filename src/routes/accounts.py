from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import JWTError
from sqlalchemy import select, delete, update
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
from exceptions import TokenExpiredError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    UserResetPasswordCompleteRequestSchema,
    UserLoginRequestSchema,
    RefreshAccessTokenRequest,
    UserBase,
)

from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from security.utils import generate_secure_token
from services.users import get_user_by_email

router = APIRouter()


@router.post("/register/", status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegistrationRequestSchema, db=Depends(get_db)
) -> UserRegistrationResponseSchema:
    user_exists = await get_user_by_email(db, cast(str, user_data.email))

    if user_exists:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    try:
        hashed_password = hash_password(user_data.password)
        user = UserModel(
            email=cast(str, user_data.email),
            _hashed_password=hashed_password,
            group=await db.scalar(
                select(UserGroupModel).where(
                    UserGroupModel.name == UserGroupEnum.USER
                )
            ),
        )
        db.add(user)
        await db.flush()

        activation_token_str = generate_secure_token()
        activation_token = ActivationTokenModel(
            user=user, token=activation_token_str
        )
        db.add(activation_token)

        await db.commit()

    except Exception:
        await db.rollback()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(id=user.id, email=user.email)


@router.post("/activate/")
async def activate(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user: UserModel = await db.scalar(
        select(UserModel).where(UserModel.email == activation_data.email)
    )

    if user.is_active:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == activation_data.token,
            ActivationTokenModel.expires_at > datetime.now(timezone.utc),
            ActivationTokenModel.user == user,
        )
    )

    if token:
        await db.execute(
            update(UserModel)
            .where(UserModel.id == user.id)
            .values(is_active=True)
        )

        await db.flush()

        await db.execute(
            delete(ActivationTokenModel).where(
                ActivationTokenModel.id == token.id
            )
        )

        await db.commit()

        return {"message": "User account activated successfully."}

    raise HTTPException(
        status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired activation token.",
    )


@router.post("/password-reset/request/")
async def reset_password_request(
    reset_password_request_data: UserBase,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(
        select(UserModel).where(
            UserModel.email == reset_password_request_data.email,
            UserModel.is_active == True,  # noqa: E712
        )
    )

    if user:
        password_reset_token_str = generate_secure_token()
        password_reset_token = PasswordResetTokenModel(
            token=password_reset_token_str,
            user=user,
        )

        db.add(password_reset_token)

        await db.commit()

    return {
        "message": (
            "If you are registered, "
            "you will receive an email with instructions."
        )
    }


@router.post("/reset-password/complete/")
async def reset_password(
    reset_password_data: UserResetPasswordCompleteRequestSchema,
    db=Depends(get_db),
):
    try:
        user = await get_user_by_email(db, str(reset_password_data.email))

        password_reset_token: PasswordResetTokenModel = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user == user,
                PasswordResetTokenModel.token == reset_password_data.token,
            )
        )

        if password_reset_token and cast(
            datetime, password_reset_token.expires_at
        ).replace(tzinfo=timezone.utc) >= datetime.now(timezone.utc):
            hashed_password = hash_password(reset_password_data.password)

            await db.execute(
                update(UserModel)
                .where(UserModel.id == user.id)
                .values(_hashed_password=hashed_password)
            )

            await db.flush()

            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.id == password_reset_token.id
                )
            )

            await db.commit()

            return {"message": "Password reset successfully."}

        else:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user == user
                )
            )

            await db.commit()

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    raise HTTPException(
        status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token.",
    )


@router.post("/login/", status_code=status.HTTP_201_CREATED)
async def login(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        user: UserModel = await get_user_by_email(db, user_data.email)

        if not user:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.verify_password(user_data.password):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        refresh_token_str = jwt_manager.create_refresh_token(
            {"user_id": user.id}
        )

        refresh_token = RefreshTokenModel.create(
            user.id,
            token=refresh_token_str,
            days_valid=settings.LOGIN_TIME_DAYS,
        )
        db.add(refresh_token)
        await db.commit()

        access_token = jwt_manager.create_access_token({"user_id": user.id})

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_str,
            "token_type": "bearer",
        }
    except SQLAlchemyError:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/refresh/")
async def refresh_access_token(
    refresh_access_token_data: RefreshAccessTokenRequest,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded = jwt_manager.decode_refresh_token(
            refresh_access_token_data.refresh_token
        )
    except (TokenExpiredError, JWTError):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == refresh_access_token_data.refresh_token,
            RefreshTokenModel.expires_at >= datetime.now(timezone.utc),
        )
    )

    if not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user = await db.scalar(
        select(UserModel).where(UserModel.id == decoded["user_id"])
    )

    if not user or token.user_id != user.id:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    return {
        "access_token": jwt_manager.create_access_token({"user_id": user.id})
    }
