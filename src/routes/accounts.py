from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
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
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    AccountRead,
    UserRegistrationRequestSchema,
    TokenCheck,
    AccountBase,
    ResetPassword,
    AccountLogin,
    Token,
    RefreshToken
)
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()


async def create_account(
        db: AsyncSession,
        data: UserRegistrationRequestSchema
):
    result = await db.execute(
        select(UserGroupModel)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group = result.scalar_one()

    user = UserModel.create(
        email=data.email,
        raw_password=data.password,
        group_id=group.id
    )
    db.add(user)
    await db.flush()
    activation_token = ActivationTokenModel(
        user_id=user.id
    )
    db.add(activation_token)

    return user


async def get_user_by_email(email: str, db: AsyncSession):
    result = await db.execute(
        select(UserModel)
        .where(UserModel.email == email))
    return result.scalar_one_or_none()


@router.post(
    "/register/",
    response_model=AccountRead,
    status_code=status.HTTP_201_CREATED,
)
async def register(
        data: UserRegistrationRequestSchema
        , db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(email=data.email, db=db)

    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )
    try:
        user_create = await create_account(db=db, data=data)
        await db.commit()

        return user_create

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def activate_user(
        data: TokenCheck,
        db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(email=data.email, db=db)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    result = await db.execute(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == user.id)
    )
    active_token = result.scalar_one_or_none()

    if active_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(
        datetime,
        active_token.expires_at,
    ).replace(tzinfo=timezone.utc)

    if (
        active_token.token != data.token
        or expires_at < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(active_token)
    await db.commit()
    return {
        "message": "User account activated successfully."
    }


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK
)
async def reset_password(
    data: AccountBase,
    db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(email=data.email, db=db)

    if user is None or not user.is_active:
        return {
            "message":
                "If you are registered,"
                " you will receive an email with instructions."
        }

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    previous_reset_password = result.scalar_one_or_none()

    if previous_reset_password is not None:
        await db.delete(previous_reset_password)

    new_reset_password = PasswordResetTokenModel(
        user_id=user.id
    )

    db.add(new_reset_password)
    await db.commit()

    return {
        "message": "If you are registered,"
                   " you will receive an email with instructions."
    }


@router.post("/reset-password/complete/")
async def reset_password_complete(
        data: ResetPassword,
        db: AsyncSession = Depends(get_db)
):
    result_password = await db.execute(
        select(PasswordResetTokenModel).
        where(PasswordResetTokenModel.token == data.token)
    )

    reset_token = result_password.scalar_one_or_none()
    if reset_token is None:
        user = await get_user_by_email(
            email=data.email,
            db=db,
        )

        if user is not None:
            result = await db.execute(
                select(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )

            existing_token = result.scalar_one_or_none()

            if existing_token is not None:
                await db.delete(existing_token)
                await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )
    expires_at = cast(
        datetime,
        reset_token.expires_at,
    ).replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    user = await get_user_by_email(email=data.email, db=db)
    if user is None:
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    if reset_token.user_id != user.id or not user.is_active:
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )
    try:
        user.password = data.password
        await db.delete(reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )
    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=Token,
    status_code=status.HTTP_201_CREATED
)
async def login(
    data: AccountLogin,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await get_user_by_email(email=data.email, db=db)
    if user is None or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."

        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": user.id},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
    )
    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id}
    )
    refresh_token_record = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
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


@router.post(
    "/refresh/",
    status_code=status.HTTP_200_OK
)
async def update_access_token(
        refresh_token: RefreshToken,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        decoded_token = jwt_manager.decode_refresh_token(
            refresh_token.refresh_token
        )

    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token.",
        )
    result = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == refresh_token.refresh_token)
    )
    token = result.scalar_one_or_none()
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )
    user_id = decoded_token.get("user_id")
    user = await db.get(UserModel, user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if token.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id}
    )

    return {
        "access_token": access_token
    }
