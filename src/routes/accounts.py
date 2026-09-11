from datetime import datetime, timezone

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
    UserCreate,
    UserRead,
    AccountActivation,
    UserBase,
    ResetPassword,
    Token,
    UserLogin,
    RefreshToken,
    AccessToken,
)

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    if await db.scalar(select(UserModel).where(UserModel.email == user.email)):
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )

    user_group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )

    if user_group is None:
        raise HTTPException(
            status_code=500,
            detail="Default user group not found.",
        )

    try:
        new_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

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


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
    account: AccountActivation,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == account.email))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    activation_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == account.token,
        )
    )

    if activation_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    expires_at = activation_token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        user.is_active = True
        await db.delete(activation_token)
        await db.commit()

    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during account activation.",
        ) from error

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    user_data: UserBase,
    db: AsyncSession = Depends(get_db),
):
    response = {
        "message": (
            "If you are registered, you will receive " "an email with instructions."
        )
    }

    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )

        if user is None or not user.is_active:
            return response

        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )

        new_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_token)

        await db.commit()

    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while requesting a password reset.",
        ) from error

    return response


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password_complete(
    reset_pass: ResetPassword, db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(select(UserModel).where(UserModel.email == reset_pass.email))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    if token.token != reset_pass.token:
        await db.delete(token)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = token.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        if reset_pass.password:
            user.password = reset_pass.password
            await db.delete(token)
            await db.commit()
            await db.refresh(user)
            return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=Token,
    status_code=status.HTTP_200_OK,
)
async def login(
    user_data: UserLogin,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))

    if user is None or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    refresh_token_record = RefreshTokenModel.create(
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=refresh_token,
    )

    try:
        db.add(refresh_token_record)
        await db.commit()

    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        ) from error

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    response_model=AccessToken,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    token_data: RefreshToken,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    # Сначала проверяем подпись и срок действия JWT
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        ) from error

    user_id = payload.get("user_id")

    stored_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
    )

    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    # JWT должен принадлежать тому же пользователю,
    # что и запись в базе
    if stored_token.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})

    return {"access_token": access_token}
