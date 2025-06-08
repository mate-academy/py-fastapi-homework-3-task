from datetime import datetime, timedelta, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from security.token_manager import JWTAuthManager
from database.session_sqlite import settings
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationResponseSchema,
    MessageResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)


def get_jwt_manager() -> JWTAuthManager:
    """
    Returns an instance of JWTAuthManager, configured with settings.
    Handles potential differences in settings attribute names between dev and test.
    """
    algorithm = getattr(settings, "ALGORITHM", None)
    if algorithm is None:
        algorithm = getattr(settings, "JWT_SIGNING_ALGORITHM", "HS256")

    return JWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=algorithm,
    )


router = APIRouter(tags=["Accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_409_CONFLICT: {
            "model": MessageResponseSchema,
            "description": "Користувач з такою поштою вже існує.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": MessageResponseSchema,
            "description": "Помилка сервера.",
        },
    },
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    """
    Реєстрація нового користувача.

    Приймає email та пароль, створює нового користувача
    та генерує токен активації.
    """
    try:
        existing_user = await db.scalar(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        user_group = await db.scalar(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        if not user_group:
            user_group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(user_group)
            await db.flush()

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        new_user.is_active = False

        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return UserRegistrationResponseSchema(
            id=cast(int, new_user.id), email=new_user.email
        )

    except HTTPException:
        raise
    except IntegrityError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )
    except Exception as e:
        await db.rollback()
        print(f"Error during user registration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": MessageResponseSchema,
            "description": "Невірний або прострочений токен активації, або обліковий запис вже активовано.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": MessageResponseSchema,
            "description": "Користувача або токен активації не знайдено.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": MessageResponseSchema,
            "description": "Помилка сервера.",
        },
    },
)
async def activate_user_account(
    activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    """
    Активація облікового запису користувача.

    Приймає email та токен активації, перевіряє їх
    та активує обліковий запис користувача.
    """
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == activation_data.email)
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        if user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        activation_token = await db.scalar(
            select(ActivationTokenModel).where(
                ActivationTokenModel.user_id == user.id,
                ActivationTokenModel.token == activation_data.token,
            )
        )

        if not activation_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        current_utc_time = datetime.now(timezone.utc)
        expires_at_aware = activation_token.expires_at
        if expires_at_aware.tzinfo is None:
            expires_at_aware = expires_at_aware.replace(tzinfo=timezone.utc)

        if expires_at_aware < current_utc_time:
            await db.delete(activation_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user.is_active = True
        db.add(user)

        await db.delete(activation_token)

        await db.commit()
        await db.refresh(user)

        return MessageResponseSchema(message="User account activated successfully.")

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        print(f"Error during account activation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during account activation.",
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": MessageResponseSchema,
            "description": "Помилка сервера.",
        }
    },
)
async def request_password_reset(
    request_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    """
    Запит на скидання пароля.

    Приймає email користувача.
    З міркувань безпеки, завжди повертає успішний статус,
    навіть якщо email не знайдено або обліковий запис неактивний,
    щоб уникнути перебору email-ів.
    """
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == request_data.email)
        )

        if not user or not user.is_active:
            print(
                f"Password reset requested for non-existent or inactive email: {request_data.email}"
            )
            return MessageResponseSchema(
                message="If you are registered, you will receive an email with instructions."
            )

        existing_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        if existing_token:
            await db.delete(existing_token)
            await db.commit()

        new_reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_reset_token)
        await db.commit()
        await db.refresh(new_reset_token)

        print(
            f"Generated password reset token for {user.email}: {new_reset_token.token}"
        )

        return MessageResponseSchema(
            message="If you are registered, you will receive an email with instructions."
        )

    except Exception as e:
        await db.rollback()
        print(f"Error requesting password reset: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during password reset request.",
        )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": MessageResponseSchema,
            "description": "Невірний email або токен.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": MessageResponseSchema,
            "description": "Помилка сервера.",
        },
    },
)
async def complete_password_reset(
    reset_data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    """
    Завершує процес скидання пароля, встановлюючи новий пароль користувача.

    Приймає email, токен скидання пароля та новий пароль.
    Перевіряє токен, оновлює пароль користувача та видаляє токен.
    """
    try:
        user = await db.scalar(
            select(UserModel).where(UserModel.email == reset_data.email)
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        password_reset_token = await db.scalar(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id,
                PasswordResetTokenModel.token == reset_data.token,
            )
        )

        if not password_reset_token:
            existing_token_for_user = await db.scalar(
                select(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            if existing_token_for_user:
                await db.delete(existing_token_for_user)
                await db.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        current_utc_time = datetime.now(timezone.utc)
        expires_at_aware = password_reset_token.expires_at
        if expires_at_aware.tzinfo is None:
            expires_at_aware = expires_at_aware.replace(tzinfo=timezone.utc)

        if expires_at_aware < current_utc_time:
            await db.delete(password_reset_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.password = reset_data.password
        db.add(user)

        await db.delete(password_reset_token)

        await db.commit()
        await db.refresh(user)

        return MessageResponseSchema(message="Password reset successfully.")

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        print(f"Error completing password reset: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_401_UNAUTHORIZED: {
            "model": MessageResponseSchema,
            "description": "Невірні облікові дані або обліковий запис неактивний.",
        },  # Змінено
        status.HTTP_403_FORBIDDEN: {
            "model": MessageResponseSchema,
            "description": "Обліковий запис неактивний.",
        },  # Змінено
        status.HTTP_404_NOT_FOUND: {
            "model": MessageResponseSchema,
            "description": "Користувача не знайдено.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": MessageResponseSchema,
            "description": "Помилка сервера.",
        },
    },
)
async def user_login(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_manager),
):
    """
    **Аутентифікація користувача та видача JWT токенів.**

    Приймає **email** та **пароль**, перевіряє їх, і у випадку успіху
    повертає **токен доступу** (Access Token) та **токен оновлення** (Refresh Token).
    """
    try:
        user = await db.scalar(
            select(UserModel)
            .where(UserModel.email == login_data.email)
            .options(joinedload(UserModel.group))
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.verify_password(login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        access_token_expire_minutes = getattr(
            settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 15
        )
        refresh_token_expire_days = getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)

        access_token_expires_delta = timedelta(minutes=access_token_expire_minutes)
        refresh_token_expires_delta = timedelta(days=refresh_token_expire_days)

        access_token = jwt_manager.create_access_token(
            data={
                "sub": user.email,
                "user_id": user.id,
                "group": user.group.name.value,
            },
            expires_delta=access_token_expires_delta,
        )
        refresh_token_value = jwt_manager.create_refresh_token(
            data={"sub": user.email, "user_id": user.id},
            expires_delta=refresh_token_expires_delta,
        )

        new_refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=refresh_token_expire_days,
            token=refresh_token_value,
        )
        db.add(new_refresh_token_record)
        await db.commit()
        await db.refresh(new_refresh_token_record)

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token_value,
            token_type="bearer",
            expires_in=int(access_token_expires_delta.total_seconds()),
        )

    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        print(f"Помилка під час входу користувача: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_400_BAD_REQUEST: {
            "model": MessageResponseSchema,
            "description": "Недійсний або прострочений токен оновлення.",
        },
        status.HTTP_401_UNAUTHORIZED: {
            "model": MessageResponseSchema,
            "description": "Недійсний токен оновлення.",
        },
        status.HTTP_404_NOT_FOUND: {
            "model": MessageResponseSchema,
            "description": "Користувача не знайдено.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": MessageResponseSchema,
            "description": "Помилка сервера.",
        },
    },
)
async def refresh_tokens(
    refresh_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManager = Depends(get_jwt_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        user_id = payload.get("user_id")

        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token payload.",
            )

        db_refresh_token = await db.scalar(
            select(RefreshTokenModel).where(
                RefreshTokenModel.token == refresh_data.refresh_token
            )
        )

        if not db_refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )

        user = await db.scalar(
            select(UserModel)
            .where(UserModel.id == user_id)
            .options(joinedload(UserModel.group))
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not active.",
            )

        if db_refresh_token.user_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token.",
            )

        await db.delete(db_refresh_token)
        await db.commit()

        access_token_expire_minutes = getattr(
            settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 15
        )
        refresh_token_expire_days = getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", 7)

        access_token_expires_delta = timedelta(minutes=access_token_expire_minutes)
        refresh_token_expires_delta = timedelta(days=refresh_token_expire_days)

        new_access_token = jwt_manager.create_access_token(
            data={
                "sub": user.email,
                "user_id": user.id,
                "group": user.group.name.value,
            },
            expires_delta=access_token_expires_delta,
        )
        new_refresh_token_value = jwt_manager.create_refresh_token(
            data={"sub": user.email, "user_id": user.id},
            expires_delta=refresh_token_expires_delta,
        )

        new_refresh_token_record = RefreshTokenModel.create(
            user_id=cast(int, user.id),
            days_valid=refresh_token_expire_days,
            token=new_refresh_token_value,
        )
        db.add(new_refresh_token_record)
        await db.commit()
        await db.refresh(new_refresh_token_record)

        return TokenRefreshResponseSchema(
            access_token=new_access_token,
            refresh_token=new_refresh_token_value,
            token_type="bearer",
            expires_in=int(access_token_expires_delta.total_seconds()),
        )

    except TokenExpiredError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )
    except InvalidTokenError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token."
        )
    except HTTPException:
        await db.rollback()
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during token refresh.",
        )
