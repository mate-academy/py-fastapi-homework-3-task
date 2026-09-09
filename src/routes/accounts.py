from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import (
    BaseAppSettings,
    get_jwt_auth_manager,
    get_settings,
)
from database import (
    ActivationTokenModel,
    UserGroupEnum,
    get_db,
)
from exceptions import InvalidTokenError, TokenExpiredError
from schemas.accounts import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from services.crud import (
    activate_user,
    create_password_reset_token,
    create_refresh_token,
    create_user,
    delete_activation_token,
    delete_password_reset_token,
    delete_password_reset_tokens,
    get_activation_token,
    get_group_by_name,
    get_password_reset_token_by_user_id,
    get_refresh_token,
    get_user_by_email,
    get_user_by_email_and_password,
    get_user_by_id,
)


router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> UserRegistrationResponseSchema:
    try:
        db_user = await get_user_by_email(
            db=db,
            email=str(user_data.email),
        )

        if db_user is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"A user with this email "
                    f"{user_data.email} already exists."
                ),
            )

        user_group = await get_group_by_name(
            db=db,
            name=UserGroupEnum.USER,
        )

        if user_group is None:
            raise RuntimeError("Default user group does not exist.")

        db_user = await create_user(
            db=db,
            user_data=user_data,
            group_id=cast(int, user_group.id),
        )

        await db.flush()

        activation_token = ActivationTokenModel(
            user_id=cast(int, db_user.id),
        )
        db.add(activation_token)

        await db.commit()
        await db.refresh(db_user)

        return db_user

    except HTTPException:
        raise

    except IntegrityError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A user with this email "
                f"{user_data.email} already exists."
            ),
        )

    except SQLAlchemyError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    except Exception:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


def raise_invalid_activation_token() -> HTTPException:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired activation token.",
    )


@router.post(
    "/activate/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema
)
async def account_activation(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    token_record = await get_activation_token(
        db=db,
        token=activation_data.token,
    )

    if token_record is None:
        raise_invalid_activation_token()

    expires_at = cast(datetime, token_record.expires_at).replace(
        tzinfo=timezone.utc,
    )

    if expires_at <= datetime.now(timezone.utc):
        raise_invalid_activation_token()

    user = await get_user_by_email(
        db=db,
        email=str(activation_data.email),
    )

    if user is None or user.id != token_record.user_id:
        raise_invalid_activation_token()

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    try:
        activate_user(user)
        await delete_activation_token(db=db, token=token_record)
        await db.commit()

    except Exception:
        await db.rollback()
        raise

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema
)
async def request_password_reset(
    user_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    response = (
        "If you are registered, you will "
        "receive an email with instructions."
    )

    try:
        user = await get_user_by_email(
            db=db,
            email=str(user_data.email),
        )

        if user is None or not user.is_active:
            return MessageResponseSchema(message=response)

        await delete_password_reset_tokens(
            db=db,
            user_id=cast(int, user.id),
        )

        token = create_password_reset_token(
            db=db,
            user=user,
        )

        await db.commit()
        await db.refresh(token)

        return MessageResponseSchema(message=response)

    except SQLAlchemyError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while requesting password reset.",
        )


def invalid_email_or_token_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token.",
    )


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
    response_model=MessageResponseSchema,
)
async def complete_reset_password(
    reset_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    try:
        user = await get_user_by_email(
            db=db,
            email=str(reset_data.email),
        )

        if user is None or not user.is_active:
            raise invalid_email_or_token_error()

        token_record = await get_password_reset_token_by_user_id(
            db=db,
            user_id=cast(int, user.id),
        )

        if token_record is None:
            raise invalid_email_or_token_error()

        expires_at = cast(
            datetime,
            token_record.expires_at,
        ).replace(tzinfo=timezone.utc)

        token_is_invalid = token_record.token != reset_data.token
        token_is_expired = (
            expires_at <= datetime.now(timezone.utc)
        )

        if token_is_invalid or token_is_expired:
            await delete_password_reset_token(
                db=db,
                token=token_record,
            )
            await db.commit()

            raise invalid_email_or_token_error()

        user.password = reset_data.password

        await delete_password_reset_token(
            db=db,
            token=token_record,
        )

        await db.commit()

    except HTTPException:
        raise

    except SQLAlchemyError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "An error occurred while resetting "
                "the password."
            ),
        )

    except Exception:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "An error occurred while resetting "
                "the password."
            ),
        )

    return MessageResponseSchema(
        message="Password reset successfully.",
    )


def invalid_db_operations_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An error occurred while processing the request.",
    )


@router.post(
    "/login/",
    status_code=status.HTTP_200_OK,
    response_model=UserLoginResponseSchema,
)
async def login(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(
        get_jwt_auth_manager
    ),
) -> UserLoginResponseSchema:
    try:
        user = await get_user_by_email_and_password(
            db=db,
            email=str(login_data.email),
            password=login_data.password,
        )

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        payload = {
            "user_id": cast(int, user.id),
        }

        access_token = jwt_manager.create_access_token(
            data=payload,
        )

        refresh_token = jwt_manager.create_refresh_token(
            data=payload,
        )

        create_refresh_token(
            db=db,
            user_id=cast(int, user.id),
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )

        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
        )

    except HTTPException:
        raise

    except SQLAlchemyError:
        await db.rollback()
        raise invalid_db_operations_error()

    except Exception:
        await db.rollback()
        raise invalid_db_operations_error()


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(
        get_jwt_auth_manager
    ),
    db: AsyncSession = Depends(get_db),
) -> TokenRefreshResponseSchema:
    try:
        refresh_token = token_data.refresh_token

        refresh_token_data = jwt_manager.decode_refresh_token(
            token=refresh_token,
        )

        db_token = await get_refresh_token(
            db=db,
            refresh_token=refresh_token,
        )

        if db_token is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )

        user_id = refresh_token_data.get("user_id")

        try:
            user_id = int(user_id)
        except (TypeError, ValueError):
            raise InvalidTokenError

        user = await get_user_by_id(
            db=db,
            user_id=user_id,
        )

        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )

        if db_token.user_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )

        access_token = jwt_manager.create_access_token(
            data={"user_id": cast(int, user.id)},
        )

        return TokenRefreshResponseSchema(
            access_token=access_token,
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

    except HTTPException:
        raise

    except SQLAlchemyError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    except Exception:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
