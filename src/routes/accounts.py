from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_current_user, get_jwt_auth_manager, get_settings
from database import get_db
from database.models.accounts import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
)
from schemas.accounts import (
    PasswordResetCompleteRequestSchema,
    PasswordResetCompleteResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetResponseSchema,
    TokenRefreshRequestSchema,
    TokenResponseSchema,
    UserActivationRequestSchema,
    UserActivationResponseSchema,
    UserLoginRequestSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)

try:
    from exceptions.security import TokenExpiredError
except ImportError:
    try:
        from security.exceptions import TokenExpiredError
    except ImportError:
        class TokenExpiredError(Exception):
            pass

router = APIRouter()


def _get_refresh_token_days(settings) -> int:
    return (
        getattr(settings, "REFRESH_TOKEN_EXPIRES_DAYS", None)
        or getattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", None)
        or getattr(settings, "JWT_REFRESH_TOKEN_EXPIRE_DAYS", None)
        or getattr(settings, "REFRESH_TOKEN_EXPIRATION_DAYS", 7)
    )


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        query = select(UserModel).where(UserModel.email == user_data.email)
        result = await db.execute(query)
        if result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        group_query = select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
        group_result = await db.execute(group_query)
        user_group = group_result.scalar_one_or_none()

        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Default user group not found.",
            )

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        return new_user

    except HTTPException:
        await db.rollback()
        raise
    except ValueError as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post(
    "/activate/",
    response_model=UserActivationResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_account(
    data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    token_query = select(ActivationTokenModel).where(
        ActivationTokenModel.user_id == user.id,
        ActivationTokenModel.token == data.token,
    )
    token_result = await db.execute(token_query)
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=PasswordResetResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    success_response = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        return success_response

    existing_token_query = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    )
    existing_result = await db.execute(existing_token_query)
    existing_token = existing_result.scalar_one_or_none()

    if existing_token:
        await db.delete(existing_token)
        await db.flush()

    new_token = PasswordResetTokenModel(user_id=user.id)
    db.add(new_token)
    await db.commit()

    return success_response


@router.post(
    "/reset-password/complete/",
    response_model=PasswordResetCompleteResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    token_query = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id,
        PasswordResetTokenModel.token == data.token,
    )
    token_result = await db.execute(token_query)
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        delete_stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        existing_tokens = await db.execute(delete_stmt)
        for tok in existing_tokens.scalars().all():
            await db.delete(tok)
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
        return {"message": "Password reset successfully."}
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=TokenResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_auth_manager=Depends(get_jwt_auth_manager),
    settings=Depends(get_settings),
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    try:
        access_token = jwt_auth_manager.create_access_token(
            data={"sub": str(user.id), "user_id": user.id, "email": user.email}
        )
        refresh_token = jwt_auth_manager.create_refresh_token(
            data={"sub": str(user.id), "user_id": user.id}
        )

        days_valid = _get_refresh_token_days(settings)
        db_refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=days_valid,
            token=refresh_token,
        )
        db.add(db_refresh_token)
        await db.commit()
    except HTTPException:
        await db.rollback()
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return TokenResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )


@router.post(
    "/refresh/",
    response_model=TokenResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh_tokens(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_auth_manager=Depends(get_jwt_auth_manager),
    settings=Depends(get_settings),
):
    try:
        payload = jwt_auth_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    raw_user_id = payload.get("sub") or payload.get("user_id")
    if raw_user_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )
    user_id = int(raw_user_id)

    token_query = select(RefreshTokenModel).where(
        RefreshTokenModel.token == data.refresh_token,
        RefreshTokenModel.user_id == user_id,
    )
    token_result = await db.execute(token_query)
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired.",
        )

    user_query = select(UserModel).where(UserModel.id == user_id)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    await db.delete(token_record)
    await db.flush()

    new_access_token = jwt_auth_manager.create_access_token(
        data={"sub": str(user_id), "user_id": user_id, "email": user.email}
    )
    new_refresh_token = jwt_auth_manager.create_refresh_token(
        data={"sub": str(user_id), "user_id": user_id}
    )

    days_valid = _get_refresh_token_days(settings)
    new_db_refresh_token = RefreshTokenModel.create(
        user_id=user_id,
        days_valid=days_valid,
        token=new_refresh_token,
    )
    db.add(new_db_refresh_token)
    await db.commit()

    return TokenResponseSchema(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )


@router.get(
    "/me/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def get_me(current_user: UserModel = Depends(get_current_user)):
    return current_user
