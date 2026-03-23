import secrets
from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.exc import SQLAlchemyError

from database import get_db
from config import get_jwt_auth_manager, get_settings
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password

from database.models.accounts import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    ActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    LoginRequestSchema,
    LoginResponseSchema,
    RefreshTokenRequestSchema,
    TokenResponseSchema,
)

router = APIRouter(tags=["Accounts"])


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == user_data.email)
        )
        existing_user = result.scalars().first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists.",
            )

        group_result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == "USER")
        )
        user_group = group_result.scalars().first()
        group_id = user_group.id if user_group else 1

        new_user = UserModel(
            email=user_data.email,
            _hashed_password=hash_password(user_data.password),
            is_active=False,
            group_id=group_id,
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(
            token=secrets.token_urlsafe(32), user_id=cast(int, new_user.id)
        )
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        return new_user

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_account(
    activation_data: ActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ActivationTokenModel)
        .join(UserModel)
        .where(
            ActivationTokenModel.token == activation_data.token,
            UserModel.email == activation_data.email,
        )
    )
    token_record = result.scalars().first()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    user = await db.get(UserModel, token_record.user_id)
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
    reset_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    success_message = {
        "message": "If you are registered, you will receive an email with instructions."
    }

    result = await db.execute(
        select(UserModel).where(UserModel.email == reset_data.email)
    )
    user = result.scalars().first()

    if user and user.is_active:
        old_tokens = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        for token in old_tokens.scalars().all():
            await db.delete(token)

        new_token = PasswordResetTokenModel(
            token=secrets.token_urlsafe(32), user_id=cast(int, user.id)
        )
        db.add(new_token)
        await db.commit()

    return success_message


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def complete_password_reset(
    reset_data: PasswordResetCompleteSchema, db: AsyncSession = Depends(get_db)
):
    try:
        user_result = await db.execute(
            select(UserModel).where(UserModel.email == reset_data.email)
        )
        user = user_result.scalars().first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        token_result = await db.execute(
            select(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        token_record = token_result.scalars().first()

        if not token_record:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        is_invalid_token = token_record.token != reset_data.token
        expires_at = cast(datetime, token_record.expires_at).replace(
            tzinfo=timezone.utc
        )
        is_expired = datetime.now(timezone.utc) > expires_at

        if is_invalid_token or is_expired:
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user._hashed_password = hash_password(reset_data.password)
        await db.delete(token_record)
        await db.commit()

        return {"message": "Password reset successfully."}

    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/", response_model=LoginResponseSchema, status_code=status.HTTP_201_CREATED
)
async def login(
    login_data: LoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        result = await db.execute(
            select(UserModel).where(UserModel.email == login_data.email)
        )
        user = result.scalars().first()

        if not user or not verify_password(login_data.password, user._hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )

        access_token = jwt_manager.create_access_token({"sub": str(user.id)})
        refresh_token_value = jwt_manager.create_refresh_token({"sub": str(user.id)})

        db_refresh_token = RefreshTokenModel(
            token=refresh_token_value, user_id=cast(int, user.id)
        )
        db.add(db_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_value,
            "token_type": "bearer",
        }
    except HTTPException:
        raise
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post(
    "/refresh/", response_model=TokenResponseSchema, status_code=status.HTTP_200_OK
)
async def refresh_token(
    token_data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = int(payload.get("sub"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
    )
    db_token = result.scalars().first()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user = await db.get(UserModel, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )

    new_access_token = jwt_manager.create_access_token({"sub": str(user.id)})
    return {"access_token": new_access_token}
