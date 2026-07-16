from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, BaseAppSettings, get_settings
from database import (
    get_db,
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError
from schemas import UserActivationRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema
from schemas.accounts import (
    UserRegistrationResponseSchema, UserRegistrationRequestSchema,
    PasswordResetCompleteRequestSchema, PasswordResetRequestSchema,
    TokenRefreshResponseSchema, TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/accounts/login/")
router = APIRouter()


def _is_expired(expires_at: datetime) -> bool:
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return now > expires_at


@router.post("/register/", status_code=status.HTTP_201_CREATED, response_model=UserRegistrationResponseSchema)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    try:
        check_email = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
        if check_email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )

        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=1
        )

        db.add(new_user)
        await db.flush()
        await db.refresh(new_user)

        activation_token = ActivationTokenModel(user=new_user)
        db.add(activation_token)

        await db.commit()
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
    user_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    token = await db.scalar(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == user_data.token)
        .options(joinedload(ActivationTokenModel.user))
    )

    if not token or token.user.email != user_data.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if _is_expired(token.expires_at):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if token.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token.user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def password_reset_request(
    user_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))

    if user and user.is_active:
        token = await db.scalar(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )

        if token:
            await db.delete(token)

        new_token = PasswordResetTokenModel(user=user)
        db.add(new_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
)
async def password_reset_complete(
    user_data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
    if not (user and user.is_active):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == user_data.token,
        )
    )

    if not token:
        stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
        result = await db.execute(stmt)
        tokens = result.scalars().all()

        for db_token in tokens:
            await db.delete(db_token)

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = token.expires_at
    now = datetime.now(timezone.utc)

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if now > expires_at:
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        user.password = user_data.password
        await db.delete(token)
        await db.commit()

        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    user_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))

        if not user or not user.verify_password(user_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password."
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated."
            )

        refresh_token_value = jwt_manager.create_refresh_token(
            {"user_id": user.id, "email": user.email}
        )
        access_token = jwt_manager.create_access_token(
            {"user_id": user.id, "email": user.email}
        )

        refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            token=refresh_token_value,
            days_valid=settings.LOGIN_TIME_DAYS,
        )

        db.add(refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            refresh_token=refresh_token.token,
            access_token=access_token,
            token_type="bearer",
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=status.HTTP_200_OK)
async def refresh_access_token(
    user_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(user_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token.")

    db_token = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == user_data.refresh_token)
    )
    if not db_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token payload.")

    user = await db.get(UserModel, int(user_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    new_access_token = jwt_manager.create_access_token(
        {"user_id": user.id, "email": user.email}
    )

    return TokenRefreshResponseSchema(access_token=new_access_token)
