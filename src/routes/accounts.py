from datetime import datetime
from exceptions import TokenExpiredError, InvalidTokenError
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
    RefreshTokenModel
)
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    AccessTokenResponseSchema,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema,
             status_code=status.HTTP_201_CREATED)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == user_data.email.lower()))
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists."
        )

    group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    if not group:
        group = UserGroupModel(name=UserGroupEnum.USER)
        db.add(group)
        await db.flush()

    try:
        user = UserModel.create(email=user_data.email,
                                raw_password=user_data.password, group_id=group.id)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        db.add(user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=user.id)
        db.add(activation_token)
        await db.commit()

        return UserRegistrationResponseSchema(id=user.id, email=user.email)

    except BaseSecurityError as e:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/")
async def activate_account(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == data.email.lower()))
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
    if not token or token.token != data.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if datetime.utcnow() > token.expires_at.replace(tzinfo=None):
        await db.delete(token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/")
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email.lower()))

    if user and user.is_active:
        await db.execute(delete(
            PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        db.add(PasswordResetTokenModel(user_id=user.id))
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/")
async def reset_password(
        data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email.lower()))
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token = await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
    if (
            not token or token.token != data.token or datetime.utcnow() > token.expires_at.replace(tzinfo=None)
    ):
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = data.password
        await db.delete(token)
        await db.commit()
        return {"message": "Password reset successfully."}
    except BaseSecurityError as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(e))
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema,
             status_code=status.HTTP_200_OK)
async def login_user(
        data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email.lower()))
    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id, "sub": user.email})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        refresh_entry = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_entry)
        await db.commit()

        return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=AccessTokenResponseSchema)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Token has expired.")

    token_entry = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    if not token_entry:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user.id, "sub": user.email})
    return {"access_token": new_access_token}
