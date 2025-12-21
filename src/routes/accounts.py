from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from datetime import datetime, timezone

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
    LoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenResponseSchema,
    RefreshTokenResponseSchema
)
from security.auth import get_jwt_auth_manager, JWTAuthManagerInterface
from core.config import get_settings, BaseAppSettings

from src.schemas.accounts import MessageResponseSchema

router = APIRouter(tags=["Accounts"])


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register(
        data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User already exists.")

    group_stmt = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    group_result = await db.execute(group_stmt)
    group = group_result.scalar_one()

    new_user = UserModel.create(
        email=data.email,
        raw_password=data.password,
        group_id=group.id
    )
    db.add(new_user)
    await db.flush()

    activation_token = ActivationTokenModel(user_id=new_user.id)
    db.add(activation_token)

    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post("/activate/")
async def activate(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = select(ActivationTokenModel).join(UserModel).where(
        UserModel.email == data.email,
        ActivationTokenModel.token == data.token
    )
    result = await db.execute(stmt)
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Token has expired.")

    user_stmt = select(UserModel).where(UserModel.email == data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one()

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return {"message": "Account activated successfully."}


@router.post("/password-reset/request/")
async def request_password_reset(
        data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
        )
        new_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(
    data: PasswordResetCompleteRequestSchema,  # Онови тут
    db: AsyncSession = Depends(get_db)
):
    stmt = select(PasswordResetTokenModel).join(UserModel).where(
        UserModel.email == data.email,
        PasswordResetTokenModel.token == data.token
    )
    result = await db.execute(stmt)
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    user_stmt = select(UserModel).where(UserModel.email == data.email)
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=TokenResponseSchema)
async def login(
        data: LoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    stmt = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        refresh_token = jwt_manager.create_refresh_token(data={"sub": str(user.id)})
        access_token = jwt_manager.create_access_token(data={"sub": str(user.id)})

        db_refresh_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh_token)
        await db.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post("/api/v1/accounts/refresh/", response_model=RefreshTokenResponseSchema)
async def refresh_access_token(
        data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired.")

    stmt = select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token)
    result = await db.execute(stmt)
    db_token = result.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = payload.get("sub")
    user_stmt = select(UserModel).where(UserModel.id == int(user_id))
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(data={"sub": str(user.id)})
    return {"access_token": new_access_token}
