from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime, timezone

from config.dependencies import get_db, get_jwt_auth_manager, get_settings
from database.models.accounts import (
    UserModel, ActivationTokenModel, PasswordResetTokenModel,
    RefreshTokenModel, UserGroupEnum
)
from schemas.accounts import (
    UserRegistrationRequestSchema, UserRegistrationResponseSchema,
    UserActivationRequestSchema, PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema, UserLoginRequestSchema,
    TokensResponseSchema, RefreshTokenRequestSchema,
    AccessTokenResponseSchema, MessageResponseSchema
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter(prefix="/api/v1/accounts", tags=["Accounts"])


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register_user(payload: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).filter_by(email=payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"A user with this email {payload.email} already exists.")

    try:
        user = UserModel.create(email=payload.email, raw_password=payload.password, group_id=UserGroupEnum.USER.value)
        db.add(user)
        await db.flush()
        token = ActivationTokenModel(user_id=user.id)
        db.add(token)
        await db.commit()
        return UserRegistrationResponseSchema(id=user.id, email=user.email)
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(payload: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).filter_by(email=payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    result = await db.execute(select(ActivationTokenModel).filter_by(user_id=user.id, token=payload.token))
    token = result.scalar_one_or_none()
    if not token or token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(payload: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).filter_by(email=payload.email, is_active=True))
    user = result.scalar_one_or_none()
    if user:
        await db.execute(
            PasswordResetTokenModel.__table__.delete().where(PasswordResetTokenModel.user_id == user.id)
        )
        token = PasswordResetTokenModel(user_id=user.id)
        db.add(token)
        await db.commit()
    return MessageResponseSchema(message="If you are registered, you will receive an email with instructions.")


@router.post("/password-reset/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(payload: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).filter_by(email=payload.email, is_active=True))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result = await db.execute(select(PasswordResetTokenModel).filter_by(user_id=user.id, token=payload.token))
    token = result.scalar_one_or_none()
    if not token or token.expires_at < datetime.now(timezone.utc):
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = payload.password
        await db.delete(token)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=TokensResponseSchema, status_code=201)
async def login(payload: UserLoginRequestSchema,
                db: AsyncSession = Depends(get_db),
                jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
                settings = Depends(get_settings)):
    result = await db.execute(select(UserModel).filter_by(email=payload.email))
    user = result.scalar_one_or_none()
    if not user or not user.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        access_token = jwt_manager.create_access_token({"sub": str(user.id)})
        refresh_token = jwt_manager.create_refresh_token({"sub": str(user.id)})

        token_record = RefreshTokenModel.create(user_id=user.id, token=refresh_token, days_valid=settings.LOGIN_TIME_DAYS)
        db.add(token_record)
        await db.commit()

        return TokensResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token
        )
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=AccessTokenResponseSchema)
async def refresh_access_token(payload: RefreshTokenRequestSchema,
                               db: AsyncSession = Depends(get_db),
                               jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    try:
        payload_data = jwt_manager.decode_refresh_token(payload.refresh_token)
        user_id = int(payload_data.get("sub"))
    except Exception:
        raise HTTPException(status_code=400, detail="Token has expired or is invalid.")

    result = await db.execute(select(RefreshTokenModel).filter_by(token=payload.refresh_token))
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    result = await db.execute(select(UserModel).filter_by(id=user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"sub": str(user.id)})
    return AccessTokenResponseSchema(access_token=access_token)
