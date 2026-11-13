from datetime import datetime, timezone
from typing import cast
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager
from crud import create_user, get_user_by_email, create_reset_token
from database import (
    get_db,
    UserModel,
    ActivationTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    TokenRefreshResponseSchema,
    UserLoginRequestSchema
)
from schemas.accounts import (
    UserBase,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password, verify_password


router = APIRouter()


@router.post("/refresh/", response_model=TokenRefreshResponseSchema, status_code=200)
async def refresh_token(
        request: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        data = jwt_manager.decode_refresh_token(token=request.refresh_token)
    except TokenExpiredError:
        raise HTTPException(400, "Token has expired.")
    except InvalidTokenError:
        raise HTTPException(401, "Refresh token not found.")

    refresh_token_model_execute = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == request.refresh_token
        )
    )
    refresh_token_model = refresh_token_model_execute.scalar_one_or_none()

    if refresh_token_model is None:
        raise HTTPException(401, "Refresh token not found.")

    user_execute = await db.execute(select(UserModel).where(UserModel.id == data["user_id"]))
    user = user_execute.scalar_one_or_none()

    if user is None:
        raise HTTPException(404, "User not found.")

    new_access_token = jwt_manager.create_access_token(
        data={"user_id": user.id}
    )

    return {"access_token": f"{new_access_token}"}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login(
        request: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = await get_user_by_email(db=db, email=request.email)

    if not user or not verify_password(request.password, user._hashed_password):
        raise HTTPException(401, "Invalid email or password.")
    if not user.is_active:
        raise HTTPException(403, "User account is not activated.")

    user_id = user.id

    try:
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": user_id})
        refresh_token_model = RefreshTokenModel.create(user_id=cast(int, user_id), days_valid=7, token=refresh_token)
        db.add(refresh_token_model)
        await db.commit()
        await db.refresh(refresh_token_model)
    except (IntegrityError, SQLAlchemyError):
        await db.rollback()
        raise HTTPException(500, "An error occurred while processing the request.")

    access_token = jwt_manager.create_access_token(data={"user_id": user_id})

    return UserLoginResponseSchema(access_token=access_token, refresh_token=refresh_token, token_type="bearer")


@router.post("/reset-password/complete/", status_code=200)
async def password_reset_complete(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db=db, email=data.email)

    if user is None or not user.is_active:
        raise HTTPException(400, detail="Invalid email or token.")

    user_reset_password = user.password_reset_token

    if not user_reset_password:
        raise HTTPException(400, detail="Invalid email or token.")

    is_token = (user_reset_password.token == data.token)
    expires_at = user_reset_password.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if not is_token or expires_at < datetime.now(timezone.utc):
        await db.delete(user_reset_password)
        await db.commit()
        await db.refresh(user)
        raise HTTPException(400, detail="Invalid email or token.")

    try:
        hashed = hash_password(data.password)
        user._hashed_password = hashed
        await db.delete(user_reset_password)
        await db.commit()
        await db.refresh(user)
    except (IntegrityError, SQLAlchemyError):
        await db.rollback()
        raise HTTPException(500, detail="An error occurred while resetting the password.")

    return {"message": "Password reset successfully."}


@router.post("/password-reset/request/", status_code=200)
async def password_reset_request(data: UserBase, db: AsyncSession = Depends(get_db)):
    user = await get_user_by_email(db=db, email=data.email)
    if user and user.is_active:
        await create_reset_token(db=db, user=user)
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/activate/", status_code=200)
async def user_activation(
    request: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .join(UserModel)
        .where(
            UserModel.email == request.email,
            ActivationTokenModel.token == request.token,
        )
    )
    token = (await db.execute(stmt)).scalars().first()
    try:
        if token.user.is_active is True:
            raise HTTPException(400, "User account is already active.")
    except AttributeError:
        raise HTTPException(400, "Invalid or expired activation token.")

    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        await db.commit()
        raise HTTPException(400, "Invalid or expired activation token.")

    token.user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/register/",
    status_code=201,
    response_model=UserRegistrationResponseSchema,
)
async def user_registration(
        schema_in: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    old_user = await get_user_by_email(db=db, email=schema_in.email)
    if old_user is not None:
        raise HTTPException(409, f"A user with this email {schema_in.email} already exists.")
    try:
        new_user = await create_user(db, schema_in)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, f"A user with this email {schema_in.email} already exists.")
    except Exception:
        await db.rollback()
        raise HTTPException(500, "An error occurred during user creation.")
    return UserRegistrationResponseSchema.model_validate(new_user)
