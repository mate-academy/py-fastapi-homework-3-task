from datetime import datetime, timezone, timedelta
from uuid import uuid4

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetSchema,
    MessageResponseSchema,
    UserLoginRequestSchema,
    RefreshTokenRequestSchema,
)

from jose import JWTError, ExpiredSignatureError
from exceptions import TokenExpiredError, InvalidTokenError

router = APIRouter()


@router.get("/ping")
async def ping():
    return {"message": "pong"}


# ---------------- Registration ----------------
@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    existing_stmt = select(UserModel).where(UserModel.email == user_data.email)
    existing_result = await db.execute(existing_stmt)
    existing_user = existing_result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=1,
    )
    db.add(user)
    await db.flush()

    token = ActivationTokenModel(
        user_id=user.id,
        token=str(uuid4()),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db.add(token)
    try:
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    await db.refresh(user)

    return UserRegistrationResponseSchema(id=user.id, email=user.email)


# ---------------- Activation ----------------
@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def activate_user(
    activation_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(ActivationTokenModel)
        .where(ActivationTokenModel.token == activation_data.token)
        .options(joinedload(ActivationTokenModel.user))
    )
    result = await db.execute(stmt)
    token_model = result.scalars().first()

    if not token_model or token_model.user.email != activation_data.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    expires_at = token_model.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_model)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    user = token_model.user
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    user.is_active = True
    await db.delete(token_model)
    await db.commit()
    await db.refresh(user)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "User account activated successfully."},
    )


# ---------------- Login ----------------
@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    stmt = select(UserModel).where(UserModel.email == login_data.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    try:
        access_token = jwt_manager.create_access_token({"user_id": user.id})
        refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

        token_record = RefreshTokenModel.create(
            user_id=user.id, days_valid=7, token=refresh_token
        )
        db.add(token_record)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"access_token": access_token, "refresh_token": refresh_token},
    )


# ---------------- Refresh ----------------
@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(
    refresh_data: RefreshTokenRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    # Ищем токен в базе
    stmt = select(RefreshTokenModel).where(
        RefreshTokenModel.token == refresh_data.refresh_token
    )
    result = await db.execute(stmt)
    token_model = result.scalars().first()

    if not token_model:
        try:
            jwt_manager.decode_refresh_token(refresh_data.refresh_token)
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Token has expired."
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found."
            )

        # если JWT валиден, но в БД нет
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )


    # Проверяем срок действия токена в базе
    expires_at = token_model.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_model)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    # Проверяем пользователя
    stmt_user = select(UserModel).where(UserModel.id == token_model.user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    # Генерация новых токенов
    access_token = jwt_manager.create_access_token({"user_id": user.id})
    new_refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    token_model.token = new_refresh_token
    token_model.expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    try:
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"access_token": access_token, "refresh_token": new_refresh_token},
    )


# ---------------- Password Reset ----------------
@router.post(
    "/password-reset/request/",
    status_code=status.HTTP_200_OK,
)
async def request_password_reset_token(
    request_data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    stmt = (
        select(UserModel)
        .where(UserModel.email == request_data.email)
        .options(joinedload(UserModel.password_reset_token))
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    generic_response = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "message": "If you are registered, you will receive an email with instructions."
        },
    )

    if not user or not user.is_active:
        return generic_response

    if user.password_reset_token:
        await db.delete(user.password_reset_token)

    token = PasswordResetTokenModel(
        user_id=user.id,
        token=str(uuid4()),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.add(token)

    try:
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate password reset token.",
        )

    return generic_response


@router.post(
    "/reset-password/complete/",
    status_code=status.HTTP_200_OK,
)
async def reset_password(
    reset_data: PasswordResetSchema, db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(UserModel)
        .where(UserModel.email == reset_data.email)
        .options(joinedload(UserModel.password_reset_token))
    )
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    token_model = user.password_reset_token
    if not token_model or token_model.token != reset_data.token:
        if token_model:
            await db.delete(token_model)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    expires_at = token_model.expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        await db.delete(token_model)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    user.hashed_password = hash_password(reset_data.password)
    await db.delete(token_model)

    try:
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Password reset successfully."},
    )
