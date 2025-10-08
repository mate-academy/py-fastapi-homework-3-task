import uuid
from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload
from jose.exceptions import JWTError
from exceptions.security import TokenExpiredError

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
from database.validators.accounts import validate_password_strength
from schemas import (
    MessageResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    UserActivationRequestSchema,
    UserRegistrationRequestSchema
)
from schemas.accounts import DetailResponseSchema, UserRegistrationResponseSchema, UserReadSchema, \
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, TokenRefreshRequestSchema, \
    TokenRefreshResponseSchema
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
    responses={
        409: {
            "model": DetailResponseSchema,
            "description": "User already exists",
        },
        500: {
            "model": DetailResponseSchema,
            "description": "Error occurred",
        },
    }
)
async def register_user(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db),
):
    try:
        existing_user = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user_data.email} already exists."
            )
        user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        if not user_group:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User group not found."
            )
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=user_group.id,
        )
        db.add(user)
        token = ActivationTokenModel(user=user)
        db.add(token)
        await db.commit()
        return user
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/")
async def activate_user(
        data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db),
) -> MessageResponseSchema:
    user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")
    token_record = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    )
    if not token_record or token_record.token != data.token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    if token_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )
    user.is_active = True
    await db.delete(token_record)
    await db.commit()
    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    path="/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema
)
async def user_login(
        request_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == request_data.email)
    )
    if not user or not user.verify_password(request_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    access_token = jwt_manager.create_access_token(
        data={"user_id": user.id, "email": user.email}
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={"user_id": user.id, "email": user.email},
        expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
    )
    try:
        refresh_token_obj = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(refresh_token_obj)
        await db.commit()
        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def request_for_reset_password(
        request: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await db.scalar(select(UserModel).where(
        UserModel.email == request.email
    ))
    if db_user and db_user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == db_user.id
        ))
        token = str(uuid.uuid4())
        new_token = PasswordResetTokenModel(user_id=db_user.id, token=token)
        db.add(new_token)
        await db.commit()
    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def reset_password(
    request: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    db_user = await db.scalar(select(UserModel).where(UserModel.email == request.email))
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        db_token = await db.scalar(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
        )
        if (
            not db_token
            or db_token.token != request.token
            or db_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        ):
            if db_token:
                await db.execute(
                    delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
                )
                await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        db_user.password = request.password
        await db.execute(
            delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == db_user.id)
        )
        await db.commit()
        await db.refresh(db_user)
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK
)
async def refresh(
    request: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(request.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid refresh token.")
    db_token = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == request.refresh_token)
    )
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    user_id = payload.get("user_id")
    if db_token.user_id != user_id:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    db_user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not db_user or not db_user.is_active:
        raise HTTPException(status_code=404, detail="User not found.")
    access_token = jwt_manager.create_access_token(
        data={"user_id": db_user.id, "email": db_user.email}
    )
    return TokenRefreshResponseSchema(access_token=access_token)
