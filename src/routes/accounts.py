from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from jose import ExpiredSignatureError
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
from exceptions import TokenExpiredError
from schemas import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password

router = APIRouter()


# Write your code here
async def get_user_by_email(
        email: str,
        db: AsyncSession = Depends(get_db)
) -> UserModel:
    result = await db.scalar(
        select(UserModel).where(UserModel.email == email)
    )
    return result


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def register_user(
        user: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(email=user.email, db=db)
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists."
        )
    try:
        user_group = await db.scalar(
            select(UserGroupModel).where(
                UserGroupModel.name == UserGroupEnum.USER)
        )
        if not user_group:
            user_group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(user_group)
            await db.commit()
            await db.refresh(user_group)

        new_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=user_group.id
        )
        new_user.is_active = False

        db.add(new_user)
        await db.flush()
        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)

        return new_user

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def user_activate(
        request: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(email=request.email, db=db)
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A user with given email {request.email} does not exist."
        )
    if db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )
    db_token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == db_user.id
        )
    )

    if (
            not db_token
            or db_token.token != request.token
            or cast(datetime, db_token.expires_at)
            .replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )
    db_user.is_active = True
    await db.delete(db_token)
    await db.commit()
    return {
        "message": "User account activated successfully."
    }


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK
)
async def user_password_reset(
        request_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(email=request_data.email, db=db)
    if db_user and db_user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == db_user.id
            )
        )

        new_reset_token = PasswordResetTokenModel(user_id=db_user.id)
        db.add(new_reset_token)
        await db.commit()

    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema
)
async def password_reset_complete(
        request_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    db_user = await get_user_by_email(email=request_data.email, db=db)
    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    stmt_token = select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == db_user.id)
    db_token = await db.scalar(stmt_token)

    expired = db_token and cast(datetime, db_token.expires_at).replace(
        tzinfo=timezone.utc) <= datetime.now(timezone.utc)
    wrong_token = db_token and db_token.token != request_data.token

    if not db_token or wrong_token or expired:
        if db_token:
            await db.delete(db_token)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        db_user._hashed_password = hash_password(request_data.password)
        await db.delete(db_token)
        await db.commit()
        await db.refresh(db_user)

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )

    return {
        "message": "Password reset successfully."
    }


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED
)
async def user_login(
        credentials: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings)
):
    db_user = await db.scalar(
        select(UserModel).where(UserModel.email == credentials.email)
    )
    if not db_user or not db_user.verify_password(credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )
    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )
    access_token = jwt_manager.create_access_token(
        data={"sub": credentials.email, "user_id": db_user.id}
    )
    refresh_token = jwt_manager.create_refresh_token(
        data={"sub": credentials.email, "user_id": db_user.id}
    )

    try:
        db_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_token)
        await db.commit()
        await db.refresh(db_token)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": db_token.token,
        "token_type": "bearer"
    }


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema
)
async def token_refresh(
        request_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded = jwt_manager.decode_refresh_token(request_data.refresh_token)

    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Signature has expired."
        )

    stmt_token = select(RefreshTokenModel).where(
        RefreshTokenModel.token == request_data.refresh_token
    )
    db_token = await db.scalar(stmt_token)

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    if cast(datetime, db_token.expires_at).replace(
            tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        await db.delete(db_token)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    db_user = await db.scalar(
        select(UserModel).where(UserModel.id == db_token.user_id)
    )
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    if decoded.get("user_id") != db_token.user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token ownership."
        )
    access_token = jwt_manager.create_access_token(
        data={"sub": db_user.email, "user_id": db_user.id}
    )
    return {
        "access_token": access_token
    }
