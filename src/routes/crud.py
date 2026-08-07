from datetime import datetime

from exceptions import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from pydantic import EmailStr

from fastapi import HTTPException, status

from database import UserGroupModel, ActivationTokenModel, RefreshTokenModel
from database.models.accounts import (
    UserModel,
    UserGroupEnum,
    PasswordResetTokenModel,
)

from schemas import (
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
)
from security.passwords import hash_password, verify_password

from dotenv import load_dotenv

load_dotenv()


async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    existing_email_user = await db.scalar(
        select(UserModel).where(UserModel.email == user.email)
    )
    if existing_email_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        hashed = hash_password(user.password)
        default_user_query = select(UserGroupModel).where(
            UserGroupModel.name == UserGroupEnum.USER
        )

        db_user = UserModel(
            email=user.email,
            _hashed_password=hashed,
            group=await db.scalar(default_user_query),
            is_active=False,
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)

        activation_token = ActivationTokenModel(
            user_id=db_user.id,
        )

        db.add(activation_token)
        await db.commit()
        await db.refresh(activation_token)
        return db_user
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during user creation.",
        )


async def activate_user(db: AsyncSession, payload: UserActivationRequestSchema):
    token_db = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.token == payload.token)
    )
    if token_db is None or token_db.expires_at < datetime.now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    user_db = await db.scalar(select(UserModel).where(UserModel.id == token_db.user_id))

    if user_db.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )
    if user_db.email != payload.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )
    user_db.is_active = True
    db.add(user_db)
    await db.delete(token_db)
    await db.commit()


async def get_user_by_email(db: AsyncSession, email: EmailStr):
    return await db.scalar(select(UserModel).where(UserModel.email == email))


async def request_reset_token(db: AsyncSession, payload: PasswordResetRequestSchema):
    email = payload.email
    user_db = await get_user_by_email(db=db, email=email)
    if user_db is None or not user_db.is_active:
        return
    await db.execute(
        delete(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user_db.id
        )
    )

    new_reset_token = PasswordResetTokenModel(user=user_db)
    db.add(new_reset_token)
    await db.commit()


async def password_reset_complete(
    db: AsyncSession, payload: PasswordResetCompleteRequestSchema
):
    email = payload.email
    user_db = await get_user_by_email(db=db, email=email)
    if user_db is None or not user_db.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    token_db = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user_db.id,
        )
    )
    if token_db is None or token_db.token != payload.token:
        if token_db is not None:
            await db.delete(token_db)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    if token_db.expires_at < datetime.now():
        await db.delete(token_db)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    try:
        new_password_hash = hash_password(payload.password)
        user_db._hashed_password = new_password_hash
        await db.delete(token_db)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


async def login_user(
    db: AsyncSession,
    credentials: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface,
):
    user_db = await db.scalar(
        select(UserModel).where(
            UserModel.email == credentials.email,
        )
    )
    if user_db is None or not verify_password(
        credentials.password, user_db._hashed_password
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    if not user_db.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )
    try:
        access_token = jwt_manager.create_access_token(data={"user_id": user_db.id})
        refresh_token = jwt_manager.create_refresh_token(data={"user_id": user_db.id})
        refresh_token_db = RefreshTokenModel.create(
            user_id=user_db.id, token=refresh_token, days_valid=7
        )
        token_type = "bearer"
        db.add(refresh_token_db)
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": token_type,
    }


async def access_token_refresh(
    db: AsyncSession,
    token: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface,
):
    refresh_token = token.refresh_token
    try:
        token_data = jwt_manager.decode_refresh_token(token=refresh_token)
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    except InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Token.",
        )

    token_db = await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == refresh_token)
    )

    if token_db is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found."
        )

    user_db = await db.scalar(
        select(UserModel).where(UserModel.id == token_data["user_id"])
    )
    if user_db is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
        )
    new_access_token = jwt_manager.create_access_token(data={"user_id": user_db.id})
    return new_access_token
