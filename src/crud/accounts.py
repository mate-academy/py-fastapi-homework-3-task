from datetime import timedelta, datetime, timezone

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_settings
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (UserRegistrationRequestSchema,
                              UserActivationRequestSchema,
                              PasswordResetRequestSchema,
                              PasswordResetCompleteRequestSchema,
                              UserLoginRequestSchema,
                              TokenRefreshRequestSchema,
                              MessageResponseSchema)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import hash_password
from database import (UserModel,
                      ActivationTokenModel,
                      PasswordResetTokenModel,
                      RefreshTokenModel,
                      UserGroupModel)
from security.token_manager import JWTAuthManager
from security.utils import check_token_is_valid


settings = get_settings()


async def create_token(db: AsyncSession, user: UserModel, jwt_manager: JWTAuthManagerInterface):
    data = {
        "user_id": user.id,
        "email": user.email,
    }
    refresh_token = jwt_manager.create_refresh_token(
        data=data,
    )
    access_token = jwt_manager.create_access_token(
        data=data,
    )

    try:
        token = RefreshTokenModel(
            user=user,
            token=refresh_token,
        )
        db.add(token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


async def create_activation_token(user_id: int, db: AsyncSession):
    new_token = ActivationTokenModel(
        user_id=user_id
    )
    db.add(new_token)
    await db.flush()

    return new_token


async def create_and_store_refresh_token(db: AsyncSession, user: UserModel, jwt_manager: JWTAuthManager):
    token_str = jwt_manager.create_refresh_token({"user_id": user.id})

    expires_at = datetime.now(timezone.utc) + timedelta(days=7)

    refresh_token = RefreshTokenModel(
        user_id=user.id,
        token=token_str,
        expires_at=expires_at
    )

    db.add(refresh_token)
    await db.commit()
    await db.refresh(refresh_token)

    return refresh_token


async def get_user_by_email(db: AsyncSession, email: str):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == email)
    )

    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def create_user(user_data: UserRegistrationRequestSchema, db: AsyncSession):

    existing_user = await get_user_by_email(db=db, email=user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user_data.email} already exists."
        )

    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == user_data.group.name))
    user_group = result.scalar_one_or_none()

    hashed_password = hash_password(user_data.password)
    new_user = UserModel(
        email=user_data.email,
        _hashed_password=hashed_password,
        group_id=user_group.id
    )

    db.add(new_user)
    await db.flush()

    try:
        new_token = await create_activation_token(new_user.id, db)
        new_user.activation_token = new_token
        await db.commit()
        await db.refresh(new_user)
        return new_user

    except Exception:

        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


async def activate_user_account(db: AsyncSession, user_data: UserActivationRequestSchema):
    user = await get_user_by_email(db=db, email=user_data.email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    is_valid = await check_token_is_valid(token=user_data.token, expected_token=user.activation_token)

    if is_valid is False:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired activation token."
        )

    user.is_active = True
    user.activation_token = None
    db.add(user)

    await db.commit()
    await db.refresh(user)

    return MessageResponseSchema(
        status_code=200,
        message="User account activated successfully."
    )


async def password_reset(db: AsyncSession, user_data: PasswordResetRequestSchema):
    stmt = (
        select(UserModel)
        .options(joinedload(UserModel.password_reset_token))
        .where(UserModel.email == user_data.email)
    )

    result = await db.execute(stmt)
    user = result.scalars().first()

    if user and user.is_active is True:

        await db.delete(user.password_reset_token) if user.password_reset_token else None

        new_token = PasswordResetTokenModel(user=user)
        db.add(new_token)
        user.password_reset_token = new_token

        await db.commit()

    return MessageResponseSchema(
        status_code=200,
        message="If you are registered, you will receive an email with instructions."
    )


async def reset_password_completion(db: AsyncSession, user_data: PasswordResetCompleteRequestSchema):
    password_reset_token = None

    try:
        stmt = (
            select(UserModel)
            .options(joinedload(UserModel.password_reset_token))
            .where(UserModel.email == user_data.email)
        )
        result = await db.execute(stmt)
        user = result.scalars().first()

        if not user or not user.is_active:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        password_reset_token = user.password_reset_token

        if not password_reset_token:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        is_valid = await check_token_is_valid(token=user_data.token, expected_token=password_reset_token)
        if not is_valid:
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = user_data.password

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
    finally:
        if password_reset_token:
            try:
                await db.delete(password_reset_token)
                await db.commit()
            except Exception:
                raise HTTPException(status_code=500,
                                    detail="An error occurred while resetting the password.")

    return MessageResponseSchema(
        status_code=200,
        message="Password reset successfully."
    )


async def authenticate_user(db: AsyncSession, user_data: UserLoginRequestSchema, jwt_manager: JWTAuthManagerInterface):
    user = await get_user_by_email(db=db, email=user_data.email)

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    return await create_token(db=db, user=user, jwt_manager=jwt_manager)


async def access_token_refresh(db: AsyncSession,
                               user_data: TokenRefreshRequestSchema,
                               jwt_manager: JWTAuthManagerInterface
                               ):
    try:
        payload = jwt_manager.decode_refresh_token(user_data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=401, detail="Refresh token not found.")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid token.")

    result = await db.execute(
        select(RefreshTokenModel).where(RefreshTokenModel.token == user_data.refresh_token)
    )
    token_record = result.scalars().first()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    result_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token(
        {
            "user_id": user.id
        }
    )

    return {"access_token": new_access_token}
