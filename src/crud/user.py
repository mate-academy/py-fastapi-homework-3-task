from fastapi import HTTPException

from config import get_settings
from crud.base import Base
from database import (
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import EmailStr
from schemas import (
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    UserLoginRequestSchema,
)
from datetime import datetime, timezone

from security.token_manager import JWTAuthManager

SETTINGS = get_settings()  # This returns a BaseAppSettings instance.

TOKEN_MANAGER = JWTAuthManager(
    secret_key_access=SETTINGS.SECRET_KEY_ACCESS,
    secret_key_refresh=SETTINGS.SECRET_KEY_REFRESH,
    algorithm=SETTINGS.JWT_SIGNING_ALGORITHM,
)


class UserDB(Base):
    model = UserModel

    @classmethod
    async def get_user_by_email(cls, email: EmailStr, db: AsyncSession):
        user = select(cls.model).where(cls.model.email == email)
        result = await db.execute(user)

        return result.scalar_one_or_none()

    @classmethod
    async def register_user(cls, db: AsyncSession, user_data):

        find_user = await cls.get_user_by_email(user_data.email, db)

        if find_user:
            raise ValueError(
                f"A user with this email {user_data.email} already exists."
            )

        stmt = select(UserGroupModel.id).where(
            UserGroupModel.name == UserGroupEnum.USER
        )
        user_group = await db.execute(stmt)
        user_group_id = user_group.scalar_one_or_none()
        if user_group_id:
            user = cls.model.create(user_data.email, user_data.password, user_group_id)

            db.add(user)
            await db.commit()
            await db.refresh(user)

            user_id = user.id

            activation_token = ActivationTokenModel(user_id=user_id)
            db.add(activation_token)
            await db.commit()

            return user

    @classmethod
    async def activate_user_account(
        cls, data: UserActivationRequestSchema, db: AsyncSession
    ):

        user = await cls.get_user_by_email(data.email, db)
        current_time = datetime.now(timezone.utc)
        if user and not user.is_active:
            stmt = select(
                ActivationTokenModel.token,
                ActivationTokenModel.expires_at,
                ActivationTokenModel.user_id,
            ).where(
                ActivationTokenModel.expires_at > current_time,
                ActivationTokenModel.user_id == user.id,
            )
            result_token = await db.execute(stmt)
            activation_token_data = result_token.fetchone()
            if activation_token_data:
                user.is_active = True
                await db.commit()

                stmt_delete = delete(ActivationTokenModel).where(
                    ActivationTokenModel.user_id == user.id
                )
                await db.execute(stmt_delete)
                await db.commit()
            else:
                raise ValueError("Invalid or expired activation token.")
        else:
            raise ValueError("User account is already active.")

    @classmethod
    async def password_reset_request(
        cls, data: PasswordResetRequestSchema, db: AsyncSession
    ):
        user = await cls.get_user_by_email(data.email, db)
        if user and user.is_active:
            stmt_delete = delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
            await db.execute(stmt_delete)
            await db.commit()

            user_id = int(user.id)
            instance = PasswordResetTokenModel(user_id=user_id)
            db.add(instance)
            await db.commit()
        else:
            raise ValueError(
                "If you are registered, you will receive an email with instructions."
            )

    @classmethod
    async def user_password_reset_complete(cls, data, db: AsyncSession):
        user = await cls.get_user_by_email(data.email, db)
        current_time = datetime.now(timezone.utc)

        if not (user and user.is_active):
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        stmt = select(
            PasswordResetTokenModel.token,
            PasswordResetTokenModel.expires_at,
            PasswordResetTokenModel.user_id,
        ).where(
            PasswordResetTokenModel.expires_at > current_time,
            PasswordResetTokenModel.user_id == user.id,
        )
        result_token = await db.execute(stmt)
        token_data = result_token.fetchone()

        if token_data and token_data.token == data.token:
            try:
                user.password = data.password
                stmt_delete = delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
                await db.execute(stmt_delete)
                await db.commit()
            except SQLAlchemyError as sae:
                await db.rollback()
                raise HTTPException(
                    status_code=500,
                    detail="An error occurred while resetting the password.",
                )
            except Exception as e:
                await db.rollback()
                raise HTTPException(
                    status_code=500, detail="An internal error occurred."
                )
        else:
            try:
                stmt_delete = delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
                await db.execute(stmt_delete)
                await db.commit()
            except SQLAlchemyError as sae:
                await db.rollback()
                raise HTTPException(
                    status_code=500,
                    detail="An error occurred while resetting the password.",
                )
            except Exception as e:
                await db.rollback()
                raise HTTPException(
                    status_code=500, detail="An internal error occurred."
                )
            raise HTTPException(status_code=400, detail="Invalid email or token.")

    @classmethod
    async def login_user(cls, data: UserLoginRequestSchema, db: AsyncSession):
        user = await cls.get_user_by_email(data.email, db)
        if not user or not user.verify_password(data.password):
            raise HTTPException(status_code=401, detail="Invalid email or password.")

        if not user.is_active:
            raise HTTPException(
                status_code=403, detail="User account is not activated."
            )

        access_token = TOKEN_MANAGER.create_access_token(data={"user_id": user.id})
        refresh_token = TOKEN_MANAGER.create_refresh_token(data={"user_id": user.id})

        stmt = RefreshTokenModel.create(
            user_id=user.id, days_valid=7, token=refresh_token
        )

        try:
            db.add(stmt)
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(
                status_code=500,
                detail="An error occurred while processing the request.",
            )
        except Exception:
            await db.rollback()
            raise HTTPException(
                status_code=500,
                detail="An error occurred while processing the request.",
            )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }
