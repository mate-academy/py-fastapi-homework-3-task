from datetime import datetime, timezone
from typing import List

from fastapi import HTTPException
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload
from database import UserGroupModel, UserModel, ActivationTokenModel, PasswordResetTokenModel


class UserGroupCRUD:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_user_group_by_name(self, name: str) -> UserGroupModel | None:
        stmt = select(UserGroupModel).where(UserGroupModel.name == name)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()


class UserCRUD:
    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def create_user_instance(
            email: str,
            password: str,
            group_id
    ) -> UserModel:
        return UserModel.create(
            email=email,
            raw_password=password,
            group_id=group_id
        )

    async def add_user(
            self,
            user: UserModel
    ) -> UserModel:
        self.db.add(user)
        await self.db.flush()
        await self.db.refresh(user)
        return user

    async def get_user_by_email(self, email: str) -> UserModel | None:
        stmt = select(UserModel).where(UserModel.email == email)
        stmt_result = await self.db.execute(stmt)
        user = stmt_result.scalar_one_or_none()
        return user

    async def update_password(
            self,
            user: UserModel,
            new_password: str
    ) -> UserModel:
        try:
            user.password = new_password
            await self.db.commit()
            await self.db.refresh(user)
            return user
        except ValueError as e:
            await self.db.rollback()
            raise HTTPException(
                status_code=400,
                detail=f"Invalid password: {str(e)}"
            )
        except Exception:
            await self.db.rollback()
            raise HTTPException(
                status_code=500,
                detail="An error occurred while resetting the password."
            )


class ActivationTokenCRUD:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_activation_token(
            self,
            token: str
    ) -> ActivationTokenModel | None:
        stmt = select(ActivationTokenModel).where(
            ActivationTokenModel.token == token
        ).options(
            joinedload(ActivationTokenModel.user)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def delete_activation_token(self, token: str) -> None:
        stmt = delete(ActivationTokenModel).where(
            ActivationTokenModel.token == token
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def validate_and_activate_user(self, token: str) -> UserModel:
        activation_token = await self.get_activation_token(token)

        if not activation_token:
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired activation token."
            )

        user = activation_token.user

        expires_at_with_tz = activation_token.expires_at.replace(
            tzinfo=timezone.utc
        )
        if expires_at_with_tz < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=400,
                detail="Invalid or expired activation token."
            )

        if user.is_active:
            raise HTTPException(
                status_code=400,
                detail="User account is already active."
            )

        user.is_active = True
        await self.db.commit()

        await self.delete_activation_token(token)

        return user


class PasswordResetTokenCRUD:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_token(
            self,
            user_id: int
    ) -> List[PasswordResetTokenModel]:
        stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user_id
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def delete_tokens(
            self,
            tokens: List[PasswordResetTokenModel]
    ) -> None:
        for token in tokens:
            await self.db.delete(token)
        await self.db.commit()

    @staticmethod
    def create_reset_token_instance(
            user_id: int
    ) -> PasswordResetTokenModel:
        return PasswordResetTokenModel(user_id=user_id)

    async def get_by_token(
            self,
            token: str
    ) -> PasswordResetTokenModel | None:
        stmt = select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.token == token
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()
