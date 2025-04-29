from datetime import timezone, datetime
from typing import cast

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings
from schemas.accounts import UserRegistrationRequestSchema, UserActivationRequestSchema
from crud.crud import UserGroupCRUD, UserCRUD, ActivationTokenCRUD, PasswordResetTokenCRUD
from security.interfaces import JWTAuthManagerInterface
from security.token_manager import JWTAuthManager
from database import ActivationTokenModel, UserModel, RefreshTokenModel


class UserService:
    def __init__(self, db: AsyncSession, jwt_manager: JWTAuthManager):
        self.db = db
        self.jwt_manager = jwt_manager
        self.user_group_crud = UserGroupCRUD(db)

    async def create_user(self, user: UserRegistrationRequestSchema):
        user_group = await self.user_group_crud.get_user_group_by_name("USER")

        new_user = UserCRUD.create_user_instance(
            email=str(user.email),
            password=user.password,
            group_id=user_group.id,
        )
        self.db.add(new_user)
        try:
            await self.db.flush()
            await self.db.refresh(new_user)

            activation_token = self.jwt_manager.create_access_token(
                data={"sub": str(new_user.email), "type": "activation"}
            )

            token_model = ActivationTokenModel(
                user_id=new_user.id,
                token=activation_token
            )
            self.db.add(token_model)
            await self.db.commit()
            return new_user

        except IntegrityError:
            await self.db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"A user with this email {user.email} already exists.",
            )


class ActivationTokenService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.activation_token_crud = ActivationTokenCRUD(db)

    async def activate_user(
            self,
            activation_request: UserActivationRequestSchema
    ):
        await (
            self.activation_token_crud.validate_and_activate_user(
                activation_request.token
            )
        )
        return {"message": "User account activated successfully."}


class PasswordResetService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.password_reset_token_crud = PasswordResetTokenCRUD(db)
        self.user_crud = UserCRUD(db)

    async def request_password_reset(
            self,
            email: str,
    ) -> dict:
        user = await self.user_crud.get_user_by_email(email=email)

        if user and user.is_active is True:
            token_list = await self.password_reset_token_crud.get_token(
                cast(int, user.id)
            )
            await self.password_reset_token_crud.delete_tokens(token_list)
            new_token = (self.password_reset_token_crud.
                         create_reset_token_instance(cast(int, user.id)))
            user.password_reset_token = new_token

        await self.db.commit()
        # TODO: Implement email sending logic here (e.g., send reset link with new_token.token)

        return {"message": "If you are registered, "
                           "you will receive an email with instructions."}

    async def validate_reset_token(self, email: str, token: str) -> UserModel:
        user = await self.user_crud.get_user_by_email(email)
        if not user or not user.is_active:
            token_list = await (
                self.password_reset_token_crud.get_token(user.id)
            ) if user else []
            if token_list:
                await (self.password_reset_token_crud.
                       delete_tokens(token_list)
                       )
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        reset_token = await self.password_reset_token_crud.get_by_token(token)
        if not reset_token or reset_token.user_id != user.id:
            token_list = await self.password_reset_token_crud.get_token(
                cast(int, user.id)
            )
            if token_list:
                await self.password_reset_token_crud.delete_tokens(token_list)
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        expires_at_with_tz = cast(
            datetime,
            reset_token.expires_at
        ).replace(tzinfo=timezone.utc)
        if expires_at_with_tz < datetime.now(timezone.utc):
            await self.password_reset_token_crud.delete_tokens([reset_token])
            raise HTTPException(
                status_code=400,
                detail="Invalid email or token."
            )

        return user

    async def complete_password_reset(
            self,
            email: str,
            token: str,
            password: str
    ) -> dict:
        try:
            user = await self.validate_reset_token(email, token)

            await self.user_crud.update_password(user, password)

            reset_token = await self.password_reset_token_crud.get_by_token(
                token
            )
            if reset_token:
                await self.password_reset_token_crud.delete_tokens(
                    [reset_token]
                )

            await self.db.commit()
            # TODO: Implement email sending logic here (e.g., send reset link with reset_token.token)

            return {"message": "Password reset successfully."}
        except HTTPException as e:
            await self.db.rollback()
            raise e
        except Exception as e:
            await self.db.rollback()
            raise HTTPException(
                status_code=500,
                detail=f"An error occurred while resetting the password:"
                       f" {str(e)}"
            )


class AuthService:
    def __init__(
            self,
            db: AsyncSession,
            user_crud: UserCRUD,
            jwt_manager: JWTAuthManagerInterface,
            settings: BaseAppSettings,
    ):
        self.db = db
        self.user_crud = user_crud
        self.jwt_manager = jwt_manager
        self.settings = settings

    async def login(self, email: str, password: str) -> dict:
        try:
            user = await self.user_crud.get_user_by_email(email=email)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password."
                )

            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User account is not activated."
                )

            if not user.verify_password(password):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password."
                )

            access_token = self.jwt_manager.create_access_token(
                data={"user_id": user.id}
            )
            refresh_token = self.jwt_manager.create_refresh_token(
                data={"user_id": user.id}
            )
            refresh_token_instance = RefreshTokenModel.create(
                user_id=user.id,
                token=refresh_token,
                days_valid=7
            )
            self.db.add(refresh_token_instance)
            await self.db.commit()

            return {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "bearer",
            }
        except HTTPException as e:
            await self.db.rollback()
            raise e
        except Exception as e:
            print(f"Error in login: {str(e)}")
            await self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while processing the request."
            )

    async def refresh_access_token(self, refresh_token: str) -> dict:
        try:
            try:
                payload = self.jwt_manager.decode_refresh_token(refresh_token)
                if not payload or "user_id" not in payload:
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid refresh token."
                    )
                user_id = payload["user_id"]
            except Exception as e:
                error_msg = str(e).lower()
                if "expired" in error_msg:
                    raise HTTPException(
                        status_code=400,
                        detail="Token has expired."
                    )
                raise HTTPException(
                    status_code=400,
                    detail="Invalid refresh token."
                )

            stmt = select(RefreshTokenModel).where(
                RefreshTokenModel.token == refresh_token
            )
            result = await self.db.execute(stmt)
            token_record = result.scalars().first()
            if not token_record:
                raise HTTPException(
                    status_code=401,
                    detail="Refresh token not found."
                )
            if token_record.user_id != user_id:
                raise HTTPException(
                    status_code=401,
                    detail="Refresh token not found."
                )

            stmt = select(UserModel).where(UserModel.id == user_id)
            result = await self.db.execute(stmt)
            user = result.scalars().first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found.")

            new_access_token = self.jwt_manager.create_access_token(
                data={"user_id": user_id}
            )
            return {"access_token": new_access_token}

        except HTTPException as e:
            await self.db.rollback()
            raise e
        except Exception as e:
            print(f"Error in refresh_access_token: {str(e)}")
            await self.db.rollback()
            raise HTTPException(
                status_code=500,
                detail="An error occurred while processing the request."
            )
