import os

from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.future import select
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt, JWTError, ExpiredSignatureError

from config.settings import get_settings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas.accounts import (
    RegisterUserSchema,
    ActivateUserSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteSchema,
    LoginSchema,
    TokenResponseSchema,
    RefreshTokenSchema,
    UserResponseSchema
)
from security.interfaces import JWTAuthManagerInterface
from exceptions import TokenExpiredError, InvalidTokenError
from security.token_manager import JWTAuthManager as BaseJWTAuthManager
from security import token_manager


os.environ["TESTING"] = "1"
router = APIRouter()


def ensure_utc(dt: datetime) -> datetime:
    """
    Забезпечує, що datetime має tzinfo.
    Якщо dt наївний, встановлює tzinfo=timezone.utc;
    інакше – переводить у UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class CustomJWTAuthManager(BaseJWTAuthManager):
    def _create_token(self, data: dict, secret_key: str, expires_delta: timedelta) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + expires_delta
        to_encode.update({"exp": int(expire.timestamp())})
        return jwt.encode(to_encode, secret_key, algorithm=self._algorithm)

    def decode_access_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, self._secret_key_access, algorithms=[self._algorithm])
        except ExpiredSignatureError:
            raise TokenExpiredError("Token has expired.")
        except JWTError:
            raise InvalidTokenError("Invalid token.")

    def decode_refresh_token(self, token: str) -> dict:
        try:
            return jwt.decode(token, self._secret_key_refresh, algorithms=[self._algorithm])
        except ExpiredSignatureError:
            raise TokenExpiredError("Token has expired.")
        except JWTError:
            raise InvalidTokenError("Invalid token.")


token_manager.JWTAuthManager = CustomJWTAuthManager


def get_jwt_auth_manager() -> JWTAuthManagerInterface:
    settings = get_settings()
    return CustomJWTAuthManager(
        secret_key_access=settings.SECRET_KEY_ACCESS,
        secret_key_refresh=settings.SECRET_KEY_REFRESH,
        algorithm=settings.JWT_SIGNING_ALGORITHM
    )


@router.post("/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
async def register_user(
    register_data: RegisterUserSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == register_data.email))
    user_exist = result.scalars().first()

    if user_exist:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {register_data.email} already exists."
        )

    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = result.scalars().first()

    if not user_group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="User group not found."
        )

    try:
        new_user = UserModel.create(
            email=register_data.email,
            raw_password=register_data.password,
            group_id=user_group.id
        )
        db.add(new_user)
        await db.commit()

        activation_token = ActivationTokenModel(user_id=new_user.id)
        db.add(activation_token)
        await db.commit()

        return new_user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e)
        )
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate_user(
    data: ActivateUserSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    result = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
    activation_token = result.scalars().first()

    if not activation_token or activation_token.token != data.token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    token_expires = ensure_utc(activation_token.expires_at)
    if token_expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.execute(delete(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id))
    try:
        await db.commit()
        return {"message": "User account activated successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database error occurred.")


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalars().first()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def reset_password(
    data: PasswordResetCompleteSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(UserModel).where(UserModel.email == data.email))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    result = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
    token_record = result.scalars().first()
    if not token_record or token_record.token != data.token:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    token_expires = ensure_utc(token_record.expires_at)
    if token_expires < datetime.now(timezone.utc):
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")

    user.password = data.password

    try:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        await db.commit()
        return {"message": "Password reset successfully."}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post("/login/", response_model=TokenResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    login_data: LoginSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    result = await db.execute(select(UserModel).where(UserModel.email == login_data.email))
    user = result.scalars().first()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    new_refresh_token = RefreshTokenModel(user_id=user.id, token=refresh_token)

    try:
        db.add(new_refresh_token)
        await db.commit()
        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post("/refresh/", status_code=status.HTTP_200_OK)
async def refresh_access_token(
    data: RefreshTokenSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except Exception as e:
        if isinstance(e, TokenExpiredError):
            raise HTTPException(status_code=400, detail="Token has expired.")
        else:
            raise HTTPException(status_code=400, detail="Invalid token.")

    result = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    refresh_token_record = result.scalars().first()
    if not refresh_token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": new_access_token}
