from datetime import datetime, timedelta, timezone
from secrets import compare_digest
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import BaseAppSettings, get_jwt_auth_manager, get_settings
from database import (
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupEnum,
    UserGroupModel,
    UserModel,
    get_db,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    MessageResponseSchema,
    PasswordResetCompleteRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    UserActivationRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface


class AccountRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def handle_request(request: Request):
            try:
                return await handler(request)
            except RequestValidationError as error:
                if self.path.endswith("/reset-password/complete/"):
                    raise HTTPException(status_code=400, detail="Invalid email or token.") from error
                raise

        return handle_request


router = APIRouter(route_class=AccountRoute)


def token_has_expired(expires_at: datetime) -> bool:
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= datetime.now(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    duplicate_detail = f"A user with this email {data.email} already exists."
    existing_user_query = select(UserModel.id).where(UserModel.email == data.email)

    try:
        if await db.scalar(existing_user_query) is not None:
            raise HTTPException(status_code=409, detail=duplicate_detail)

        group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        if group is None:
            raise HTTPException(status_code=500, detail="An error occurred during user creation.")

        user = await run_in_threadpool(UserModel.create, data.email, data.password, group.id)
        db.add(user)
        await db.flush()
        db.add(ActivationTokenModel(user_id=user.id))
        await db.commit()
    except IntegrityError as error:
        await db.rollback()
        if await db.scalar(existing_user_query) is not None:
            raise HTTPException(status_code=409, detail=duplicate_detail) from error
        raise HTTPException(status_code=500, detail="An error occurred during user creation.") from error
    except HTTPException:
        raise
    except Exception as error:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.") from error

    return {"id": user.id, "email": user.email}


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    invalid_detail = "Invalid or expired activation token."
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == data.email).with_for_update())
        if user is None:
            raise HTTPException(status_code=400, detail=invalid_detail)
        if user.is_active:
            raise HTTPException(status_code=400, detail="User account is already active.")

        try:
            data.token.encode("utf-8")
        except UnicodeEncodeError as error:
            raise HTTPException(status_code=400, detail=invalid_detail) from error

        result = await db.execute(
            delete(ActivationTokenModel)
            .where(
                ActivationTokenModel.user_id == user.id,
                ActivationTokenModel.token == data.token,
                ActivationTokenModel.expires_at > datetime.now(timezone.utc),
            )
            .returning(ActivationTokenModel.id)
        )
        if result.scalar_one_or_none() is None:
            raise HTTPException(status_code=400, detail=invalid_detail)

        user.is_active = True
        await db.commit()
    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while activating the account.") from error

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    response = {"message": "If you are registered, you will receive an email with instructions."}
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == data.email).with_for_update())
        if user is None or not user.is_active:
            return response

        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        db.add(PasswordResetTokenModel(user_id=user.id))
        await db.commit()
    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.") from error

    return response


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(data: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    invalid_detail = "Invalid email or token."
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == data.email).with_for_update())
        if user is None or not user.is_active:
            raise HTTPException(status_code=400, detail=invalid_detail)

        result = await db.execute(
            delete(PasswordResetTokenModel)
            .where(PasswordResetTokenModel.user_id == user.id)
            .returning(PasswordResetTokenModel.token, PasswordResetTokenModel.expires_at)
        )
        token = result.one_or_none()
        if token is None:
            raise HTTPException(status_code=400, detail=invalid_detail)

        provided_token = data.token.encode("utf-8", errors="surrogatepass")
        stored_token = token.token.encode("utf-8", errors="surrogatepass")
        if not compare_digest(provided_token, stored_token) or token_has_expired(token.expires_at):
            await db.commit()
            raise HTTPException(status_code=400, detail=invalid_detail)

        await run_in_threadpool(setattr, user, "password", data.password)
        await db.commit()
    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.") from error

    return {"message": "Password reset successfully."}


# The assignment's integration tests require 201 for a successful login.
@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    try:
        user = await db.scalar(select(UserModel).where(UserModel.email == data.email))
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        try:
            password_is_valid = await run_in_threadpool(user.verify_password, data.password)
        except ValueError:
            password_is_valid = False
        if not password_is_valid:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")

        access_token = jwt_manager.create_access_token({"user_id": user.id, "jti": str(uuid4())})
        refresh_token = jwt_manager.create_refresh_token(
            {"user_id": user.id, "jti": str(uuid4())},
            expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS),
        )
        db.add(RefreshTokenModel.create(user_id=user.id, days_valid=settings.LOGIN_TIME_DAYS, token=refresh_token))
        await db.commit()
    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.") from error

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
    except BaseSecurityError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except UnicodeError as error:
        raise HTTPException(status_code=400, detail="Invalid token.") from error

    user_id = payload.get("user_id")
    if not isinstance(user_id, int) or isinstance(user_id, bool):
        raise HTTPException(status_code=400, detail="Invalid token.")

    try:
        token = await db.scalar(select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
        if token is None:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

        user = await db.get(UserModel, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        if token.user_id != user.id:
            raise HTTPException(status_code=401, detail="Refresh token not found.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is not activated.")
        if token_has_expired(token.expires_at):
            raise HTTPException(status_code=400, detail="Token has expired.")
    except SQLAlchemyError as error:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.") from error

    access_token = jwt_manager.create_access_token({"user_id": user.id, "jti": str(uuid4())})
    return {"access_token": access_token}
