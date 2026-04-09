import os
import base64

from datetime import datetime, timezone, timedelta
from typing import cast, Annotated
from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

# from sqlalchemy.orm import Session, joinedload
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface
from schemas import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from database.crud import (
    register_new_user,
    insert_activation_token,
    set_user_active_status,
    delete_activation_token,
    delete_all_password_reset_tokens,
    insert_password_reset_token,
    delete_password_reset_token_and_returning,
    change_password_for_user,
    get_user_by_email,
    insert_refresh_token,
    get_refresh_token_and_join_with_user,
)

router = APIRouter()
database = Annotated[AsyncSession, Depends(get_db)]
settings = Annotated[BaseAppSettings, Depends(get_settings)]
JWTManager = Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)]
_InternalServerErrorForRegister = HTTPException(
    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    detail="An error occurred during user creation.",
)
_InternalServerErrorForChangePassword = HTTPException(
    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    detail="An error occurred while resetting the password.",
)
_InternalServerErrorForLogin = HTTPException(
    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
    detail="An error occurred while processing the request.",
)


def _generate_token(length: int) -> str:
    return base64.b64encode(os.urandom(length)).decode("utf-8")


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    db: database, user: UserRegistrationRequestSchema, settings: settings
):
    try:
        new_user = await register_new_user(db=db, user=user)
        if not new_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A user with this email {user.email} already exists.",
            )
        token = _generate_token(48)
        if not await insert_activation_token(
            db=db,
            token=token,
            user=new_user,
            timedelta=timedelta(settings.TOKEN_DELTA_HOURS),
        ):
            raise _InternalServerErrorForRegister
        await db.commit()
        return new_user
    except Exception as e:
        await db.rollback()
        print(e)
        if isinstance(e, HTTPException):
            raise
        if isinstance(e, ValueError):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
            )
        raise _InternalServerErrorForRegister


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user_account(
    db: database, act_request: UserActivationRequestSchema, settings: settings
):
    try:
        if not await set_user_active_status(db=db, email=act_request.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )
        timedelta_ = timedelta(hours=settings.TOKEN_DELTA_HOURS)
        if not await delete_activation_token(
            db=db,
            token=act_request.token,
            email=act_request.email,
            timedelta_=timedelta_,
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )
        await db.commit()
        return {"message": "User account activated successfully."}
    except Exception as e:
        await db.rollback()
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(
    db: database, pass_request: PasswordResetRequestSchema, settings: settings
):
    try:
        await delete_all_password_reset_tokens(db=db, pass_request=pass_request)
        token = _generate_token(48)
        timedelta_ = timedelta(hours=settings.TOKEN_DELTA_HOURS)
        if not await insert_password_reset_token(
            db=db, token=token, timedelta_=timedelta_, pass_request=pass_request
        ):
            raise HTTPException()
        await db.commit()
    except Exception:
        await db.rollback()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password_complete(
    db: database, pass_req_complete: PasswordResetCompleteRequestSchema
):
    try:
        if not await delete_password_reset_token_and_returning(
            db=db, pass_req_complete=pass_req_complete
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )
        if not await change_password_for_user(
            db=db, pass_req_complete=pass_req_complete
        ):
            raise _InternalServerErrorForChangePassword
        await db.commit()
    except Exception as e:
        await db.rollback()
        if isinstance(e, HTTPException):
            raise
        if isinstance(e, ValueError):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
            )
        raise _InternalServerErrorForChangePassword
    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    db: database,
    user_req: UserLoginRequestSchema,
    jwt_manager: JWTManager,
    settings: settings,
):
    try:
        user = await get_user_by_email(
            db=db, email=user_req.email, password=user_req.password
        )
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is not activated.",
            )
        data = {"sub": user.email, "user_id": user.id}
        access_token = jwt_manager.create_access_token(data=data)

        data.update(jti=_generate_token(48))  # To be able to blacklist a token
        refresh_token_model = await insert_refresh_token(
            db=db,
            token=jwt_manager.create_refresh_token(data=data),
            days_to_expire=settings.LOGIN_TIME_DAYS,
            user=user,
        )
        await db.commit()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token_model.token,
        }
    except Exception as e:
        await db.rollback()
        if isinstance(e, HTTPException):
            raise
        raise _InternalServerErrorForLogin


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    db: database, refresh_req: TokenRefreshRequestSchema, jwt_manager: JWTManager
):
    try:
        data = jwt_manager.decode_refresh_token(token=refresh_req.refresh_token)
        token_model = await get_refresh_token_and_join_with_user(
            db=db, token=refresh_req.refresh_token
        )
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )
    else:
        if not token_model:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )
        if not (user := await get_user_by_email(db=db, user_id=data["user_id"])):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
            )
        data = {
            "sub": user.email,
            "user_id": user.id,
        }
        return {
            "access_token": jwt_manager.create_access_token(data=data),
        }
