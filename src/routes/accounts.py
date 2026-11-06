from typing import Annotated

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

import crud
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from crud.accounts import create_user, activate_user, create_reset_password_token, \
    login_user, refresh_access_token_for_user
from database import (
    get_db
)
from exceptions import UserWithEmailAlreadyExistsError, TokenNotFoundError, TokenExpiredError, \
    UserAlreadyActiveError, UserDBError, InvalidCredentialsError, UserNotActivatedError, BaseSecurityError, \
    InvalidTokenError, UserNotFoundError
from schemas import UserRegistrationResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, \
    MessageResponseSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema, \
    UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(
        db_session: Annotated[AsyncSession, Depends(get_db)],
        user_data: UserRegistrationRequestSchema
):
    try:
        created_user = await create_user(db_session=db_session, create_user_data=user_data)
        return created_user
    except UserWithEmailAlreadyExistsError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"A user with this email {user_data.email} already exists.")
    except SQLAlchemyError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during user creation.")


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate(
        db_session: Annotated[AsyncSession, Depends(get_db)],
        activate_data: UserActivationRequestSchema
):
    try:
        await activate_user(db_session=db_session, activate_data=activate_data)
    except (TokenNotFoundError, TokenExpiredError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired activation token.")
    except UserAlreadyActiveError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User account is already active.")

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset(
        db_session: Annotated[AsyncSession, Depends(get_db)],
        data: PasswordResetRequestSchema
):
    try:
        await create_reset_password_token(db_session=db_session, data=data)
    except (UserDBError, SQLAlchemyError) as e:
        print(e)

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_reset_password(
        db_session: Annotated[AsyncSession, Depends(get_db)],
        data: PasswordResetCompleteRequestSchema
):
    try:
        await crud.accounts.complete_reset_password(db_session=db_session, data=data)
    except (UserDBError, BaseSecurityError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token.")
    except SQLAlchemyError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while resetting the password.")

    return MessageResponseSchema(
        message="Password reset successfully."
    )


@router.post("/login/", response_model=UserLoginResponseSchema)
async def login(
        db_session: Annotated[AsyncSession, Depends(get_db)],
        login_data: UserLoginRequestSchema,
        jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
        settings: Annotated[BaseAppSettings, Depends(get_settings)],
):
    try:
        access_token, refresh_token = await login_user(
            db_session=db_session,
            data=login_data,
            jwt_manager=jwt_manager,
            settings=settings,
        )
    except InvalidCredentialsError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    except UserNotActivatedError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is not activated.")
    except SQLAlchemyError:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
        db_session: Annotated[AsyncSession, Depends(get_db)],
        data: TokenRefreshRequestSchema,
        jwt_manager: Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)],
):
    try:
        new_access_token = await refresh_access_token_for_user(
            db_session=db_session,
            data=data,
            jwt_manager=jwt_manager,
        )
        return TokenRefreshResponseSchema(
            access_token=new_access_token,
        )
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired.")
    except TokenNotFoundError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found.")
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
