from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

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
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    summary="Register a new user",
    description=(
        "<h3>This endpoint registers a new user account in the database. "
        "Clients must provide a valid 'email' and 'password' in the request body. "
        "The response includes the created user's details (excluding the password), "
        "along with appropriate status codes for validation or duplicate email errors.</h3>"
    ),
    responses={
        409: {
            "description": "User with this email already exists.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "A user with this email user@example.com already exists."
                    }
                }
            },
        },
        500: {
            "description": "Error creating user.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred during user creation."}
                }
            },
        },
    },
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == user.email)
    )
    db_user = result.scalar_one_or_none()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user.email} already exists.",
        )

    try:
        user_group_result = await db.execute(
            select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
        )
        db_user_group = user_group_result.scalar_one_or_none()
        db_user = UserModel.create(
            email=user.email,
            raw_password=user.password,
            group_id=db_user_group.id
        )
        db.add(db_user)
        await db.flush()
        await db.refresh(db_user)

        activation_token = ActivationTokenModel(user=db_user)
        db.add(activation_token)
        await db.commit()

        return UserRegistrationResponseSchema.model_validate(db_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation."
        )


@router.post(
    "/activate/",
    response_model=MessageResponseSchema,
    summary="Activate a user account",
    description=(
        "<h3>This endpoint activates a registered user account using a verification token. "
        "Clients must provide 'email' and 'token' in the request body. "
        "The response confirms successful activation, or returns status code 400 "
        "if the token is invalid, expired, or the account is already active.</h3>"
    ),
    responses={
        400: {
            "description": "Invalid or expired activation token, or user account is already active.",
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_or_expired_token": {
                            "summary": "Invalid or expired token",
                            "value": {
                                "detail": "Invalid or expired activation token."
                            }
                        },
                        "already_active": {
                            "summary": "Account already active",
                            "value": {
                                "detail": "User account is already active."
                            },
                        }
                    }
                }
            },
        },
    },
)
async def activate(
    activation_request: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    token_result = await db.execute(
        select(ActivationTokenModel)
        .options(joinedload(ActivationTokenModel.user))
        .where(ActivationTokenModel.token == activation_request.token)
    )
    db_token = token_result.scalar_one_or_none()

    if (
        not db_token
        or cast(datetime, db_token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        or db_token.user.email != activation_request.email
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if db_token.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    try:
        db_token.user.is_active = True
        await db.delete(db_token)
        await db.commit()

        return MessageResponseSchema(message="User account activated successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during activation."
        )


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    summary="Request a password reset",
    description=(
        "<h3>This endpoint initiates the password reset process "
        "by sending a reset token to the user's email. "
        "Clients must provide the registered 'email' address in the request body.</h3>"
    ),
)
async def password_reset(
    reset_request: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == reset_request.email)
    )
    db_user = user_result.scalar_one_or_none()

    if db_user and db_user.is_active:
        try:
            stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user == db_user)
            await db.execute(stmt)
            new_rest_token = PasswordResetTokenModel(user=db_user)
            db.add(new_rest_token)
            await db.commit()

        except SQLAlchemyError:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while requesting a password reset."
            )

    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    summary="Complete password reset",
    description=(
        "<h3>This endpoint completes the password reset process for a user account. "
        "Clients must provide the registered 'email', the verification 'token', and "
        "a new 'password' in the request body. "
        "The response confirms that the password has been updated, "
        "or returns appropriate status codes if the email/token is invalid, expired, "
        "or an unexpected error occurs.</h3>"
    ),
    responses={
        400: {
            "description": "Invalid email, token, password, or expired token.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid email or token."
                    }
                }
            },
        },
        500: {
            "description": "Unexpected error while resetting the password.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while resetting the password."
                    }
                }
            },
        },
    },
)
async def reset_password_complete(
    reset_request: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == reset_request.email)
    )
    db_user = user_result.scalar_one_or_none()

    if not db_user or not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    reset_token_result = await db.execute(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user == db_user)
    )
    db_reset_token = reset_token_result.scalar_one_or_none()

    if (
        not db_reset_token
        or cast(datetime, db_reset_token.expires_at).replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)
        or db_reset_token.token != reset_request.token
    ):
        stmt = delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user == db_user)
        await db.execute(stmt)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token."
        )

    try:
        db_user.password = reset_request.password
        await db.delete(db_reset_token)
        await db.commit()

        return MessageResponseSchema(message="Password reset successfully.")

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password."
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    summary="User login",
    description=(
        "<h3>This endpoint authenticates a registered user and issues JWT tokens. "
        "Clients must provide their 'email' and 'password' in the request body. "
        "The response includes an 'access_token', a 'refresh_token', and the 'token_type' ('bearer'), "
        "or returns appropriate status codes if credentials are invalid, the account "
        "is inactive, or a server error occurs.</h3>"
    ),
    responses={
        401: {
            "description": "Invalid email or password.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid email or password."
                    }
                }
            },
        },
        403: {
            "description": "User account is not activated.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User account is not activated."
                    }
                }
            },
        },
        500: {
            "description": "Unexpected error while logging in.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "An error occurred while processing the request."
                    }
                }
            },
        },
    },
    status_code=status.HTTP_201_CREATED
)
async def login(
    login_request: UserLoginRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
    db: AsyncSession = Depends(get_db)
):
    user_result = await db.execute(
        select(UserModel).where(UserModel.email == login_request.email)
    )
    db_user = user_result.scalar_one_or_none()

    if not db_user or not db_user.verify_password(login_request.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not db_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})
    refresh_token = jwt_manager.create_refresh_token(data={"user_id": db_user.id})

    try:
        db_refresh_token = RefreshTokenModel.create(
            user_id=db_user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token
        )
        db.add(db_refresh_token)
        await db.commit()

        return UserLoginResponseSchema(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    summary="Refresh access token",
    description=(
        "<h3>This endpoint issues a new 'access_token' using a valid 'refresh_token'. "
        "Clients must provide the 'refresh_token' in the request body. "
        "The response includes the new 'access_token', "
        "or returns appropriate status codes if the token is invalid or expired, not "
        "found, or the associated user does not exist.</h3>"
    ),
    responses={
        400: {
            "description": "Refresh token is invalid or has expired.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Token has expired."
                    }
                }
            },
        },
        401: {
            "description": "Refresh token not found.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Refresh token not found."
                    }
                }
            },
        },
        404: {
            "description": "User associated with the token not found.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User not found."
                    }
                }
            },
        },
    },
)
async def get_new_access_token(
    request_refresh_token: TokenRefreshRequestSchema,
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    db: AsyncSession = Depends(get_db)
):
    try:
        decode_data = jwt_manager.decode_refresh_token(request_refresh_token.refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    result_refresh_token = await db.execute(
        select(RefreshTokenModel)
        .where(RefreshTokenModel.token == request_refresh_token.refresh_token)
    )
    db_refresh_token = result_refresh_token.scalar_one_or_none()

    if not db_refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    user_result = await db.execute(
        select(UserModel).where(UserModel.id == decode_data["user_id"])
    )
    db_user = user_result.scalar_one_or_none()

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    access_token = jwt_manager.create_access_token(data={"user_id": db_user.id})

    return TokenRefreshResponseSchema(access_token=access_token)
