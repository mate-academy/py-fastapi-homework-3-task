from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

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
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas import (UserRegistrationRequestSchema,
                     UserRegistrationResponseSchema,
                     UserActivationRequestSchema,
                     MessageResponseSchema,
                     PasswordResetRequestSchema,
                     PasswordResetCompleteRequestSchema, UserLoginRequestSchema, UserLoginResponseSchema,
                     TokenRefreshResponseSchema, TokenRefreshRequestSchema
                     )
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register",
    response_model=UserRegistrationResponseSchema,
    summary="Add a new user",
    description=(
            "<h3>This endpoint allows new users to register by providing their email and new_password. "
            "It should handle potential errors and return the appropriate response based "
            "on the scenarios described below.</h3>"
    ),
    responses={
        201: {"description": "User registered successfully."},
        409: {"description": "A user with the same email already exists.",
              "content": {
                  "application/json": {
                      "example": {"detail": "A user with this email test@example.com already exists."}
                  }
              }
        },
        500: {"description": "An error occurred during user creation.",
              "content": {
                  "application/json": {
                      "example": {"detail": "An error occurred during user creation."}
                  }
              }
        },
    },
    status_code=201
)
async def user_register(
        user_data: UserRegistrationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> UserRegistrationResponseSchema:
    # Check if email exist
    user_result = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    if user_result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")

    # Check default group for new register
    group_result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    group = group_result.scalar_one_or_none()
    if not group:
        raise HTTPException(status_code=500, detail="Default user group not found")

    try:
        # Create a new user
        user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.new_password,
            group_id=group.id
        )
        # New activation token
        token = ActivationTokenModel(user=user)

        db.add_all([user, token])
        await db.commit()
        await db.refresh(user)

        return UserRegistrationResponseSchema.from_orm(user)

    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate",
             response_model=MessageResponseSchema,
             summary="User Account Activation Endpoint",
             description=(
                     "<h3>This endpoint allows users to activate their accounts "
                    "by providing a valid activation token and email. "
                    "The required behavior and response structure are detailed below.</h3>?"
             ),
             responses={
                 200: {"description": "The user's account was successfully activated."},
                 400: {"description": ("If the token is invalid or expired, "
                                       "or if the account is already active."),
                       "content": {
                           "application/json": {
                               "examples": {
                                   "invalid_or_expired": {
                                       "summary": "If the token is invalid or expired",
                                       "value": {"detail": "Invalid or expired activation token."}
                                   },
                                   "already_active": {
                                       "summary": "If the user's account is already active",
                                       "value": {"detail": "User account is already active."}
                                   }
                               }
                           }
                       }
                 }
             },
             status_code=200
             )
async def user_activate(
        activation_data: UserActivationRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:

    token_result = await db.execute(
        select(ActivationTokenModel)
        .where(
            ActivationTokenModel.token == activation_data.token
        )
    )
    token = token_result.scalar_one_or_none()

    # Validate token is not found or expired: BaseSecurityError
    if not token or token.user.email != activation_data.email:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    # The user account is already active
    if token.user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    # Set is_active to True for current user
    user = token.user
    user.is_active = True

    # Delete this activation token if  successful activation
    if user.is_active:
        await db.delete(token)
    await db.commit()

    return MessageResponseSchema(message="User account activated successfully.")


@router.post(
    "/password-reset/request",
    response_model=MessageResponseSchema,
    summary="User Password Reset Token Request Endpoint",
    description=("<h3>This endpoint allows users to request a new_password reset token. "
                 "The endpoint ensures that no sensitive user information is leaked "
                 "while providing a mechanism to reset passwords securely.</h3>"),
    responses={
        200: {"description": "If you are registered, you will receive an email with instructions."}
    },
    status_code=200
)
async def create_reset_pwd_token(
        user_data: PasswordResetRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:

    res = MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )

    user_result = await db.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    user = user_result.scalar_one_or_none()

    # Verify the user's existence and active status.
    if not user or not user.is_active:
        return res

    # Delete any existing tokens and generate new for this user.
    old_token = user.password_reset_token
    if old_token:
        await db.delete(old_token)

    new_token = PasswordResetTokenModel(user=user)

    # save to DB
    db.add(new_token)
    await db.commit()
    await db.refresh(new_token)  # token for send on email of user

    return res


@router.post(
    "/reset-password/complete",
    response_model=MessageResponseSchema,
    summary="Password Reset Completion Endpoint",
    description=("<h3>This endpoint allows users to reset "
                 "their new_password using a valid new_password reset token.</h3>"),
    responses={
        200: {"description": "Password reset successfully."},
        400: {"description": ("The provided email, token, or "
                              "new_password is invalid, or the token has expired."),
              "content": {
                  "application/json": {
                      "examples": {
                          "invalid_token": {
                              "summary": "Invalid Token",
                              "value": {"detail": "Invalid email or token."}
                          },
                          "expired_token": {
                              "summary": "Expired Token",
                              "value": {"detail": "Invalid email or token."}
                          }
                      },
                  }
              }
        },
        500: {
            "description": "An unexpected error occurred while resetting the new_password.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while resetting the new_password."}
                }
            }
        }
    },
    status_code=200
)
async def completion_reset_password(
        reset_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
) -> MessageResponseSchema:
    # Validate the token expiration using a timezone-aware comparison
    token_result = await db.execute(
        select(PasswordResetTokenModel)
        .options(joinedload(PasswordResetTokenModel.user))
        .where(PasswordResetTokenModel.token == reset_data.token)
    )
    token = token_result.scalar_one_or_none()

    if not token or not token.user or token.user.email != reset_data.email or not token.user.is_active:
        if token:
            await db.delete(token)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if token.expires_at < datetime.now(timezone.utc):
        await db.delete(token)
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    # Use proper database transaction handling to prevent partial updates.
    try:
        user = token.user
        user.password = reset_data.new_password

        await db.delete(token)
        await db.commit()
        await db.refresh(user)
        return MessageResponseSchema(message="Password reset successfully.")
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the new_password.")


@router.post(
    "/login",
    response_model=UserLoginResponseSchema,
    summary="User Login Endpoint",
    description=("<h3> an endpoint that authenticates a user based on "
                 "their email and password, generates access and refresh "
                 "tokens upon successful login, and stores the refresh "
                 "token in the database.</h3>"),
    responses={
        201: {"description": (
                "access_token: A JWT used for accessing protected resources."
                "refresh_token: A JWT used to refresh the access token."
                "token_type: Specifies the type of token (bearer).")
        },
        401: {
            "description": "Occurs when the email or password is invalid.",
            "content": {
                "application/json": {
                    "example": {"detail": "Invalid email or password."}
                }
            }
        },
        403: {
            "description": "Occurs when the user's account is not activated.",
            "content": {
                "application/json": {
                    "example": {"detail": "User account is not activated."}
                }
            }
        },
        500: {
            "description": "Occurs when there is an unexpected database error.",
            "content": {
                "application/json": {
                    "example": {"detail": "An error occurred while processing the request."}
                }
            }
        }
    },
    status_code=201
)
async def user_login(
        user_data: UserLoginRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        settings: BaseAppSettings = Depends(get_settings),
        db: AsyncSession = Depends(get_db)
) -> UserLoginResponseSchema:
    # Get User by email
    user_result = await db.execute(
        select(UserModel)
        .where(UserModel.email == user_data.email)
    )
    user = user_result.scalar_one_or_none()

    # validate password for this user
    if not user or not user.verify_password(user_data.new_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    # check is_activated this user
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    try:
        data = {"sub": str(user.id)}
        new_access_token = jwt_manager.create_access_token(data=data)

        new_refresh_token = jwt_manager.create_refresh_token(
            data=data,
            expires_delta=timedelta(days=settings.LOGIN_TIME_DAYS)
        )
        save_token = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=int(settings.LOGIN_TIME_DAYS),
            token=str(new_refresh_token)
        )
        db.add(save_token)
        await db.commit()
        await db.refresh(user)

        return UserLoginResponseSchema(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer"
        )

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while processing the request."
        )


@router.post(
    "/refresh",
    response_model=TokenRefreshResponseSchema,
    summary="Access Token Refresh Endpoint",
    description=("<h3>This endpoint allows users to "
                 "refresh their access token by "
                 "providing a valid refresh token.</h3>"),
    responses={
        200: {"access_token": "new_access_token"},
        400: {"description": "The provided refresh token is invalid or expired.",
              "content": {"application/json": {
                      "example": {"detail": "Token has expired."}}}},
        401: {"description": "The provided refresh token does not exist in the database",
              "content": {"application/json": {
                          "example": {"detail": "Refresh token not found."}}}},
        404: {"description": "The user associated with the refresh token does not exist.",
              "content": {"application/json": {
                  "example": {"detail": "User not found."}}}}
    },
    status_code=200
)
async def refresh_access_token(
        refresh_token_data: TokenRefreshRequestSchema,
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
        db: AsyncSession = Depends(get_db)
) -> TokenRefreshResponseSchema:
    raw_token = refresh_token_data.refresh_token
    # Validated refresh token
    try:
        jwt_manager.decode_refresh_token(raw_token)
    except TokenExpiredError as e:
        try:
            result = await db.execute(
                select(RefreshTokenModel)
                .where(RefreshTokenModel.token == raw_token)
            )
            db_refresh_token = result.scalar_one_or_none()

            if db_refresh_token:
                await db.delete(db_refresh_token)
                await db.commit()

        except SQLAlchemyError:
            pass

        raise HTTPException(status_code=400, detail=str(e))

    except BaseSecurityError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        result = await db.execute(
            select(RefreshTokenModel)
            .options(joinedload(RefreshTokenModel.user))
            .where(RefreshTokenModel.token == raw_token)
        )
        db_refresh_token = result.scalar_one_or_none()

        if not db_refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token not found.")

        user = db_refresh_token.user
        if not user or not user.is_active:
            raise HTTPException(status_code=404, detail="User not found.")

        now = datetime.now(timezone.utc)
        if db_refresh_token.expires_at < now:
            await db.delete(db_refresh_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Token has expired.")

        payload = jwt_manager.decode_refresh_token(raw_token)
        sub = payload.get("sub")
        if sub is None:
            await db.delete(db_refresh_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Token has expired.")

        if str(sub) not in (str(user.id), str(user.email)):
            await db.delete(db_refresh_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Token has expired.")

        # Generating new access token for this user
        new_access_token = jwt_manager.create_access_token(data={"sub": str(user.id)})

        return TokenRefreshResponseSchema(access_token=new_access_token)

    except SQLAlchemyError as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
