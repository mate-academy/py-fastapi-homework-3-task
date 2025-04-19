import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from starlette.responses import JSONResponse

from config import get_jwt_auth_manager
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas import TokenRefreshRequestSchema, TokenRefreshResponseSchema
from schemas.accounts import (UserRegistrationResponseSchema, UserRegistrationRequestSchema,
                              UserActivationRequestSchema,
                              MessageResponseSchema, PasswordResetRequestSchema, PasswordResetCompleteRequestSchema,
                              UserLoginRequestSchema,
                              UserLoginResponseSchema)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post("/register/",
             response_model=UserRegistrationResponseSchema,
             status_code=status.HTTP_201_CREATED,
             responses={
                 201: {"description": "User registered successfully"},
                 409: {"description": "A user with the same email already exists."},
                 500: {"description": "An error occurred during user creation."}

             })
async def user_register(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    user_exist = await db.scalar(select(UserModel).where(UserModel.email == user_data.email))
    if user_exist:
        raise HTTPException(status_code=409, detail=f"A user with this email {user_data.email} already exists.")
    try:

        group_user = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == user_data.group))
        if not group_user:
            group_user = UserGroupModel(
                name=user_data.group,
            )
            db.add(group_user)
            await db.flush()
        try:
            user_db = UserModel.create(
                email=user_data.email,
                raw_password=user_data.password,
                group_id=group_user.id
            )
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))

        try:
            db.add(user_db)

            user_activate_token = ActivationTokenModel(user=user_db)
            db.add(user_activate_token)

            await db.commit()
            await db.refresh(user_db)
            return user_db
        except ValueError as e:
            await db.rollback()
            raise HTTPException(status_code=422, detail=str(e))

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")


@router.post("/activate/",
             response_model=MessageResponseSchema,
             status_code=status.HTTP_200_OK,
             responses={
                 200: {"message": "User account activated successfully."},
                 400: {"detail": "Invalid or expired activation token."}
             }
             )
async def user_activate(user_data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user_db = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user_db = user_db.scalars().first()
    if not user_db:
        raise HTTPException(status_code=400, detail="User does not exist.")

    if user_db.is_active is True:
        raise HTTPException(status_code=400, detail="User account is already active.")

    activate_token_db = await db.execute(select(ActivationTokenModel)
                                         .where(ActivationTokenModel.user_id == user_db.id))
    activate_token_db = activate_token_db.scalars().first()
    if not activate_token_db:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if (user_data.token != activate_token_db.token) or (activate_token_db.expires_at < datetime.now()):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user_db.is_active = True
    db.add(user_db)

    await db.delete(activate_token_db)

    await db.commit()
    await db.refresh(user_db)

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/",
             status_code=status.HTTP_200_OK,
             responses={
                 200: {"message": "If you are registered, you will receive an email with instructions."}
             })
async def reset_password_request(user_data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user = await db.execute(select(UserModel)
                            .where(UserModel.email == user_data.email, UserModel.is_active.is_(True)))
    user = user.scalars().first()

    if user:
        password_reset_tokens = await db.execute(
            select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        password_reset_tokens = password_reset_tokens.scalars().all()
        if password_reset_tokens:
            for token in password_reset_tokens:
                await db.delete(token)
        await db.commit()

        new_pass_reset_token = PasswordResetTokenModel(user_id=user.id)
        db.add(new_pass_reset_token)
        await db.commit()
        await db.refresh(new_pass_reset_token)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "If you are registered, you will receive an email with instructions."}
    )


@router.post("/reset-password/complete/",
             status_code=status.HTTP_200_OK,
             responses={
                 200: {"message": "Password reset successfully."},
                 400: {"detail": "Invalid email or token."},
                 500: {"detail": "An error occurred while resetting the password."}
             })
async def reset_password_complete(
        user_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await db.execute(select(UserModel).where(UserModel.email == user_data.email))
    user = user.scalars().first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    passwd_reset_token = await db.execute(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    passwd_reset_token = passwd_reset_token.scalars().first()

    if passwd_reset_token is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        if user_data.token != passwd_reset_token.token:
            await db.delete(passwd_reset_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        if passwd_reset_token.expires_at < datetime.now():
            await db.delete(passwd_reset_token)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")

        user.password = user_data.password
        await db.delete(passwd_reset_token)
        await db.commit()
        return {"message": "Password reset successfully."}

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=status.HTTP_201_CREATED)
async def login_user(user_data: UserLoginRequestSchema,
                     db: AsyncSession = Depends(get_db),
                     jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)):
    user = await db.execute(select(UserModel)
                            .where(UserModel.email == user_data.email))
    user = user.scalars().first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if user.verify_password(user_data.password) is False:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if user.is_active is False:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    payload_access = {
        "user_id": user.id,
        "email": user.email,
    }
    access_token = jwt_manager.create_access_token(payload_access)

    payload_refresh = {
        "user_id": user.id,
        "jti": str(uuid.uuid4()),

    }
    refresh_token = jwt_manager.create_refresh_token(payload_refresh)

    token_db = RefreshTokenModel.create(user_id=user.id, token=refresh_token, days_valid=3)
    db.add(token_db)
    try:
        await db.commit()
        await db.refresh(token_db)

        return UserLoginResponseSchema(access_token=access_token,
                                       refresh_token=refresh_token)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token_user(user_data: TokenRefreshRequestSchema,
                             db: AsyncSession = Depends(get_db),
                             jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
                             ):
    try:
        user_payload = jwt_manager.decode_refresh_token(user_data.refresh_token)
    except TokenExpiredError as e:
        raise HTTPException(status_code=400, detail=str(e))

    except InvalidTokenError as e:
        raise HTTPException(status_code=400, detail=str(e))

    db_token = await db.execute(select(RefreshTokenModel).where(RefreshTokenModel.token == user_data.refresh_token))
    db_token = db_token.scalars().first()
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = int(user_payload.get("user_id"))
    if user_id is not None:
        user_db = await db.execute(select(UserModel).where(UserModel.id == user_id))
        user_db = user_db.scalars().first()
        if not user_db:
            raise HTTPException(status_code=404, detail="User not found.")

    db_user = await db.execute(select(UserModel).where(UserModel.id == user_id))
    db_user = db_user.scalars().first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found.")

    payload = {
        "user_id": db_user.id,
        "email": db_user.email}

    access_token = jwt_manager.create_access_token(payload)

    return TokenRefreshResponseSchema(access_token=access_token)
