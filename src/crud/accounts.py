from datetime import datetime, timezone
from sqlite3 import IntegrityError

from sqlalchemy import select, cast, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from crud.exceptions import UserAlreadyExist, UserDoesNotExist, UserGroupDoesNotExist, UserAlreadyActivated, \
    UserError, UserNotActivated, InvalidPassword
from database.models.accounts import UserModel, UserGroupModel, ActivationTokenModel, PasswordResetTokenModel, \
    RefreshTokenModel
from database.models.accounts import UserGroupEnum
from exceptions import TokenExpiredError, InvalidTokenError

from schemas import UserRegistrationRequestSchema, UserActivationRequestSchema, \
    PasswordResetRequestSchema, PasswordResetCompleteRequestSchema, UserLoginResponseSchema, UserLoginRequestSchema, \
    TokenRefreshRequestSchema, TokenRefreshResponseSchema
from security.interfaces import JWTAuthManagerInterface


async def _get_user_by_email(db: AsyncSession, user_email: str) -> UserModel:
    user = await db.scalar(
        select(UserModel).where(
            UserModel.email == user_email
        )
    )

    if not user:
        raise UserDoesNotExist("User does not exist")
    return user


async def _get_user_group(db: AsyncSession, name: UserGroupEnum) -> UserGroupModel:
    user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == name))

    if not user_group:
        raise UserGroupDoesNotExist("User group does not exist")

    return user_group


async def register_user(db: AsyncSession, user_data: UserRegistrationRequestSchema) -> UserModel:
    if await db.scalar(
        select(UserModel).where(
            UserModel.email == user_data.email
        )
    ):
        raise UserAlreadyExist("User with this email already exists")

    user_group = await _get_user_group(db, UserGroupEnum.USER)
    new_user = UserModel.create(
        raw_password=user_data.password,
        email=user_data.email,
        group_id=user_group.id
    )

    try:
        db.add(new_user)
        await db.flush()
        await db.refresh(new_user)

        new_db_token = ActivationTokenModel(
            user_id=new_user.id,
            user=new_user
        )
        db.add(new_db_token)
        await db.commit()

        return new_user
    except IntegrityError:
        await db.rollback()
        raise


async def activate_user(db: AsyncSession, user_data: UserActivationRequestSchema):
    user_db = await _get_user_by_email(db, str(user_data.email))
    if user_db.is_active:
        raise UserAlreadyActivated("User already activated")

    token_record = await db.scalar(
        select(ActivationTokenModel).where(ActivationTokenModel.user_id == user_db.id)
    )

    if not token_record:
        raise InvalidTokenError("Token is invalid")

    expires_at = token_record.expires_at.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > expires_at:
        raise TokenExpiredError("Token expired")
    try:
        delete_stmt = (
            delete(ActivationTokenModel).
            where(ActivationTokenModel.user_id == user_db.id)
        )

        await db.execute(delete_stmt)

        user_db.is_active = True

        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise UserError("Some database error occured")


async def password_reset(db: AsyncSession, user_data: PasswordResetRequestSchema):
    try:
        user = await _get_user_by_email(db, user_email=user_data.email)
        if not user.is_active:
            raise UserNotActivated("User is not active")
        reset_token_old = await db.scalar(select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        ))
        try:
            if reset_token_old:
                delete_stmt = (
                    delete(PasswordResetTokenModel).
                    where(PasswordResetTokenModel.user_id == user.id)
                )

                await db.execute(delete_stmt)
            reset_token_new = PasswordResetTokenModel(
                user_id=user.id,
                # user=user
            )

            db.add(reset_token_new)
            await db.commit()
        except IntegrityError:
            await db.rollback()
            pass
    except (UserDoesNotExist, UserNotActivated):
        pass


async def password_reset_complete(db: AsyncSession, user_data: PasswordResetCompleteRequestSchema):
    user = await _get_user_by_email(db, user_email=user_data.email)

    reset_token = await db.scalar(select(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == user.id
    ))

    if not reset_token:
        raise InvalidTokenError("Invalid email or token.")

    if reset_token.token != user_data.token:
        await db.delete(reset_token)
        await db.commit()

        raise InvalidTokenError("Invalid email or token.")

    if not user.is_active:
        raise UserNotActivated("User is not active")

    expires_at = reset_token.expires_at.replace(tzinfo=timezone.utc)
    is_expired = datetime.now(timezone.utc) > expires_at
    if is_expired:
        await db.delete(reset_token)
        await db.commit()
        raise TokenExpiredError("Password reset token is expired")

    try:
        user.password = user_data.password

        await db.delete(reset_token)

        await db.commit()
    except (IntegrityError, SQLAlchemyError):
        await db.rollback()
        raise


async def login_user(db: AsyncSession, user_data: UserLoginRequestSchema,
                     jwt: JWTAuthManagerInterface) -> UserLoginResponseSchema:
    user = await _get_user_by_email(db, user_data.email)
    if not user.verify_password(raw_password=user_data.password):
        raise InvalidPassword

    if not user.is_active:
        raise UserNotActivated

    token_payload = {
        "user_id": user.id,
        "email": user_data.email,
        "password": user_data.password
    }
    new_refresh_token = jwt.create_refresh_token(data=token_payload)
    new_access_token = jwt.create_access_token(data=token_payload)

    new_refresh_token_db = RefreshTokenModel.create(
        user_id=user.id,
        token=new_refresh_token,
        days_valid=30
    )
    try:
        db.add(new_refresh_token_db)
        await db.commit()

        new_refresh_token_db.user_id = user.id
        await db.commit()
        await db.refresh(new_refresh_token_db)

        return UserLoginResponseSchema(
            access_token=new_access_token,
            refresh_token=new_refresh_token
        )
    except (IntegrityError, SQLAlchemyError):
        await db.rollback()
        raise


async def refresh_access_token(db: AsyncSession, token_data: TokenRefreshRequestSchema,
                               jwt: JWTAuthManagerInterface) -> TokenRefreshResponseSchema:
    decoded_token = jwt.decode_refresh_token(token_data.refresh_token)

    refresh_token = await db.scalar(select(RefreshTokenModel).where(
        RefreshTokenModel.user_id == decoded_token.get("user_id")
    ))

    if not refresh_token:
        raise InvalidTokenError("Invalid refresh password token or not found")

    # check if the token is expired
    expires_at = refresh_token.expires_at.replace(tzinfo=timezone.utc)
    is_expired = datetime.now(timezone.utc) > expires_at

    if is_expired:
        raise TokenExpiredError("Refresh token is expired")

    user = await db.get(UserModel, decoded_token.get("user_id"))
    if user is None:
        raise UserDoesNotExist

    # generate access token
    new_access_token = jwt.create_access_token(data=decoded_token)

    return TokenRefreshResponseSchema(
        access_token=new_access_token
    )
