from datetime import datetime, timezone

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager

from config import BaseAppSettings
from database import UserModel, UserGroupModel, UserGroupEnum, ActivationTokenModel, PasswordResetTokenModel, \
    RefreshTokenModel
from exceptions import TokenExpiredError, InvalidTokenError, TokenNotFoundError, UserWithEmailAlreadyExistsError, \
    UserAlreadyActiveError, UserNotFoundError, \
    UserNotActivatedError, InvalidCredentialsError
from schemas import UserRegistrationRequestSchema, UserActivationRequestSchema, PasswordResetRequestSchema, \
    PasswordResetCompleteRequestSchema, UserLoginRequestSchema, TokenRefreshRequestSchema
from security.interfaces import JWTAuthManagerInterface


async def _get_user_by_email(
        db_session: AsyncSession,
        email: str,
):
    statement_user = (
        select(UserModel)
        .where(UserModel.email == email)
    )
    return await db_session.scalar(statement_user)


async def _get_user_by_id(
        db_session: AsyncSession,
        user_id: int,
):
    statement_user = (
        select(UserModel)
        .where(UserModel.id == user_id)
    )
    return await db_session.scalar(statement_user)


async def _get_role_user(
        db_session: AsyncSession
):
    statement = (
        select(UserGroupModel)
        .where(UserGroupModel.name == UserGroupEnum.USER)
    )
    return await db_session.scalar(statement)


def _verify_token_is_expired(expires_at: datetime) -> bool:
    return expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)


async def create_user(
        db_session: AsyncSession,
        create_user_data: UserRegistrationRequestSchema
):
    user = await _get_user_by_email(db_session=db_session, email=create_user_data.email)
    if user is not None:
        raise UserWithEmailAlreadyExistsError()

    role_user = await _get_role_user(db_session=db_session)
    user = UserModel.create(
        email=create_user_data.email,
        raw_password=create_user_data.password,
        group_id=role_user.id,
    )
    db_session.add(user)
    await db_session.flush()

    activation_token = ActivationTokenModel(
        user_id=user.id,
    )
    db_session.add(activation_token)
    await db_session.commit()
    await db_session.refresh(user)
    return user


async def activate_user(
        db_session: AsyncSession,
        activate_data: UserActivationRequestSchema
):
    statement_token = (
        select(ActivationTokenModel)
        .join(ActivationTokenModel.user)
        .where(
            UserModel.email == activate_data.email,
            ActivationTokenModel.token == activate_data.token,
        )
        .options(contains_eager(ActivationTokenModel.user))
    )
    token_from_db = await db_session.scalar(statement_token)
    if token_from_db is None:
        raise TokenNotFoundError()
    if _verify_token_is_expired(token_from_db.expires_at):
        raise TokenExpiredError()

    user = token_from_db.user
    if user.is_active:
        raise UserAlreadyActiveError()

    user.is_active = True
    await db_session.delete(token_from_db)
    await db_session.commit()


async def create_reset_password_token(
        db_session: AsyncSession,
        data: PasswordResetRequestSchema
):
    user_from_db = await _get_user_by_email(db_session=db_session, email=data.email)
    if user_from_db is None:
        raise UserNotFoundError()
    if not user_from_db.is_active:
        raise UserNotActivatedError()

    statement_delete = (
        delete(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user_from_db.id)
    )
    await db_session.execute(statement_delete)

    new_reset_token = PasswordResetTokenModel(
        user_id=user_from_db.id,
    )
    db_session.add(new_reset_token)
    await db_session.commit()


async def complete_reset_password(
        db_session: AsyncSession,
        data: PasswordResetCompleteRequestSchema
):
    user_from_db = await _get_user_by_email(db_session=db_session, email=data.email)
    if user_from_db is None:
        raise UserNotFoundError()
    if not user_from_db.is_active:
        raise UserNotActivatedError()

    reset_token_from_db = await db_session.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user_from_db.id))

    if reset_token_from_db is None:
        raise TokenNotFoundError()

    await db_session.delete(reset_token_from_db)

    if reset_token_from_db.token != data.token:
        await db_session.commit()
        raise InvalidTokenError()
    if _verify_token_is_expired(reset_token_from_db.expires_at):
        await db_session.commit()
        raise TokenExpiredError()

    user_from_db.password = data.password
    db_session.add(user_from_db)
    await db_session.commit()


async def login_user(
        db_session: AsyncSession,
        data: UserLoginRequestSchema,
        jwt_manager: JWTAuthManagerInterface,
        settings: BaseAppSettings,
) -> tuple[str, str]:
    user = await _get_user_by_email(db_session=db_session, email=data.email)
    if user is None or not user.verify_password(data.password):
        raise InvalidCredentialsError()
    if not user.is_active:
        raise UserNotActivatedError()

    payload = {"user_id": user.id}
    access_token = jwt_manager.create_access_token(payload)
    refresh_token = jwt_manager.create_refresh_token(payload)

    db_session.add(
        RefreshTokenModel.create(
            user_id=user.id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=refresh_token,
        )
    )
    await db_session.commit()
    return access_token, refresh_token


async def refresh_access_token_for_user(
        db_session: AsyncSession,
        jwt_manager: JWTAuthManagerInterface,
        data: TokenRefreshRequestSchema
):
    user_id_from_token = jwt_manager.decode_refresh_token(data.refresh_token)["user_id"]

    token_from_db = await db_session.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == data.refresh_token))
    if token_from_db is None:
        raise TokenNotFoundError()

    user_from_db = await _get_user_by_id(db_session=db_session, user_id=user_id_from_token)
    if user_from_db is None:
        raise UserNotFoundError()

    return jwt_manager.create_access_token({"user_id": user_from_db.id})
