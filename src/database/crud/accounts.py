from datetime import timedelta, datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import insert, select, update, func, delete
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import contains_eager

from exceptions import TokenExpiredError, InvalidTokenError
from schemas import (
    UserRegistrationRequestSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
)
from database.models.accounts import (
    UserModel,
    UserGroupModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)  # I don't know if there is a way to do it like in Django, get_user_model()
from security.token_manager import JWTAuthManagerInterface

STANDARD_GROUP = "USER"


async def insert_activation_token(
    db: AsyncSession, token: str, timedelta: timedelta, user: UserModel
) -> bool:
    expires_at = datetime.now(timezone.utc) + timedelta
    try:
        act_res = await db.execute(
            insert(ActivationTokenModel)
            .values(token=token, expires_at=expires_at, user_id=user.id)
            .returning(ActivationTokenModel.token)
        )
        return act_res.scalar_one_or_none() == token
    except (IntegrityError, SQLAlchemyError):
        return False


async def register_new_user(
    db: AsyncSession, user: UserRegistrationRequestSchema
) -> Optional[UserModel]:
    user_dump = user.model_dump(exclude={"password"})
    user_dump["raw_password"] = user.password
    user_dump["group_id"] = await db.scalar(
        select(UserGroupModel.id).where(UserGroupModel.name == STANDARD_GROUP)
    )
    raw_user = UserModel.create(**user_dump)
    db.add(raw_user)
    try:
        await db.flush()
        return raw_user
    except (IntegrityError, SQLAlchemyError):
        return None


async def delete_activation_token(db: AsyncSession, token: str, email: str) -> bool:
    subquery = select(UserModel.id).where(UserModel.email == email).scalar_subquery()

    stmt = delete(ActivationTokenModel).where(
        ActivationTokenModel.token == token,
        ActivationTokenModel.expires_at > datetime.now(timezone.utc),
        ActivationTokenModel.user_id == subquery,
    )
    res = await db.execute(stmt)
    return res.rowcount == 1


async def set_user_active_status(db: AsyncSession, email: str) -> bool:
    res = await db.execute(
        update(UserModel)
        .where(UserModel.email == email, UserModel.is_active == False)  # noqa E712
        .values(is_active=True)
    )
    return res.rowcount == 1


async def delete_all_password_reset_tokens(
    db: AsyncSession, pass_request: PasswordResetRequestSchema
) -> bool:
    subquery = (
        select(UserModel.id)
        .where(UserModel.email == pass_request.email)
        .scalar_subquery()
    )

    stmt = delete(PasswordResetTokenModel).where(
        PasswordResetTokenModel.user_id == subquery,
    )
    res = await db.execute(stmt)
    return res.rowcount >= 1


async def insert_password_reset_token(
    db: AsyncSession,
    pass_request: PasswordResetRequestSchema,
    token: str,
    timedelta_: timedelta,
) -> bool:
    subquery = (
        select(UserModel.id)
        .where(
            UserModel.email == pass_request.email,
            UserModel.is_active == True,  # noqa E712
        )
        .scalar_subquery()
    )

    stmt = insert(PasswordResetTokenModel).values(
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta_,
        user_id=subquery,
    )
    res = await db.execute(stmt)
    return res.rowcount == 1


async def delete_password_reset_token(
    db: AsyncSession, pass_req_complete: PasswordResetCompleteRequestSchema
) -> Tuple[Optional[PasswordResetTokenModel], bool]:
    subquery = (
        select(UserModel.id)
        .where(
            UserModel.email == pass_req_complete.email,
            UserModel.is_active.is_(True),
        )
        .scalar_subquery()
    )
    select_stmt = (
        delete(PasswordResetTokenModel)
        .where(
            PasswordResetTokenModel.user_id == subquery,
        )
        .returning(PasswordResetTokenModel)
    )
    pass_reset_model = (await db.execute(select_stmt)).scalar_one_or_none()
    if pass_reset_model and (
        pass_reset_model.expires_at.replace(tzinfo=timezone.utc)
        < datetime.now(timezone.utc)
        or pass_reset_model.token != pass_req_complete.token
    ):
        return pass_reset_model, True
    return pass_reset_model, False


async def get_user_by_email(
    db: AsyncSession, email: str = None, password: str = None, user_id: str = None
) -> Optional[UserModel]:
    if user_id:
        user = await db.get(UserModel, user_id)
    else:
        user = await db.scalar(select(UserModel).where(UserModel.email == email))
    if password and user:
        if user.verify_password(password):
            return user
    else:
        return user


async def change_password_for_user(
    db: AsyncSession, pass_req_complete: PasswordResetCompleteRequestSchema
) -> bool:
    raw_user = await get_user_by_email(db=db, email=pass_req_complete.email)
    if raw_user:
        raw_user.password = pass_req_complete.password
        db.add(raw_user)
    return bool(raw_user)


async def insert_refresh_token(
    db: AsyncSession, token: str, days_to_expire: int, user: UserModel
) -> RefreshTokenModel:
    token_ = RefreshTokenModel.create(
        token=token, days_valid=days_to_expire, user_id=user.id
    )
    db.add(token_)
    return token_


async def get_refresh_token_and_join_with_user(
    db: AsyncSession, token: str
) -> Optional[RefreshTokenModel]:
    return await db.scalar(
        select(RefreshTokenModel).where(RefreshTokenModel.token == token)
    )
