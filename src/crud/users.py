from sqlalchemy.ext.asyncio import AsyncSession
from src.database import UserModel, UserGroupEnum, ActivationTokenModel, UserGroupModel
from src.schemas import UserRegistrationRequestSchema
from src.security.passwords import hash_password
from src.utils.transactions import transaction_atomic
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from fastapi import status, HTTPException
import secrets


@transaction_atomic
async def create_user(db: AsyncSession, user: UserRegistrationRequestSchema):
    try:
        hashed = hash_password(user.password)
        response = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
        user_group = response.scalar_one_or_none()
        if not user_group:
            user_group = UserGroupModel(name=UserGroupEnum.USER)
            db.add(user_group)
            await db.flush()
        db_user = UserModel(email=user.email,
                            _hashed_password=hashed,
                            group_id=user_group.id)
        db.add(db_user)
        await db.flush()
        token = ActivationTokenModel(
            user_id=db_user.id,
            token=secrets.token_urlsafe(32),
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1))
        )
        db.add(token)
        await db.commit()
        await db.refresh(db_user)
        return db_user
    except Exception:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An error occurred during user creation.")
