import os

from fastapi import HTTPException
from sqlalchemy import select

from database import PasswordResetTokenModel
from security.token_manager import JWTAuthManager


async def remove_token(db, user) -> str:
    user_token_to_remove = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    tokens_to_remove = user_token_to_remove.scalars().all()
    for token in tokens_to_remove:
        await db.delete(token)
    await db.commit()
    return "Done"


def get_jwt_manager() -> JWTAuthManager:
    secret_access = os.getenv("SECRET_KEY_ACCESS") or "SECRET_KEY_ACCESS"
    secret_refresh = os.getenv("SECRET_KEY_REFRESH") or "SECRET_KEY_REFRESH"
    algorithm = os.getenv("JWT_SIGNING_ALGORITHM") or "HS256"
    return JWTAuthManager(secret_access, secret_refresh, algorithm)
