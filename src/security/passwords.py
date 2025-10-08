import os
from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select

from security.token_manager import JWTAuthManager

pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=14, deprecated="auto")


SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


async def remove_token(db, user) -> str:
    from database import PasswordResetTokenModel

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


def hash_password(password: str) -> str:
    """
    Hash a plain-text password using the configured password context.

    This function takes a plain-text password and returns its bcrypt hash.
    The bcrypt algorithm is used with a specified number of rounds for enhanced security.

    Args:
        password (str): The plain-text password to hash.

    Returns:
        str: The resulting hashed password.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against its hashed version.

    This function compares a plain-text password with a hashed password and returns True
    if they match, and False otherwise.

    Args:
        plain_password (str): The plain-text password provided by the user.
        hashed_password (str): The hashed password stored in the database.

    Returns:
        bool: True if the password is correct, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)
