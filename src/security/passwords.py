from passlib.context import CryptContext

import bcrypt
from typing import Tuple

pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=14, deprecated="auto")


class PasswordManager:
    """Password hashing and verification manager."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        return bcrypt.checkpw(
            plain_password.encode("utf-8"), hashed_password.encode("utf-8")
        )

    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """Validate password strength."""
        if len(password) < 8:
            return False, "Password must contain at least 8 characters."
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit."
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter."
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lower letter."
        special_chars = "@$!%*?#&"
        if not any(c in special_chars for c in password):
            return (
                False,
                f"Password must contain at least one special character: {special_chars}.",
            )
        return True, ""


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
