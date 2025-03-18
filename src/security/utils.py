import hashlib
import secrets
import random
import string
from datetime import datetime, timedelta
from database import UserModel, ActivationTokenModel, PasswordResetTokenModel, RefreshTokenModel
from database.models.email_service import send_email


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Returns:
        str: Securely generated token.
    """
    return secrets.token_urlsafe(length)


def generate_activation_token() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=32))


def send_reset_email(email: str) -> None:
    send_email(email, "Password Reset", "Follow this link to reset your password.")
