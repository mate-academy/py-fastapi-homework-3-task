import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt, JWTError, ExpiredSignatureError

from src.exceptions import TokenExpiredError, InvalidTokenError
from src.security.interfaces import JWTAuthManagerInterface

logger = logging.getLogger(__name__)


class JWTAuthManager(JWTAuthManagerInterface):
    """
    A manager for creating, decoding, and verifying JWT access and refresh tokens.
    """

    _ACCESS_KEY_TIMEDELTA_MINUTES = 10
    _REFRESH_KEY_TIMEDELTA_MINUTES = 60 * 24 * 7
    _ACTIVATION_KEY_TIMEDELTA_MINUTES = 60

    def __init__(self, secret_key_access: str, secret_key_refresh: str, algorithm: str):
        """
        Initialize the manager with secret keys and algorithm for token operations.
        """
        self._secret_key_access = secret_key_access
        self._secret_key_refresh = secret_key_refresh
        self._algorithm = algorithm

    def _create_token(self, data: dict, secret_key: str, expires_delta: timedelta) -> str:
        """
        Helper function to create a JWT token with a specified expiration time.
        """
        try:
            to_encode = data.copy()
            expire = datetime.utcnow() + expires_delta
            to_encode.update({"exp": expire})
            token = jwt.encode(to_encode, secret_key, algorithm=self._algorithm)
            logger.debug(f"Created token: {token}")
            return token
        except Exception as e:
            logger.error(f"Error creating token: {str(e)}")
            raise

    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a new access token with a default or specified expiration time.
        """
        expires_delta = expires_delta or timedelta(minutes=self._ACCESS_KEY_TIMEDELTA_MINUTES)
        return self._create_token(data, self._secret_key_access, expires_delta)

    def create_refresh_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a new refresh token with a default or specified expiration time.
        """
        expires_delta = expires_delta or timedelta(minutes=self._REFRESH_KEY_TIMEDELTA_MINUTES)
        return self._create_token(data, self._secret_key_refresh, expires_delta)

    def decode_access_token(self, token: str) -> dict:
        """
        Decode and validate an access token.
        """
        try:
            return jwt.decode(token, self._secret_key_access, algorithms=[self._algorithm])
        except ExpiredSignatureError:
            logger.warning(f"Access token expired: {token}")  # Log the expiry
            raise TokenExpiredError
        except JWTError as e:
            logger.error(f"Invalid access token: {e}")
            raise InvalidTokenError

    def decode_refresh_token(self, token: str) -> dict:
        """
        Decode and validate a refresh token, returning the token's data.
        """
        try:
            return jwt.decode(token, self._secret_key_refresh, algorithms=[self._algorithm])
        except ExpiredSignatureError:
            logger.warning(f"Refresh token expired: {token}")
            raise TokenExpiredError
        except JWTError as error:
            logger.error(f"Invalid refresh token: {error}")
            raise InvalidTokenError

    def verify_refresh_token_or_raise(self, token: str) -> None:
        """
        Verify a refresh token and raise an error if it's invalid or expired.
        """
        self.decode_refresh_token(token)

    def verify_access_token_or_raise(self, token: str) -> None:
        """
        Verify an access token and raise an error if it's invalid or expired.
        """
        self.decode_access_token(token)


def create_activation_token(user_id: int, secret_key: str, algorithm: str) -> str:
    """
    Create an activation token for a user, typically used for email verification.
    This will be a JWT token with a short expiration time.
    """
    try:
        expire = datetime.utcnow() + timedelta(minutes=JWTAuthManager._ACTIVATION_KEY_TIMEDELTA_MINUTES)
        to_encode = {"sub": str(user_id), "exp": expire}
        token = jwt.encode(to_encode, secret_key, algorithm=algorithm)
        logger.debug(f"Created activation token: {token}")
        return token
    except Exception as e:
        logger.error(f"Error creating activation token: {str(e)}")
        raise


def create_password_reset_token(user_id: int, secret_key: str, algorithm: str) -> str:
    """
    Create a password reset token for a user, with a short expiration time.
    """
    try:
        expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode = {"sub": str(user_id), "exp": expire}
        token = jwt.encode(to_encode, secret_key, algorithm=algorithm)
        logger.debug(f"Created password reset token for user {user_id}")
        return token
    except Exception as e:
        logger.error(f"Error creating password reset token: {str(e)}")
        raise
