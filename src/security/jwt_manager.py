from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from fastapi import HTTPException
from security.interfaces import JWTAuthManagerInterface
import os  # Import os for environment variable access


class JWTManager(JWTAuthManagerInterface):
    # FIX 1: Load SECRET_KEY from environment variables for security.
    # Replace the hardcoded insecure value with a variable that should be set securely.
    # For testing, ensure this environment variable is set in the test runner/fixtures.
    SECRET_KEY = os.getenv("SECRET_KEY", "a_very_long_and_secure_default_key_for_testing_only_1234567890")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 60
    REFRESH_TOKEN_EXPIRE_DAYS = 7

    def create_access_token(
        self,
        data: dict,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT access token with expiration and type='access'.
        """
        payload = data.copy()
        expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        payload.update({"exp": expire, "type": "access"})
        return jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

    def create_refresh_token(
        self,
        data: dict,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """
        Create JWT refresh token with expiration and type='refresh'.
        """
        payload = data.copy()
        expire = datetime.now(timezone.utc) + (
            expires_delta or timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS)
        )
        payload.update({"exp": expire, "type": "refresh"})
        return jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

    def decode_access_token(self, token: str) -> dict:
        """
        Decode and validate access token.
        """
        try:
            decoded = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if decoded.get("type") != "access":
                raise HTTPException(status_code=401, detail="Invalid access token type.")
            return decoded
        except jwt.ExpiredSignatureError:
            # Status 401 Unauthorized is correct for an expired access token
            raise HTTPException(status_code=401, detail="Access token has expired.")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid access token.")

    def decode_refresh_token(self, token: str) -> dict:
        """
        Decode and validate refresh token.
        """
        try:
            decoded = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if decoded.get("type") != "refresh":
                raise HTTPException(status_code=401, detail="Invalid refresh token type.")
            return decoded
        except jwt.ExpiredSignatureError:
            # FIX 2: Change status code from 400 to 401 for consistency and standard auth practice.
            # An expired refresh token means the client is unauthorized to refresh.
            raise HTTPException(status_code=401, detail="Refresh token has expired.")
        except jwt.PyJWTError:
            raise HTTPException(status_code=401, detail="Invalid refresh token.")

    def verify_refresh_token_or_raise(self, token: str) -> None:
        """
        Verify refresh token validity or raise HTTPException.
        """
        self.decode_refresh_token(token)

    def verify_access_token_or_raise(self, token: str) -> None:
        """
        Verify access token validity or raise HTTPException.
        """
        self.decode_access_token(token)
