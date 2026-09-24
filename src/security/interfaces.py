from abc import ABC, abstractmethod
from datetime import timedelta


class JWTAuthManagerInterface(ABC):
    """
    Interface for JWT Authentication Manager.
    Defines methods for creating, decoding, and verifying JWT tokens.
    """

    @abstractmethod
    def create_access_token(
        self, data: dict, expires_delta: timedelta | None = None
    ) -> str:
        """
        Create a new access token.
        """

    @abstractmethod
    def create_refresh_token(
        self, data: dict, expires_delta: timedelta | None = None
    ) -> str:
        """
        Create a new refresh token.
        """

    @abstractmethod
    def decode_access_token(self, token: str) -> dict:
        """
        Decode and validate an access token.
        """

    @abstractmethod
    def decode_refresh_token(self, token: str) -> dict:
        """
        Decode and validate a refresh token.
        """

    @abstractmethod
    def verify_refresh_token_or_raise(self, token: str) -> None:
        """
        Verify a refresh token or raise an error if invalid.
        """

    @abstractmethod
    def verify_access_token_or_raise(self, token: str) -> None:
        """
        Verify an access token or raise an error if invalid.
        """
