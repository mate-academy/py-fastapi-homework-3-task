from datetime import datetime, timedelta, timezone
import secrets
from typing import cast

from exceptions import TokenExpiredError, InvalidTokenError
from database.models.accounts import ActivationTokenModel


class ActivationTokenManager:

    _DEFAULT_EXPIRES_DAYS = 1

    def __init__(self, expires_days: int | None = None):
        self._expires_days = expires_days or self._DEFAULT_EXPIRES_DAYS

    def create_token(self) -> tuple[str, datetime]:
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(days=self._expires_days)
        return token, expires_at

    def verify_token(self, token: str, token_obj: ActivationTokenModel | None, user_id: int) -> bool:
        return not (
            token_obj is None
            or token_obj.token != token
            or token_obj.user_id != user_id
            or (
                cast(
                    datetime,
                    token_obj.expires_at
                ).replace(tzinfo=timezone.utc)
                < datetime.now(timezone.utc)
            )
        )

    def verify_token_or_raise(self, token: str, token_obj: ActivationTokenModel | None) -> None:
        if token_obj is None:
            raise InvalidTokenError("Activation token not found.")

        if token_obj.token != token:
            raise InvalidTokenError("Invalid activation token.")

        if token_obj.expires_at < datetime.now(timezone.utc):
            raise TokenExpiredError("Activation token expired.")


activation_token_manager = ActivationTokenManager()
