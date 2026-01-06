import datetime
import secrets


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Returns:
        str: Securely generated token.
    """
    return secrets.token_urlsafe(length)


async def check_token_is_valid(token: str, expected_token) -> bool:

    if token is None or expected_token is None:
        return False

    expires_at_utc = expected_token.expires_at

    if expires_at_utc.tzinfo is None:
        expires_at_utc = expires_at_utc.replace(tzinfo=datetime.timezone.utc)

    not_expired = expires_at_utc > datetime.datetime.now(datetime.timezone.utc)
    token_matches = secrets.compare_digest(token, expected_token.token)

    is_valid = not_expired and token_matches

    return is_valid
