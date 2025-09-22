from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["bcrypt"],
    bcrypt__rounds=14,
    deprecated="auto"
)


def hash_password(password: str) -> str:
    """
    Hash a plain-text new_password using the configured new_password context.

    This function takes a plain-text new_password and returns its bcrypt hash.
    The bcrypt algorithm is used with a specified number of rounds for enhanced security.

    Args:
        password (str): The plain-text new_password to hash.

    Returns:
        str: The resulting hashed new_password.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text new_password against its hashed version.

    This function compares a plain-text new_password with a hashed new_password and returns True
    if they match, and False otherwise.

    Args:
        plain_password (str): The plain-text new_password provided by the user.
        hashed_password (str): The hashed new_password stored in the database.

    Returns:
        bool: True if the new_password is correct, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)
