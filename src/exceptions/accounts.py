from fastapi import HTTPException, status


class EmailAlreadyExistsError(HTTPException):
    """Raised when attempting to register with an email that already exists."""

    def __init__(self, detail: str = "Email already registered."):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
        )


class UserGroupNotFoundError(HTTPException):
    """Raised when the user group is not found in the database."""

    def __init__(self, detail: str = "User group not found. Database may not be properly initialized."):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
        )


class InvalidActivationTokenError(HTTPException):
    """Raised when activation token is invalid or expired."""

    def __init__(self, detail: str = "Invalid or expired activation token."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class AccountAlreadyActivatedError(HTTPException):
    """Raised when attempting to activate an already active account."""

    def __init__(self, detail: str = "User account is already activated."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class UserNotFoundError(HTTPException):
    """Raised when user is not found by email or ID."""

    def __init__(self, detail: str = "User not found."):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
        )


class InvalidResetTokenError(HTTPException):
    """Raised when password reset token is invalid or expired."""

    def __init__(self, detail: str = "Invalid or expired reset token."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class InvalidCredentialsError(HTTPException):
    """Raised when email or password is incorrect."""

    def __init__(self, detail: str = "Invalid email or password."):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        )


class AccountNotActivatedError(HTTPException):
    """Raised when user tries to login with inactive account."""

    def __init__(self, detail: str = "User account is not activated."):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
        )


class RefreshTokenNotFoundError(HTTPException):
    """Raised when refresh token does not exist in database."""

    def __init__(self, detail: str = "Refresh token not found."):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
        )


class TokenExpiredError(HTTPException):
    """Raised when JWT token has expired."""

    def __init__(self, detail: str = "Token has expired."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class InvalidTokenError(HTTPException):
    """Raised when JWT token is invalid or malformed."""

    def __init__(self, detail: str = "Invalid token."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
        )


class DatabaseError(HTTPException):
    """Raised for general database errors."""

    def __init__(self, detail: str = "An error occurred while processing the request."):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
        )