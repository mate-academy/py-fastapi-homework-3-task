from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators
from schemas.examples.accounts import (
    login_request_example,
    login_response_example,
    password_reset_complete_request_example,
    password_reset_complete_response_example,
    password_reset_request_example,
    password_reset_response_example,
    refresh_access_token_request_example,
    refresh_access_token_response_example,
    user_activation_request_example,
    user_activation_response_example,
    user_registration_request_example,
    user_registration_response_example,
)


class UserRegistrationRequestSchema(BaseModel):
    """
    Schema for user registration request.

    This schema defines the structure for user registration data,
    including email and password validation.

    Attributes:
        email (EmailStr): User's email address (validated format).
        password (str): User's password (must meet strength requirements).
    """

    email: EmailStr
    password: str

    model_config = {"json_schema_extra": {"examples": [user_registration_request_example]}}

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    """
    Schema for user registration response.

    This schema defines the structure for the response after successful
    user registration.

    Attributes:
        id (int): The unique identifier of the registered user.
        email (EmailStr): The registered user's email address.
    """

    id: int
    email: EmailStr

    model_config = {"from_attributes": True, "json_schema_extra": {"examples": [user_registration_response_example]}}


class UserActivationRequestSchema(BaseModel):
    """
    Schema for user account activation request.

    This schema defines the structure for activating a user account
    using their email and activation token.

    Attributes:
        email (EmailStr): The email address of the user to activate.
        token (str): The activation token sent to the user's email.
    """

    email: EmailStr
    token: str

    model_config = {"json_schema_extra": {"examples": [user_activation_request_example]}}


class UserActivationResponseSchema(BaseModel):
    """
    Schema for user activation response.

    This schema defines the structure for the response after
    successful account activation.

    Attributes:
        message (str): A success message confirming the account activation.
    """

    message: str

    model_config = {"json_schema_extra": {"examples": [user_activation_response_example]}}


class PasswordResetRequestSchema(BaseModel):
    """
    Schema for password reset request.

    This schema defines the structure for initiating a password reset
    process using the user's email.

    Attributes:
        email (EmailStr): The email address of the user requesting a password reset.
    """

    email: EmailStr

    model_config = {"json_schema_extra": {"examples": [password_reset_request_example]}}


class PasswordResetResponseSchema(BaseModel):
    """
    Schema for password reset request response.

    This schema defines the structure for the response after initiating
    a password reset request. The message is intentionally vague for security.

    Attributes:
        message (str): A generic message about password reset instructions.
    """

    message: str

    model_config = {"json_schema_extra": {"examples": [password_reset_response_example]}}


class PasswordResetCompleteRequestSchema(BaseModel):
    """
    Schema for completing password reset.

    This schema defines the structure for completing the password reset
    process with a new password.

    Attributes:
        email (EmailStr): The user's email address.
        token (str): The password reset token received via email.
        password (str): The new password (must meet strength requirements).
    """

    email: EmailStr
    token: str
    password: str

    model_config = {"json_schema_extra": {"examples": [password_reset_complete_request_example]}}

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class PasswordResetCompleteResponseSchema(BaseModel):
    """
    Schema for password reset completion response.

    This schema defines the structure for the response after
    successfully resetting the password.

    Attributes:
        message (str): A success message confirming the password reset.
    """

    message: str

    model_config = {"json_schema_extra": {"examples": [password_reset_complete_response_example]}}


class LoginRequestSchema(BaseModel):
    """
    Schema for user login request.

    This schema defines the structure for user authentication data
    required for logging in.

    Attributes:
        email (EmailStr): The user's email address.
        password (str): The user's password.
    """

    email: EmailStr
    password: str

    model_config = {"json_schema_extra": {"examples": [login_request_example]}}


class LoginResponseSchema(BaseModel):
    """
    Schema for login response.

    This schema defines the structure for the response after successful
    user authentication, including access and refresh tokens.

    Attributes:
        access_token (str): JWT access token for API authorization.
        refresh_token (str): JWT refresh token for obtaining new access tokens.
        token_type (str): The type of token (default: "bearer").
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {"json_schema_extra": {"examples": [login_response_example]}}


class RefreshTokenRequestSchema(BaseModel):
    """
    Schema for token refresh request.

    This schema defines the structure for requesting a new access token
    using a refresh token.

    Attributes:
        refresh_token (str): The JWT refresh token obtained during login.
    """

    refresh_token: str

    model_config = {"json_schema_extra": {"examples": [refresh_access_token_request_example]}}


class RefreshTokenResponseSchema(BaseModel):
    """
    Schema for token refresh response.

    This schema defines the structure for the response after successfully
    refreshing an access token.

    Attributes:
        access_token (str): The new JWT access token.
    """

    access_token: str

    model_config = {"json_schema_extra": {"examples": [refresh_access_token_response_example]}}
