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
    id: int
    email: EmailStr

    model_config = {"from_attributes": True, "json_schema_extra": {"examples": [user_registration_response_example]}}


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {"json_schema_extra": {"examples": [user_activation_request_example]}}


class UserActivationResponseSchema(BaseModel):
    message: str

    model_config = {"json_schema_extra": {"examples": [user_activation_response_example]}}


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = {"json_schema_extra": {"examples": [password_reset_request_example]}}


class PasswordResetResponseSchema(BaseModel):
    message: str

    model_config = {"json_schema_extra": {"examples": [password_reset_response_example]}}


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = {"json_schema_extra": {"examples": [password_reset_complete_request_example]}}

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str

    model_config = {"json_schema_extra": {"examples": [password_reset_complete_response_example]}}


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {"json_schema_extra": {"examples": [login_request_example]}}


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {"json_schema_extra": {"examples": [login_response_example]}}


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str

    model_config = {"json_schema_extra": {"examples": [refresh_access_token_request_example]}}


class RefreshTokenResponseSchema(BaseModel):
    access_token: str

    model_config = {"json_schema_extra": {"examples": [refresh_access_token_response_example]}}
