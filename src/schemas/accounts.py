from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators
from schemas.examples.accounts import (
    user_registration_request_schema_example,
    user_registration_response_schema_example, user_activate_request_schema_example,
    user_request_reset_password_schema_example, request_message_schema_example,
    user_request_reset_password_completed_schema_example, user_request_login_schema_example,
    user_response_login_schema_example, user_request_refresh_schema_example, user_response_refresh_schema_example,
)


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_registration_request_schema_example
            ]
        }
    }

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: EmailStr) -> EmailStr:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_registration_response_schema_example
            ]
        }
    }


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_activate_request_schema_example
            ]
        }
    }


class MessageResponseSchema(BaseModel):
    message: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                request_message_schema_example
            ]
        }
    }


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_request_reset_password_schema_example
            ]
        }
    }


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_request_reset_password_completed_schema_example
            ]
        }
    }


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_request_login_schema_example
            ]
        }
    }


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_response_login_schema_example
            ]
        }
    }


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_request_refresh_schema_example
            ]
        }
    }


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_response_refresh_schema_example
            ]
        }
    }
