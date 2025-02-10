from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

from schemas.examples.accounts import (
    user_register_schema_example,
    user_register_response_schema_example,
    user_activate_schema_example,
    user_activate_response_schema_example,
    user_password_reset_schema_example,
    user_password_reset_complete_schema_example,
    user_login_response_schema_example,
    token_refresh_response_schema_example,
    token_refresh_schema_example
)

from database.validators.accounts import validate_password_strength, validate_email


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_user_password(cls, value):
        validate_password_strength(value)
        return value

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value):
        validate_email(value)
        return value

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_register_schema_example
            ]
        }
    }


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_register_response_schema_example
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
                user_activate_schema_example
            ]
        }
    }


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_password_reset_schema_example
            ]
        }
    }

    @field_validator("email")
    @classmethod
    def validate_user_email(cls, value):
        validate_email(value)
        return value


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_password_reset_complete_schema_example
            ]
        }
    }

    @field_validator("password")
    @classmethod
    def validate_user_password(cls, value):
        validate_password_strength(value)
        return value


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_login_response_schema_example
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
                user_register_schema_example
            ]
        }
    }


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                token_refresh_schema_example
            ]
        }
    }


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                token_refresh_response_schema_example
            ]
        }
    }
