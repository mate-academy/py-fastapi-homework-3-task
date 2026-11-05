from pydantic import BaseModel, EmailStr, Field, field_validator

from database import accounts_validators
from schemas.examples.accounts import (
    register_request_schema_example,
    register_response_schema_example,
    activate_account_schema_example,
    activate_account_response_schema_example,
    password_reset_request_schema_example,
    password_reset_request_response_schema_example,
    password_reset_complete_schema_example,
    password_reset_complete_response_schema_example,
    login_schema_example,
    login_response_schema_example,
    refresh_token_schema_example,
    refresh_token_response_schema_example
)


class RegisterRequestSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                register_request_schema_example
            ]
        }
    }

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class RegisterResponseSchema(BaseModel):
    id: int
    email: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                register_response_schema_example
            ]
        }
    }


class ActivateAccountSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                activate_account_schema_example
            ]
        }
    }


class ActivateAccountResponseSchema(BaseModel):
    message: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                activate_account_response_schema_example
            ]
        }
    }


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                password_reset_request_schema_example
            ]
        }
    }


class PasswordResetRequestResponseSchema(BaseModel):
    message: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                password_reset_request_response_schema_example
            ]
        }
    }


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                password_reset_complete_schema_example
            ]
        }
    }

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                password_reset_complete_response_schema_example
            ]
        }
    }


class LoginSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                login_schema_example
            ]
        }
    }


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                login_response_schema_example
            ]
        }
    }


class RefreshTokenSchema(BaseModel):
    refresh_token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                refresh_token_schema_example
            ]
        }
    }


class RefreshTokenResponseSchema(BaseModel):
    access_token: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                refresh_token_response_schema_example
            ]
        }
    }
