import re

from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators
from schemas.examples.accounts import user_create_schema_example, user_activate_schema_example, \
    user_created_schema_example, user_password_reset_example, password_reset_completion_example, user_login_example, \
    user_login_response_example


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBaseSchema):
    new_password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                user_create_schema_example
            ]
        }
    }

    @field_validator("new_password")
    @classmethod
    def check_password(cls, v: str) -> str:
        return accounts_validators.validate_password_strength(v)


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                user_created_schema_example
            ]
        }
    }


class UserActivationRequestSchema(UserBaseSchema):
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


class PasswordResetRequestSchema(UserBaseSchema):

    model_config = {
        "json_schema_extra": {
            "examples": [
                user_password_reset_example
            ]
        }
    }


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                password_reset_completion_example
            ]
        }
    }


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                user_login_response_example
            ]
        }
    }


class UserLoginRequestSchema(UserRegistrationRequestSchema):

    model_config = {
        "json_schema_extra": {
            "examples": [
                user_login_example
            ]
        }
    }


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
