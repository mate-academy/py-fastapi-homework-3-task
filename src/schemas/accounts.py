from typing import Annotated

from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators
from database.validators.accounts import validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123!"
            }
        }
    }


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": 1,
                "email": "user@example.com"
            }
        }
    }


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "test@example.com",
                "token": "activation_token"
            }
        }
    }


class MessageResponseSchema(BaseModel):
    message: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "message": "User account activated successfully."
            }
        }
    }


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "test@example.com"
            }
        }
    }


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    password: str
    token: str

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, value: str) -> str:
        return validate_password_strength(value)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "testuser@example.com",
                "token": "valid-reset-token",
                "new_password": "NewStrongPassword123!"
            }
        }
    }


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, value: str) -> str:
        return validate_password_strength(value)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "password": "UserPassword123!"
            }
        }
    }


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer"
            }
        }
    }


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "refresh_token": "example_refresh_token"
            }
        }
    }


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "access_token": "new_access_token"
            }
        }
    }
