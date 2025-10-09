from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "user@example.com", "password": "SecurePassword123!"}
            ]
        }
    }

    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    model_config = {
        "from_attributes": True,
        "json_schema_extra": {"examples": [{"id": 1, "email": "user@example.com"}]},
    }

    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [{"email": "user@example.com", "token": "abc123def456ghi789"}]
        }
    }

    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    model_config = {"json_schema_extra": {"examples": [{"email": "user@example.com"}]}}

    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "user@example.com",
                    "token": "xyz789abc123def456",
                    "password": "NewSecurePassword123!",
                }
            ]
        }
    }

    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "user@example.com",
                    "password": "SecurePassword123",
                }
            ]
        }
    }

    email: EmailStr
    password: str


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class AccessTokenResponseSchema(BaseModel):
    access_token: str


class MessageResponseSchema(BaseModel):
    model_config = {
        "json_schema_extra": {
            "examples": [{"message": "Operation completed successfully."}]
        }
    }

    message: str
