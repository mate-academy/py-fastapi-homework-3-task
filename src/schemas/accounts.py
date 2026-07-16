from jose import JWTError
from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators, UserGroupEnum
from database.validators.accounts import validate_password_strength
from security.token_manager import JWTAuthManager


class UserScheme(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserScheme):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)


class UserRegistrationResponseSchema(UserScheme):
    id: int

    model_config = {
        "from_attributes": True,
    }


class UserLoginRequestSchema(UserScheme):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserActivationRequestSchema(UserScheme):
    token: str


class PasswordResetRequestSchema(UserScheme):
    pass


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)


class MessageResponseSchema(BaseModel):
    message: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
