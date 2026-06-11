from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators
from database.validators.accounts import validate_password_strength, validate_email


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, val: str):
        return validate_password_strength(val)

    @field_validator("email")
    @classmethod
    def check_email(cls, val: str):
        return validate_email(val)


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    message: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(UserBase):
    password: str


class TokenRefreshRequestSchema(UserBase):
    token: str
    password: str


class TokenRefreshResponseSchema(BaseModel):
    message: str


class TokenAccessRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenAccessRefreshResponseSchema(BaseModel):
    access_token: str
