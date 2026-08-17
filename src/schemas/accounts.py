from typing import Any

from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: Any) -> Any:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class MessageResponseSchema(BaseModel):
    message: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class UserActivationRequestSchema(UserBase):
    token: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: Any) -> Any:
        return accounts_validators.validate_password_strength(value)
