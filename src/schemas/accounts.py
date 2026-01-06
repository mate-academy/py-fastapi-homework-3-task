from pydantic import BaseModel, field_validator
from enum import Enum
from database import accounts_validators, UserGroupEnum


class MessageResponseSchema(BaseModel):
    status_code: int
    message: str | dict


class UserBase(BaseModel):
    email: str


class UserRegistrationRequestSchema(UserBase):
    password: str
    group: Enum = UserGroupEnum.USER

    @field_validator("password")
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)

    @field_validator("email")
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class UserActivationRequestSchema(UserBase):
    token: str

    class Config:
        from_attributes = True


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    token: str
    password : str

    @field_validator("password")
    def validate_new_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(UserBase):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
