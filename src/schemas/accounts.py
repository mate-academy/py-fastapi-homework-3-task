from typing import Annotated

from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, AfterValidator

from database import accounts_validators

NormalizedEmail = Annotated[EmailStr, AfterValidator(str.lower)]


class UserRegistrationRequestSchema(BaseModel):
    email: NormalizedEmail
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: NormalizedEmail
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: NormalizedEmail


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: NormalizedEmail
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(BaseModel):
    email: NormalizedEmail
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
