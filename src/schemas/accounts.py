from typing import Literal

from pydantic import BaseModel, EmailStr, field_validator

from database.validators import accounts as accounts_validators


def validate_new_password(password: str) -> str:
    accounts_validators.validate_password_strength(password)
    if "\x00" in password:
        raise ValueError("Password cannot contain a null byte.")
    try:
        password_size = len(password.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ValueError("Password must contain valid Unicode characters.") from error
    if password_size > 72:
        raise ValueError("Password must be at most 72 UTF-8 bytes.")
    return password


class EmailRequestSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, email: str) -> str:
        return email.lower()


class UserRegistrationRequestSchema(EmailRequestSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return validate_new_password(password)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(EmailRequestSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(EmailRequestSchema):
    pass


class PasswordResetCompleteRequestSchema(EmailRequestSchema):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password: str) -> str:
        return validate_new_password(password)


class UserLoginRequestSchema(EmailRequestSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
