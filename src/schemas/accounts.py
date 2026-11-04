from pydantic import BaseModel, EmailStr, field_validator
from database.validators.accounts import validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str) -> str:
        validate_password_strength(value)
        return value


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    token: str
    password: str


class UserLoginRequestSchema(BaseModel):
    email: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str
