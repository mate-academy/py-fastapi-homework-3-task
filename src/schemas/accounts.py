from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserRegistrationRequestSchema(BaseModel):
    password: str
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    ...


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
