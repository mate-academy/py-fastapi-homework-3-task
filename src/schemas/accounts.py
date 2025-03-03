from datetime import datetime
from pydantic import BaseModel, EmailStr


class RegisterUserSchema(BaseModel):
    email: EmailStr
    password: str


class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr


class ActivateUserSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenSchema(BaseModel):
    refresh_token: str
