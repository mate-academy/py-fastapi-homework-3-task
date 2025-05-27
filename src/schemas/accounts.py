from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr


class ActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(..., min_length=8)


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshSchema(BaseModel):
    refresh_token: str