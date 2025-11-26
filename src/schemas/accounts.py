from typing import List

from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr


class UserRegisterRequestSchema(UserBase):
    email: EmailStr
    password: str


class UserRegisterResponseSchema(UserBase):
    id: int
    email: EmailStr


class UserActivation(BaseModel):
    email: EmailStr
    token: str


class PasswordResetToken(BaseModel):
    email: EmailStr


class PasswordResetCompletion(BaseModel):
    email: EmailStr
    token: str
    password: str


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class LoginRequestResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshAccessRequestSchema(BaseModel):
    refresh_token: str


class RefreshAccessResponseSchema(BaseModel):
    access_token: str
