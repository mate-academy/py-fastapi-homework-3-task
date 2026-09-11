from fastapi import HTTPException
from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators


class UserBase(BaseModel):
    email: str

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if v:
            return accounts_validators.validate_email(v)
        raise HTTPException(status_code=400, detail="No email")

class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        if value:
            return accounts_validators.validate_password_strength(value)
        raise HTTPException(status_code=400, detail="No credentials")

class UserRead(UserBase):
    id: int


class Token(BaseModel):
    access_token: str
    token_type: str


class AccountActivation(UserBase):
    token: str


class ResetPassword(UserCreate):
    token: str
