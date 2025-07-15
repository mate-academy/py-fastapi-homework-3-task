from pydantic import BaseModel, EmailStr, field_validator
from database.models.accounts import UserGroupEnum

from database.validators.accounts import validate_password_strength


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def validate_password(cls, password_field: str) -> str:
        return validate_password_strength(password_field)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str

    @field_validator("password")
    def validate_password(cls, password_field: str) -> str:
        return validate_password_strength(password_field)


class MessageResponseSchema(BaseModel):
    message: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
