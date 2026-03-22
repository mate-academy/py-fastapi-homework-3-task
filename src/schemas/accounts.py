from pydantic import BaseModel, EmailStr, field_validator
from src.database.validators.accounts import validate_password_strength, validate_email


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str):
        return validate_email(v)

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str):
        return validate_password_strength(v)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str):
        return validate_password_strength(v)


class MessageResponseSchema(BaseModel):
    message: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
