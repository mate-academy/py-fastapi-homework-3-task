from pydantic import BaseModel, EmailStr, field_validator
from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        accounts_validators.validate_password_strength(v)
        return v


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class AccountActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        accounts_validators.validate_password_strength(v)
        return v


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequestSchema(BaseModel):
    refresh_token: str


class RefreshTokenResponseSchema(BaseModel):
    access_token: str


UserActivationRequestSchema = AccountActivationRequestSchema
PasswordResetCompleteRequestSchema = PasswordResetCompleteSchema
UserLoginRequestSchema = LoginRequestSchema
UserLoginResponseSchema = LoginResponseSchema
TokenRefreshRequestSchema = RefreshTokenRequestSchema
TokenRefreshResponseSchema = RefreshTokenResponseSchema


class MessageResponseSchema(BaseModel):
    message: str
