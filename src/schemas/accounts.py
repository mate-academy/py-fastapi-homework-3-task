from datetime import date
from database import accounts_validators
from pydantic import BaseModel, ConfigDict, EmailStr, field_validator


class BaseEmailSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return value.lower()


class EmailPasswordSchema(BaseEmailSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(EmailPasswordSchema):
    pass


class UserLoginRequestSchema(EmailPasswordSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class DetailResponseSchema(BaseModel):
    detail: str


class UserRegistrationResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseEmailSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


class TokenBase(BaseModel):
    token: str


class TokenCreate(TokenBase):
    expires_at: date
    user_id: int


class TokenPasswordRefresh(UserBase):
    pass


class ResetPassword(TokenBase, UserBase):
    password: str


class BaseSecurityError(BaseModel):
    detail: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class PasswordResetRequestSchema(BaseEmailSchema):
    pass


class PasswordResetCompleteRequestSchema(BaseEmailSchema):
    token: str
    password: str
