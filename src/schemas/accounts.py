from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("email")
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    password: str
    token: str

    @field_validator("password")
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserLoginRequestSchema(UserBase):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
