from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("email")
    @classmethod
    def check_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class Token(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    email: EmailStr
    token: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class MessageResponseSchema(BaseModel):
    message: str
