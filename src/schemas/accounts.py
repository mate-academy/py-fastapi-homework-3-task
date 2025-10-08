from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from database import accounts_validators


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


class PasswordResetRequestSchema(BaseEmailSchema):
    pass


class PasswordResetCompleteRequestSchema(EmailPasswordSchema):
    token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
