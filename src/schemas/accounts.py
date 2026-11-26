from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        accounts_validators.validate_email(value)
        return value


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = {
        "from_attributes": True,
    }


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    ...


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str


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
