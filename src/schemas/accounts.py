from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from database import accounts_validators


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        accounts_validators.validate_password_strength(value)
        return value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, email):
        return email.lower()


class UserRegistrationResponseSchema(UserBase):
    id: int


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str


class UserLoginRequestSchema(UserBase):
    password: str


class UserLoginResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
