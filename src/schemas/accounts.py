from pydantic import BaseModel, EmailStr, field_validator, ConfigDict
from database import accounts_validators


class EmailBase(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        return v.lower()

    model_config = ConfigDict(from_attributes=True)


class PasswordBase(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserRegistrationRequestSchema(EmailBase, PasswordBase):
    pass


class UserRegistrationResponseSchema(EmailBase):
    id: int


class UserActivationRequestSchema(EmailBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(EmailBase):
    pass


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str


class UserLoginRequestSchema(EmailBase, PasswordBase):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"

    model_config = ConfigDict(from_attributes=True)
