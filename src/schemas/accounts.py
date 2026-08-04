from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class PasswordMixin(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password):
        return accounts_validators.validate_password_strength(password)


class UserRegistrationRequestSchema(PasswordMixin):
    pass


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class UserLoginRequestSchema(UserBase):
    password: str


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema, PasswordMixin):
    pass


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
