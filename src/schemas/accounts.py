from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators import accounts as validators


class BaseEmailSchema(BaseModel):
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return validators.validate_email(value)


class BasePasswordSchema(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        validators.validate_password_strength(value)
        return value


class UserRegistrationRequestSchema(BaseEmailSchema, BasePasswordSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    model_config = ConfigDict(from_attributes=True)


class MessageResponseSchema(BaseModel):
    message: str


class UserActivationRequestSchema(BaseEmailSchema):
    token: str


class PasswordResetRequestSchema(BaseEmailSchema):
    pass


class PasswordResetCompleteRequestSchema(BaseEmailSchema, BasePasswordSchema):
    token: str


class UserLoginRequestSchema(BaseEmailSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
