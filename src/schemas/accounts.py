from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class MessageResponseSchema(BaseModel):
    message: str


class UserEmailSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return value.lower()


class UserPasswordSchema(UserEmailSchema):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(UserPasswordSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(UserEmailSchema):
    token: str


class PasswordResetRequestSchema(UserEmailSchema):
    pass


class PasswordResetCompleteRequestSchema(UserPasswordSchema):
    token: str


class UserLoginRequestSchema(UserEmailSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
