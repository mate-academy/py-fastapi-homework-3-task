from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class BaseEmailPasswordSchema(BaseModel):
    email: EmailStr
    password: str

    model_config = {"from_attributes": True}

    @field_validator("email")
    @classmethod
    def validate_email(cls, email):
        return accounts_validators.validate_email(email)

    @field_validator("password")
    @classmethod
    def validate_password(cls, password):
        return accounts_validators.validate_password_strength(password)


class UserRegistrationRequestSchema(BaseEmailPasswordSchema):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginRequestSchema(BaseEmailPasswordSchema):
    pass


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
