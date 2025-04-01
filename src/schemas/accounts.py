from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        return accounts_validators.validate_email(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        return accounts_validators.validate_password_strength(v)


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    type_token: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
