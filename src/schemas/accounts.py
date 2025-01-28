from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr

    class Config:
        from_attributes = True


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return value.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password_strength(value)


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
