from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators

# Write your code here


class ValidationSchema(BaseModel):

    @field_validator('email', check_fields=False)
    @classmethod
    def validate_email(cls, value):
        return accounts_validators.validate_email(value)

    @field_validator('password', check_fields=False)
    @classmethod
    def validate_password(cls, value):
        return accounts_validators.validate_password(value)

class UserBase(BaseModel):
    email: EmailStr
    password: str

class UserRegistrationRequestSchema(ValidationSchema):
    email: EmailStr
    password: str


class UserActivationRequestSchema(ValidationSchema):
    email: EmailStr
    token: str

class PasswordResetRequestSchema(ValidationSchema):
    email: EmailStr

class PasswordResetCompleteRequestSchema(ValidationSchema):
    token: str
    password: str

class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserLoginRequestSchema(UserBase):
    pass


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class MessageResponseSchema(BaseModel):
    message: str
