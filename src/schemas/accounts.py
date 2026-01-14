from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, password):
        return accounts_validators.validate_password_strength(password)

    @field_validator("email")
    @classmethod
    def validate_email(cls, email):
        return accounts_validators.validate_email(email)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: str
    token: str


class MessageResponseSchema(BaseModel):
    message: str

    class Config:
        from_attributes = True


class PasswordResetRequestSchema(BaseModel):
    email: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: str
    token: str
    password: str


class UserLoginRequestSchema(BaseModel):
    email: str
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

    class Config:
        from_attributes = True


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

    class Config:
        from_attributes = True
