from pydantic import BaseModel, EmailStr, field_validator, constr

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: constr(min_length=8)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserActivationResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetResponseSchema(BaseModel):
    message: str


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: constr(min_length=8)


class PasswordResetCompleteResponseSchema(BaseModel):
    message: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

class TokenRefreshResponseSchema(BaseModel):
    access_token: str