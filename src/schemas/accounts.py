from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

class UserResponseSchema(BaseModel):
    id: int
    email: EmailStr

class UserRegistrationResponseSchema(UserResponseSchema):
    pass


class UserActivationSchema(BaseModel):
    email: EmailStr
    token: str

UserActivationRequestSchema = UserActivationSchema

class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

class PasswordResetRequestSchema(BaseModel):
    email: EmailStr

class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str
UserLoginRequestSchema = LoginRequestSchema

class TokenRefreshResponseSchema(BaseModel):
    refresh_token: str

class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class LoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
UserLoginResponseSchema = LoginResponseSchema


class AccessTokenResponseSchema(BaseModel):
    access_token: str

class MessageResponseSchema(BaseModel):
    message: str
