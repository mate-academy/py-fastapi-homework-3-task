from pydantic import BaseModel, EmailStr


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


PasswordResetCompleteSchema = PasswordResetCompleteRequestSchema


class LoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


TokenResponseSchema = UserLoginResponseSchema


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class RefreshTokenResponseSchema(BaseModel):
    access_token: str


class MessageResponseSchema(BaseModel):
    message: str
