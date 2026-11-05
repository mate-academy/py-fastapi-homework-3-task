from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationSchema(BaseModel):
    email: EmailStr
    token: str


UserActivationRequestSchema = UserActivationSchema


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(min_length=8)


PasswordResetCompleteRequestSchema = PasswordResetCompleteSchema


class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str


UserLoginRequestSchema = UserLoginSchema


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


UserLoginResponseSchema = TokenResponseSchema


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


TokenRefreshResponseSchema = TokenResponseSchema


class MessageResponseSchema(BaseModel):
    message: str
