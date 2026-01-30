from pydantic import BaseModel, EmailStr, ConfigDict, Field


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str = Field(min_length=8)


class UserRegistrationResponseSchema(UserBaseSchema):
    model_config = ConfigDict(from_attributes=True)

    id: int


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(min_length=8)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    access_token: str


class MessageResponseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    message: str
