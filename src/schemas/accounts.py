from pydantic import BaseModel, ConfigDict, EmailStr


class MessageResponseSchema(BaseModel):
    message: str


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserActivationResponseSchema(MessageResponseSchema):
    pass


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetResponseSchema(MessageResponseSchema):
    pass


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str


class PasswordResetCompleteResponseSchema(MessageResponseSchema):
    pass


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserLoginResponseSchema(TokenResponseSchema):
    pass


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(TokenResponseSchema):
    pass
