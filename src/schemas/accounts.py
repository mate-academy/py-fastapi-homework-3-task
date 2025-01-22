from pydantic import BaseModel, EmailStr


class UserRegistrationRequestSchema(BaseModel):
    pass


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {"from_attributes": True}


class UserActivationRequestSchema(BaseModel):
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    email: EmailStr
    token: str
    password: str


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str


class MessageResponseSchema(BaseModel):
    message: str
