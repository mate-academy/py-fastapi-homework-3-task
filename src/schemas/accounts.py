from pydantic import BaseModel, EmailStr


class UserBaseSchema(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int


class UserActivationRequestSchema(UserBaseSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserBaseSchema):
    pass


class PasswordResetCompleteRequestSchema(UserBaseSchema):
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
