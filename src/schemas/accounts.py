from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators, ActivationTokenModel


class UserBaseSchema(BaseModel):
    email: str


class UserRegistrationRequestSchema(UserBaseSchema):
    password: str

    class Config:
        from_attributes = True


class UserRegistrationResponseSchema(UserBaseSchema):
    id: int

    class Config:
        from_attributes = True


class UserActivationRequestSchema(UserBaseSchema):
    token: str

    class Config:
        from_attributes = True


class MessageResponseSchema(BaseModel):
    message: str


class Token(BaseModel):
    access_token: str
    token_type: str


class PasswordResetRequestSchema(UserBaseSchema):
    pass


class PasswordResetCompleteRequestSchema(UserActivationRequestSchema):
    password: str


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


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
