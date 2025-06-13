from pydantic import BaseModel, field_validator


class EmailSchema(BaseModel):
    email: str


class PasswordSchema(BaseModel):
    password: str


class UserRegisterSchema(EmailSchema, PasswordSchema):
    pass


class UserLoginSchema(UserRegisterSchema):
    pass


class UserRegisterResponse(EmailSchema):
    id: int


class UserActivationRequestSchema(EmailSchema):
    token: str


class ResponseSchema(BaseModel):
    message: str


class UserResetPasswordComplete(EmailSchema, PasswordSchema):
    token: str


class UserLoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class RefreshTokenSchema(BaseModel):
    refresh_token: str
