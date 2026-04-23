from pydantic import BaseModel, EmailStr, field_validator, ConfigDict, Field


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not any(ch.isupper() for ch in value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(ch.isdigit() for ch in value):
            raise ValueError("Password must contain at least one digit.")
        if not any(ch.islower() for ch in value):
            raise ValueError("Password must contain at least one lower letter.")
        if not any(ch in "@$!%*?#&" for ch in value):
            raise ValueError(
                "Password must contain at least one special character: @, $, !, %, *, ?, #, &."
            )
        return value


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserActivationRequestSchema(UserBase):
    token: str


class UserRegistrationResponseSchema(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int


class PasswordResetRequestSchema(UserBase):
    pass


class PasswordResetCompleteRequestSchema(UserRegistrationRequestSchema):
    token: str


class TokenBase(BaseModel):
    pass


class TokenRefreshRequestSchema(TokenBase):
    refresh_token: str


class TokenRefreshResponseSchema(TokenBase):
    model_config = ConfigDict(from_attributes=True)

    access_token: str


class UserLoginResponseSchema(TokenRefreshRequestSchema, TokenRefreshResponseSchema):
    model_config = ConfigDict(from_attributes=True)

    token_type: str


class MessageResponseSchema(BaseModel):
    message: str
