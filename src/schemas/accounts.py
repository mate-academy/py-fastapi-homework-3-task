from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from database.validators import accounts


class UserBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        accounts.validate_password_strength(value)
        return value

    @field_validator("email")
    @classmethod
    def normalize_email(cls, email):
        return email.lower()


class UserRegistrationResponseSchema(UserBase):
    id: int


class UserLoginRequestSchema(UserRegistrationRequestSchema):
    pass


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserActivationRequestSchema(BaseModel):
    email: str


class PasswordResetRequestSchema(BaseModel):
    email: str


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str):
        accounts.validate_password_strength(value)
        return value


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class MessageResponseSchema(BaseModel):
    message: str
