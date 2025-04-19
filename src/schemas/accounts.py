import enum
from email.policy import default

from pydantic import BaseModel, EmailStr, field_validator, Field, ConfigDict

from database import accounts_validators


class UserGroupEnum(str, enum.Enum):
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"


class UserBase(BaseModel):
    email: EmailStr


# Write your code here
class UserRegistrationRequestSchema(UserBase):
    password: str
    group: UserGroupEnum = Field(default=UserGroupEnum.USER)


class UserActivationRequestSchema(UserBase):
    token: str


class UserResetPassword(UserBase):
    token: str
    password: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class MessageResponseSchema(BaseModel):
    message: str = Field(default="User account activated successfully.")
    model_config = ConfigDict(from_attributes=True)


class PasswordResetRequestSchema(UserBase):
    ...


class PasswordResetCompleteRequestSchema(UserBase):
    token: str
    password: str


class UserLoginRequestSchema(UserBase):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = Field(default="bearer")


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
