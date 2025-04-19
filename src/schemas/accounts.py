import enum

from pydantic import BaseModel, EmailStr, Field, ConfigDict


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


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


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
