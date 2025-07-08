from datetime import datetime, date
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field
from enum import Enum


class UserGroupEnum(str, Enum):
    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"


class GenderEnum(str, Enum):
    MAN = "man"
    WOMAN = "woman"


class UserGroupBase(BaseModel):
    name: UserGroupEnum


class UserGroupRead(UserGroupBase):
    id: int

    class Config:
        orm_mode = True


class UserProfileBase(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar: Optional[str] = None
    gender: Optional[GenderEnum] = None
    date_of_birth: Optional[date] = None
    info: Optional[str] = None


class UserProfileCreate(UserProfileBase):
    user_id: int


class UserProfileUpdate(UserProfileBase):
    pass


class UserProfileRead(UserProfileBase):
    id: int
    user_id: int

    class Config:
        orm_mode = True



class TokenBase(BaseModel):
    token: str
    expires_at: datetime
    user_id: int



class ActivationTokenCreate(TokenBase):
    pass


class ActivationTokenRead(TokenBase):
    id: int

    class Config:
        orm_mode = True


class PasswordResetTokenCreate(TokenBase):
    pass


class PasswordResetTokenRead(TokenBase):
    id: int

    class Config:
        orm_mode = True



class RefreshTokenCreate(TokenBase):
    pass


class RefreshTokenRead(TokenBase):
    id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    group_id: Optional[int] = None


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    group_id: int


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    group_id: Optional[int] = None


class UserRead(UserBase):
    id: int
    group: UserGroupRead
    profile: Optional[UserProfileRead] = None
    activation_token: Optional[ActivationTokenRead] = None
    password_reset_token: Optional[PasswordResetTokenRead] = None
    refresh_tokens: List[RefreshTokenRead] = []

    class Config:
        orm_mode = True


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserActivationRequestSchema(BaseModel):
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    token: str
    new_password: str
    email: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    refresh_token: str


class MessageResponseSchema(BaseModel):
    message: str
