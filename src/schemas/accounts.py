from pydantic import BaseModel, EmailStr, field_validator
from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str
    role: str = "user"

class UserRead(UserBase):
    id: int
    role: str

    class Config:
        from_attributes = True

class UserUpdate(UserBase):
    password: str | None = None
    role: str | None = None
