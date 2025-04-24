from pydantic import BaseModel, EmailStr, field_validator

from src.database.validators.accounts import validate_email, validate_password_strength


class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserRead(UserBase):
    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class UserRegistrationRequestSchema(UserCreate):
    @field_validator("email", )
    @classmethod
    def validate_an_email(cls, value: str):
        return validate_email(value)

    @field_validator("password", )
    @classmethod
    def validate_a_password(cls, value: str):
        return validate_password_strength(value)

