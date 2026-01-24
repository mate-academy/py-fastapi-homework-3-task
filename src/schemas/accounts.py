from pydantic import BaseModel, EmailStr, Field, field_validator
import re


class UserRegistrationRequestSchema(BaseModel):
    """Schema for user registration request"""
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        """Validate password strength"""
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r'[A-Z]', value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r'\d', value):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r'[@$!%*?#&]', value):
            raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
        return value

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "user@example.com",
                    "password": "SecurePassword123!"
                }
            ]
        }
    }


class UserRegistrationResponseSchema(BaseModel):
    """Schema for user registration response"""
    id: int
    email: str

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [
                {
                    "id": 1,
                    "email": "user@example.com"
                }
            ]
        }
    }


class UserActivationRequestSchema(BaseModel):
    """Schema for user activation request"""
    email: EmailStr
    token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "test@example.com",
                    "token": "activation_token"
                }
            ]
        }
    }


class MessageResponseSchema(BaseModel):
    """Generic message response schema"""
    message: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "message": "Operation completed successfully."
                }
            ]
        }
    }


class PasswordResetRequestSchema(BaseModel):
    """Schema for password reset request"""
    email: EmailStr

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "test@example.com"
                }
            ]
        }
    }


class PasswordResetCompleteRequestSchema(BaseModel):
    """Schema for password reset completion"""
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        """Validate password strength"""
        if len(value) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        if not re.search(r'[A-Z]', value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise ValueError("Password must contain at least one lower letter.")
        if not re.search(r'\d', value):
            raise ValueError("Password must contain at least one digit.")
        if not re.search(r'[@$!%*?#&]', value):
            raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
        return value

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "testuser@example.com",
                    "token": "valid-reset-token",
                    "password": "NewStrongPassword123!"
                }
            ]
        }
    }


class UserLoginRequestSchema(BaseModel):
    """Schema for user login request"""
    email: EmailStr
    password: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "email": "user@example.com",
                    "password": "UserPassword123!"
                }
            ]
        }
    }


class UserLoginResponseSchema(BaseModel):
    """Schema for user login response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                    "token_type": "bearer"
                }
            ]
        }
    }


class TokenRefreshRequestSchema(BaseModel):
    """Schema for token refresh request"""
    refresh_token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "refresh_token": "example_refresh_token"
                }
            ]
        }
    }


class TokenRefreshResponseSchema(BaseModel):
    """Schema for token refresh response"""
    access_token: str

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "access_token": "new_access_token"
                }
            ]
        }
    }
