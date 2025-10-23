import re
from pydantic import BaseModel, EmailStr, validator

# --- Password Validation ---

def validate_password(password: str) -> str:
    """
    Validates the password complexity.
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValueError("Password must contain at least one special character")
    return password


# --- Base Schemas ---

class MessageResponseSchema(BaseModel):
    """A standard schema for simple message responses."""
    message: str


# --- User Registration (Task 1) ---

class UserRegistrationRequestSchema(BaseModel):
    """Schema for user registration request body."""
    email: EmailStr
    password: str

    _password_validator = validator("password", allow_reuse=True)(validate_password)


class UserRegistrationResponseSchema(BaseModel):
    """Schema for user registration success response."""
    id: int
    email: EmailStr

    class Config:
        orm_mode = True


# --- User Activation (Task 2) ---

class UserActivationRequestSchema(BaseModel):
    """Schema for user account activation request body."""
    email: EmailStr
    token: str


# --- Password Reset Request (Task 3) ---

class PasswordResetRequestSchema(BaseModel):
    """Schema for requesting a password reset token."""
    email: EmailStr


# --- Password Reset Completion (Task 4) ---

class PasswordResetCompleteSchema(BaseModel):
    """Schema for completing the password reset process."""
    email: EmailStr
    token: str
    password: str

    _password_validator = validator("password", allow_reuse=True)(validate_password)


# --- User Login (Task 5) ---

class UserLoginRequestSchema(BaseModel):
    """Schema for user login request body."""
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    """Schema for user login success response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# --- Token Refresh (Task 6) ---

class TokenRefreshRequestSchema(BaseModel):
    """Schema for access token refresh request body."""
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    """Schema for access token refresh success response."""
    access_token: str
