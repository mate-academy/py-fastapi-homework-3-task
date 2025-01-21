import re

import email_validator
from starlette.responses import JSONResponse
from fastapi import status, HTTPException
import logging

logger = logging.getLogger(__name__)


def validate_confirm_password(cls, v, values):
    password = values.get("password")
    if password and v != password:
        raise ValueError("Passwords do not match.")
    return v


def validate_email(user_email: str) -> str:
    try:
        email_info = email_validator.validate_email(user_email, check_deliverability=False)
        email = email_info.normalized
    except email_validator.EmailNotValidError as error:
        raise ValueError(str(error))
    else:
        return email


def validate_password(cls, v):
    if len(v) < 8:
        raise ValueError('Password must contain at least 8 characters.')
    if not any(char.isdigit() for char in v):
        raise ValueError('Password must contain at least one digit.')
    if not any(char.isupper() for char in v):
        raise ValueError('Password must contain at least one uppercase letter.')
    if not any(char.islower() for char in v):
        raise ValueError('Password must contain at least one lowercase letter.')
    if not any(char in "@$!%*?&#" for char in v):
        raise ValueError('Password must contain at least one special character: @, $, !, %, *, ?, #, &.')
    return v


def validation_exception_handler(request, exc):
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        logger.warning(
            "Password validation failed:"
            " Password must contain at least 8 characters.")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least 8 characters."
        )
    if not re.search(r'[A-Z]', password):
        logger.warning("Password validation failed: "
                       "Password must contain at least one uppercase letter.")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one uppercase letter."
        )
    if not re.search(r'[a-z]', password):
        logger.warning("Password validation failed:"
                       " Password must contain at least one lowercase letter.")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one lower letter."
        )
    if not re.search(r'\d', password):
        logger.warning("Password validation failed:"
                       " Password must contain at least one digit.")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one digit."
        )
    if not re.search(r'[@$!%*?&#]', password):
        logger.warning(
            "Password validation failed:"
            " Password must contain at least one special character: @, $, !, %, *, ?, #, &.")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password must contain at least one special character: @, $, !, %, *, ?, #, &."
        )
    return password
