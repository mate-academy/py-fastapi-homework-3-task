user_registration_request_example = {
    "email": "user@example.com",
    "password": "SecurePassword123!"
}

user_registration_response_example = {
    "id": 1,
    "email": "user@example.com"
}


user_activation_request_example = {
    "email": "test@example.com",
    "token": "activation_token"
}

user_activation_response_example = {
    "message": "User account activated successfully."
}


password_reset_request_example = {
    "email": "test@example.com"
}

password_reset_response_example = {
    "message": "If you are registered, you will receive an email with instructions."
}


password_reset_complete_request_example = {
    "email": "testuser@example.com",
    "token": "valid-reset-token",
    "password": "NewStrongPassword123!"
}

password_reset_complete_response_example = {
    "message": "Password reset successfully."
}


login_request_example = {
    "email": "user@example.com",
    "password": "UserPassword123!"
}

login_response_example = {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
}


refresh_access_token_request_example = {
    "refresh_token": "example_refresh_token"
}

refresh_access_token_response_example = {
    "access_token": "new_access_token"
}
