user_register_schema_example = {
    "email": "user@example.com",
    "password": "SecurePassword123!"
}

user_register_response_schema_example = {
    "id": 1,
    "email": "user@example.com"
}

user_activate_schema_example = {
    "email": "test@example.com",
    "token": "activation_token"
}

user_activate_response_schema_example = {
    "message": "User account activated successfully."
}

user_password_reset_schema_example = {
    "email": "user@example.com"
}

user_password_reset_complete_schema_example = {
    "email": "testuser@example.com",
    "token": "valid-reset-token",
    "password": "NewStrongPassword123!"
}

user_login_response_schema_example = {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
}

token_refresh_schema_example = {
    "refresh_token": "example_refresh_token"
}

token_refresh_response_schema_example = {
    "access_token": "new_access_token"
}

user_login_schema_example = {
    "email": "user@example.com",
    "password": "SecurePassword123!"
}
