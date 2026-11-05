register_request_schema_example = {
    "email": "testuser@example.com",
    "password": "StrongPassword123!"
}

register_response_schema_example = {
    "id": 1,
    "email": "testuser@example.com"
}

activate_account_schema_example = {
    "email": "testuser@example.com",
    "token": "abc123def456"
}

activate_account_response_schema_example = {
    "message": "User account activated successfully."
}

password_reset_request_schema_example = {
    "email": "testuser@example.com"
}

password_reset_request_response_schema_example = {
    "message": "If you are registered, you will receive an email with instructions."
}

password_reset_complete_schema_example = {
    "email": "testuser@example.com",
    "token": "abc123def456",
    "password": "NewSecurePassword123!"
}

password_reset_complete_response_schema_example = {
    "message": "Password reset successfully."
}

login_schema_example = {
    "email": "testuser@example.com",
    "password": "StrongPassword123!"
}

login_response_schema_example = {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

refresh_token_schema_example = {
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}

refresh_token_response_schema_example = {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
