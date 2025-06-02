user_registration_request_schema_example = {
    "email": "user@example.com",
    "password": "SecurePassword123!"
}

user_registration_response_schema_example = {
    "id": 1,
    "email": "user@example.com",
}

user_activate_request_schema_example = {
    "email": "test@example.com",
    "token": "activation_token"
}

request_message_schema_example = {
    "message": "Message"
}

user_request_reset_password_schema_example = {
    "email": "test@example.com"
}

user_request_reset_password_completed_schema_example = {
    "email": "testuser@example.com",
    "token": "valid-reset-token",
    "password": "NewStrongPassword123!"
}

user_request_login_schema_example = {
    "email": "user@example.com",
    "password": "UserPassword123!"
}

user_response_login_schema_example = {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "bearer"
}


user_request_refresh_schema_example = {
    "refresh_token": "example_refresh_token"
}

user_response_refresh_schema_example = {
    "access_token": "new_access_token"
}
