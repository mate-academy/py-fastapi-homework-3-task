user_create_schema_example = {
  "email": "user@example.com",
  "new_password": "SecurePassword123!"
}

user_created_schema_example = {
  "id": 1,
  "email": "user@example.com",
}

user_activate_schema_example = {
  "email": "test@example.com",
  "token": "activation_token"
}

user_password_reset_example = {
  "email": "test@example.com"
}

password_reset_completion_example = {
  "email": "testuser@example.com",
  "token": "valid-reset-token",
  "new_password": "NewStrongPassword123!"
}

user_login_example = {
  "email": "user@example.com",
  "new_password": "UserPassword123!"
}

user_login_response_example = {
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
