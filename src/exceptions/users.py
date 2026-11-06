class UserDBError(Exception):
    pass


class UserWithEmailAlreadyExistsError(UserDBError):
    pass


class UserAlreadyActiveError(UserDBError):
    pass


class UserNotActivatedError(UserDBError):
    pass


class UserNotFoundError(UserDBError):
    pass


class InvalidCredentialsError(UserDBError):
    pass
