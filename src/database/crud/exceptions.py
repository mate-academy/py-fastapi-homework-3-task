class UserException(Exception):
    pass


class UserAlreadyExistsError(UserException):
    pass


class UserNotExistsError(UserException):
    pass


class UserNotActivatedError(UserException):
    pass


class UserAlreadyActivatedError(UserException):
    pass


class InvalidOrExpiredTokenError(UserException):
    pass
