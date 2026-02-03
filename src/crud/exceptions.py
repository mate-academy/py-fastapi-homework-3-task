# User

class UserError(Exception):
    pass


class UserAlreadyExist(UserError):
    pass


class UserDoesNotExist(UserError):
    pass


class UserGroupError(Exception):
    pass


class UserGroupDoesNotExist(UserGroupError):
    pass


class UserAlreadyActivated(UserError):
    pass


class UserNotActivated(UserError):
    pass


# Token

class TokenExpired(Exception):
    pass


class TokenInvalid(Exception):
    pass

class InvalidPassword(Exception):
    pass