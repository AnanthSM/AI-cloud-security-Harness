class HarnessError(Exception):
    """Public errors must be safe: never embed arguments, secrets or provider exceptions."""


class NotFound(HarnessError):
    pass


class Forbidden(HarnessError):
    pass


class Conflict(HarnessError):
    pass


class Invalid(HarnessError):
    pass
