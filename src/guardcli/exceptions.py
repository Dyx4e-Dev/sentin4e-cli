class GuardCLIException(Exception):
    def __init__(self, message: str, original_exception: Exception = None):
        super().__init__(message)
        self.original_exception = original_exception

class ExcessiveHeadersError(GuardCLIException):
    pass

class MalformedResponseError(GuardCLIException):
    pass

class ConnectionClosedError(GuardCLIException):
    pass

class RedirectLoopError(GuardCLIException):
    pass

class SSLValidationError(GuardCLIException):
    pass

class TimeoutError(GuardCLIException):
    pass

class UnknownNetworkError(GuardCLIException):
    pass
