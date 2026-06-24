class Sentin4eException(Exception):
    def __init__(self, message: str, original_exception: Exception = None):
        super().__init__(message)
        self.original_exception = original_exception

class ExcessiveHeadersError(Sentin4eException):
    pass

class MalformedResponseError(Sentin4eException):
    pass

class ConnectionClosedError(Sentin4eException):
    pass

class RedirectLoopError(Sentin4eException):
    pass

class SSLValidationError(Sentin4eException):
    pass

class TimeoutError(Sentin4eException):
    pass

class UnknownNetworkError(Sentin4eException):
    pass
