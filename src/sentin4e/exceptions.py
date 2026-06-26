class Sentin4eError(Exception):
    def __init__(self, message: str, original_exception: Exception | None = None):
        super().__init__(message)
        self.original_exception = original_exception

class ExcessiveHeadersError(Sentin4eError):
    pass

class MalformedResponseError(Sentin4eError):
    pass

class ConnectionClosedError(Sentin4eError):
    pass

class RedirectLoopError(Sentin4eError):
    pass

class SSLValidationError(Sentin4eError):
    pass

class TimeoutError(Sentin4eError):
    pass

class UnknownNetworkError(Sentin4eError):
    pass
