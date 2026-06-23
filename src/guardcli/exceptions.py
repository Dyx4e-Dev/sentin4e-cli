class GuardCLIError(Exception):
    """Base exception for GuardCLI."""
    pass

class InvalidTargetError(GuardCLIError):
    """Raised when the provided URL target is invalid."""
    pass

class ScanTimeoutError(GuardCLIError):
    """Raised when a scan times out."""
    pass

class TLSValidationError(GuardCLIError):
    """Raised when there is an issue validating TLS/SSL certificates."""
    pass
