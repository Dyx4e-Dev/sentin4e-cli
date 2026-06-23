from urllib.parse import urlparse
from guardcli.exceptions import InvalidTargetError

def validate_url(url: str) -> str:
    """Validates and sanitizes the target URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    parsed = urlparse(url)
    if not parsed.netloc:
        raise InvalidTargetError(f"Invalid URL format: {url}")
    
    return url
