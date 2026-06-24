import time
import sys
import requests
import urllib3
import http.client
from typing import Tuple, List, Optional
from requests.exceptions import RequestException
from sentin4e.exceptions import (
    ExcessiveHeadersError,
    MalformedResponseError,
    ConnectionClosedError,
    RedirectLoopError,
    SSLValidationError,
    TimeoutError,
    UnknownNetworkError,
    Sentin4eException
)

def _classify_exception(e: Exception) -> Sentin4eException:
    """
    Unwraps the exception chain and classifies the root cause accurately.
    Preserves the original exception chain in the `.original_exception` attribute.
    """
    current_e = e
    # Unroll the chain
    root_cause = e
    while current_e is not None:
        if isinstance(current_e, http.client.HTTPException):
            root_cause = current_e
            break
        elif isinstance(current_e, urllib3.exceptions.ProtocolError):
            root_cause = current_e
            # Try to dig deeper into args
            if len(current_e.args) > 1 and isinstance(current_e.args[1], Exception):
                current_e = current_e.args[1]
                continue
        # Check __cause__ or __context__
        if current_e.__cause__ is not None:
            current_e = current_e.__cause__
        elif current_e.__context__ is not None:
            current_e = current_e.__context__
        elif hasattr(current_e, 'args') and len(current_e.args) > 0 and isinstance(current_e.args[0], Exception):
            current_e = current_e.args[0]
        else:
            break
            
    # Classify the root cause
    if isinstance(root_cause, http.client.LineTooLong):
        return MalformedResponseError("Server returned a malformed response (LineTooLong).", original_exception=e)
    elif isinstance(root_cause, http.client.RemoteDisconnected):
        return ConnectionClosedError("Server closed the connection unexpectedly.", original_exception=e)
    elif isinstance(root_cause, http.client.BadStatusLine):
        return MalformedResponseError("Server returned an invalid HTTP status line (WAF drop/ban).", original_exception=e)
    elif isinstance(root_cause, http.client.HTTPException):
        err_str = str(root_cause).lower()
        if "got more than" in err_str and "headers" in err_str:
            return ExcessiveHeadersError("Server returned too many headers (exceeded http.client max headers limit).", original_exception=e)
        return MalformedResponseError(f"HTTP protocol error: {str(root_cause)}", original_exception=e)
    elif isinstance(root_cause, urllib3.exceptions.ProtocolError):
        return MalformedResponseError(f"Underlying protocol error: {str(root_cause)}", original_exception=e)
    elif isinstance(root_cause, requests.exceptions.TooManyRedirects):
        return RedirectLoopError("Exceeded maximum allowed redirects.", original_exception=e)
    elif isinstance(root_cause, requests.exceptions.SSLError):
        return SSLValidationError(f"SSL/TLS verification failed: {str(root_cause)}", original_exception=e)
    elif isinstance(root_cause, requests.exceptions.Timeout):
        return TimeoutError("Connection timed out.", original_exception=e)
    
    return UnknownNetworkError(f"Network error: {str(e)}", original_exception=e)

def fetch_url_with_retry(
    url: str, 
    max_retries: int = 3, 
    timeout: int = 10,
    insecure: bool = False,
    user_agent: str = "Sentin4e-Analyzer/1.0"
) -> Tuple[requests.Response, List[requests.Response]]:
    """Fetch URL directly with connection retries but manual redirect handling."""
    
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
    session = requests.Session()
    session.max_redirects = 5
    session.headers.update({'User-Agent': user_agent})
    
    last_exception = None
    
    for attempt in range(1, max_retries + 1):
        try:
            response = session.get(
                url, 
                timeout=timeout, 
                allow_redirects=True, 
                verify=not insecure
            )
            return response, response.history
            
        except RequestException as e:
            last_exception = e
            
            # Certain exceptions should NOT be retried
            classified = _classify_exception(e)
            if isinstance(classified, (SSLValidationError, RedirectLoopError)):
                raise classified
                
        if attempt < max_retries:
            time.sleep(2 ** attempt)
            
    if last_exception:
        raise _classify_exception(last_exception)
        
    raise UnknownNetworkError("Unknown error occurred during fetch.")

def fetch_with_redirect_history(
    url: str, 
    max_retries: int = 3, 
    timeout: int = 10,
    insecure: bool = False,
    user_agent: str = "Sentin4e-Analyzer/1.0"
) -> Tuple[requests.Response, List[requests.Response]]:
    """Fetch URL and traverse up to max_retries manually."""
    return fetch_url_with_retry(url, max_retries=max_retries, timeout=timeout, insecure=insecure, user_agent=user_agent)
