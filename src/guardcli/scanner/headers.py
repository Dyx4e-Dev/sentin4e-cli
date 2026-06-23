from typing import List, Dict, Any
from guardcli.models.report import Finding, Severity

def check_hsts(headers: Dict[str, str]) -> Finding:
    header = headers.get("strict-transport-security")
    if header:
        return Finding(
            check_name="Strict-Transport-Security (HSTS)",
            status="PASS",
            severity=Severity.INFO,
            message="HSTS is enabled.",
            recommendation="Ensure max-age is set to at least 31536000 and includeSubDomains is used."
        )
    return Finding(
        check_name="Strict-Transport-Security (HSTS)",
        status="FAIL",
        severity=Severity.CRITICAL,
        message="HSTS header is missing.",
        recommendation="Enable HSTS to force secure connections over HTTPS."
    )

def check_csp(headers: Dict[str, str]) -> Finding:
    header = headers.get("content-security-policy")
    if header:
        return Finding(
            check_name="Content-Security-Policy (CSP)",
            status="PASS",
            severity=Severity.INFO,
            message="CSP is configured.",
            recommendation="Review policies to ensure they are strict and do not allow unsafe inline execution."
        )
    return Finding(
        check_name="Content-Security-Policy (CSP)",
        status="FAIL",
        severity=Severity.CRITICAL,
        message="CSP header is missing.",
        recommendation="Implement CSP to prevent XSS and data injection attacks."
    )

def check_x_frame_options(headers: Dict[str, str]) -> Finding:
    header = headers.get("x-frame-options")
    if header:
        return Finding(
            check_name="X-Frame-Options",
            status="PASS",
            severity=Severity.INFO,
            message=f"X-Frame-Options set to {header}.",
            recommendation="Consider using CSP frame-ancestors instead for modern browsers."
        )
    return Finding(
        check_name="X-Frame-Options",
        status="FAIL",
        severity=Severity.MEDIUM,
        message="X-Frame-Options header missing.",
        recommendation="Set to DENY or SAMEORIGIN to prevent clickjacking."
    )

def check_x_content_type_options(headers: Dict[str, str]) -> Finding:
    header = headers.get("x-content-type-options")
    if header and header.lower() == "nosniff":
        return Finding(
            check_name="X-Content-Type-Options",
            status="PASS",
            severity=Severity.INFO,
            message="X-Content-Type-Options is nosniff.",
            recommendation="None"
        )
    return Finding(
        check_name="X-Content-Type-Options",
        status="FAIL",
        severity=Severity.MEDIUM,
        message="X-Content-Type-Options is missing or incorrect.",
        recommendation="Set to 'nosniff' to prevent MIME-sniffing vulnerabilities."
    )

def check_referrer_policy(headers: Dict[str, str]) -> Finding:
    header = headers.get("referrer-policy")
    if header:
        return Finding(
            check_name="Referrer-Policy",
            status="PASS",
            severity=Severity.INFO,
            message="Referrer-Policy is present.",
            recommendation="Ensure policy does not leak sensitive info."
        )
    return Finding(
        check_name="Referrer-Policy",
        status="FAIL",
        severity=Severity.MEDIUM,
        message="Referrer-Policy is missing.",
        recommendation="Set a strict policy like 'no-referrer' or 'strict-origin-when-cross-origin'."
    )

def check_permissions_policy(headers: Dict[str, str]) -> Finding:
    header = headers.get("permissions-policy")
    if header:
        return Finding(
            check_name="Permissions-Policy",
            status="PASS",
            severity=Severity.INFO,
            message="Permissions-Policy is present.",
            recommendation="Ensure it restricts unused features."
        )
    return Finding(
        check_name="Permissions-Policy",
        status="WARN",
        severity=Severity.LOW,
        message="Permissions-Policy is missing.",
        recommendation="Implement this header to disable unneeded browser features and APIs."
    )

def check_server_disclosure(headers: Dict[str, str]) -> Finding:
    server = headers.get("server")
    x_powered_by = headers.get("x-powered-by")
    
    if server or x_powered_by:
        return Finding(
            check_name="Server Disclosure",
            status="WARN",
            severity=Severity.LOW,
            message=f"Server exposes technology stack (Server: {server}, X-Powered-By: {x_powered_by}).",
            recommendation="Remove Server and X-Powered-By headers to hide infrastructure details."
        )
    return Finding(
        check_name="Server Disclosure",
        status="PASS",
        severity=Severity.INFO,
        message="No server disclosure headers found.",
        recommendation="None"
    )

def scan_headers(headers: Dict[str, str]) -> List[Finding]:
    """Runs all header checks against provided headers (lowercased keys)."""
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    return [
        check_hsts(normalized_headers),
        check_csp(normalized_headers),
        check_x_frame_options(normalized_headers),
        check_x_content_type_options(normalized_headers),
        check_referrer_policy(normalized_headers),
        check_permissions_policy(normalized_headers),
        check_server_disclosure(normalized_headers)
    ]
