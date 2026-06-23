from urllib.parse import urlparse
from guardcli.models.report import Finding, Severity

def check_https(url: str) -> Finding:
    parsed = urlparse(url)
    if parsed.scheme == "https":
        return Finding(
            check_name="HTTPS Enabled",
            status="PASS",
            severity=Severity.INFO,
            message="Target is using HTTPS.",
            recommendation="Ensure TLS 1.2 or higher is configured."
        )
    return Finding(
        check_name="HTTPS Enabled",
        status="FAIL",
        severity=Severity.CRITICAL,
        message="Target is using unencrypted HTTP.",
        recommendation="Migrate to HTTPS immediately."
    )
