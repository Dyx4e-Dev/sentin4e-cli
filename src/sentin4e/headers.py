# mypy: ignore-errors
import re
from typing import Dict, List
from sentin4e.schemas import Finding

def analyze_security_headers(headers: Dict[str, str], is_https: bool) -> List[Finding]:
    """
    Analyzes HTTP response headers for security misconfigurations.
    """
    findings = []
    
    # HTTP headers are case-insensitive.
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    headers_exact = {k.lower(): v for k, v in headers.items()}
    
    # 1. HTTPS enforcement
    if is_https:
        findings.append(Finding(
            header="HTTPS", status="STRONG", severity="INFO", value="Enabled",
            description="Connection is encrypted.", recommendation=None,
            finding_category="NETWORK"
        ))
    else:
        findings.append(Finding(
            header="HTTPS", status="MISSING", severity="CRITICAL", value=None,
            description="Connection is not encrypted.", recommendation="Enable HTTPS/TLS.",
            finding_category="NETWORK"
        ))

    # 2. HSTS
    hsts = headers_lower.get("strict-transport-security")
    if hsts:
        # Regex to find max-age regardless of spaces
        match = re.search(r"max-age\s*=\s*(\d+)", hsts)
        if match:
            try:
                age = int(match.group(1))
                if age < 31536000:
                    findings.append(Finding(
                        header="Strict-Transport-Security", status="WEAK", severity="MEDIUM", value=headers_exact.get("strict-transport-security"),
                        description="HSTS max-age is less than 1 year.", recommendation="Set max-age to at least 31536000."
                    ))
                elif "includesubdomains" not in hsts:
                    findings.append(Finding(
                        header="Strict-Transport-Security", status="WEAK", severity="MEDIUM", value=headers_exact.get("strict-transport-security"),
                        description="HSTS missing includeSubDomains.", recommendation="Add includeSubDomains to HSTS header."
                    ))
                else:
                    findings.append(Finding(
                        header="Strict-Transport-Security", status="STRONG", severity="INFO", value=headers_exact.get("strict-transport-security"),
                        description="HSTS is properly configured.", recommendation=None
                    ))
            except Exception:
                findings.append(Finding(
                    header="Strict-Transport-Security", status="INVALID", severity="MEDIUM", value=headers_exact.get("strict-transport-security"),
                    description="HSTS header is malformed.", recommendation="Fix HSTS header syntax."
                ))
        else:
            findings.append(Finding(
                header="Strict-Transport-Security", status="INVALID", severity="MEDIUM", value=headers_exact.get("strict-transport-security"),
                description="HSTS missing max-age.", recommendation="Add max-age directive."
            ))
    else:
        findings.append(Finding(
            header="Strict-Transport-Security", status="MISSING", severity="MEDIUM", value=None,
            description="HSTS header is missing.", recommendation="Implement HSTS to force HTTPS connections."
        ))

    # 3. CSP and CSP-Report-Only
    csp = headers_lower.get("content-security-policy")
    csp_report = headers_lower.get("content-security-policy-report-only")
    
    def _evaluate_csp(csp_str: str, exact_str: str, is_report_only: bool) -> Finding:
        header_name = "Content-Security-Policy-Report-Only" if is_report_only else "Content-Security-Policy"
        
        # --- Directive-aware CSP parsing ---
        directives = {}
        for part in csp_str.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive_name = tokens[0].lower()
                directive_values = [t.lower() for t in tokens[1:]]
                directives[directive_name] = directive_values
        
        script_values = directives.get("script-src", directives.get("default-src", []))
        style_values = directives.get("style-src", directives.get("default-src", []))
        
        script_has_unsafe_inline = "'unsafe-inline'" in script_values
        script_has_unsafe_eval = "'unsafe-eval'" in script_values
        script_has_nonce = any("'nonce-" in v for v in script_values)
        script_has_hash = any(v.startswith(("'sha256-", "'sha384-", "'sha512-")) for v in script_values)
        script_has_strict_dynamic = "'strict-dynamic'" in script_values
        
        style_has_unsafe_inline = "'unsafe-inline'" in style_values
        
        status = "STRONG"
        severity = "INFO"
        desc = "CSP is configured securely."
        
        if script_has_unsafe_inline and not (script_has_nonce or script_has_hash or script_has_strict_dynamic):
            status = "INSECURE"
            severity = "CRITICAL"
            desc = "CSP script-src contains 'unsafe-inline' without nonces, hashes, or strict-dynamic."
        elif script_has_unsafe_eval and not script_has_strict_dynamic:
            status = "WEAK"
            severity = "MEDIUM"
            desc = "CSP script-src contains 'unsafe-eval', which allows arbitrary code execution."
        elif script_has_unsafe_inline and (script_has_nonce or script_has_hash or script_has_strict_dynamic):
            status = "ACCEPTABLE"
            severity = "LOW"
            desc = "CSP script-src has 'unsafe-inline' but it is mitigated by nonces, hashes, or strict-dynamic."
        elif script_has_unsafe_eval and script_has_strict_dynamic:
            status = "ACCEPTABLE"
            severity = "LOW"
            desc = "CSP script-src has 'unsafe-eval' alongside strict-dynamic."
        
        if style_has_unsafe_inline and status == "STRONG":
            status = "ACCEPTABLE"
            severity = "LOW"
            desc = "CSP style-src uses 'unsafe-inline', which is common but not ideal."
        
        if is_report_only and status in ("STRONG", "ACCEPTABLE"):
            status = "ACCEPTABLE"
            severity = "LOW"
            desc = "CSP is in Report-Only mode (not enforced). " + desc
        
        recommendation = None
        if status == "INSECURE":
            recommendation = "Remove 'unsafe-inline' from script-src or add nonces/hashes/strict-dynamic."
        elif status == "WEAK":
            recommendation = "Consider removing 'unsafe-eval' from script-src if possible."
            
        return Finding(
            header=header_name, status=status, severity=severity, value=exact_str,
            description=desc, recommendation=recommendation
        )

    if csp:
        findings.append(_evaluate_csp(csp, headers_exact.get("content-security-policy"), False))
    else:
        findings.append(Finding(
            header="Content-Security-Policy", status="MISSING", severity="CRITICAL", value=None,
            description="CSP header is missing.", recommendation="Implement CSP to mitigate XSS attacks."
        ))
        
    if csp_report:
        findings.append(_evaluate_csp(csp_report, headers_exact.get("content-security-policy-report-only"), True))

    # 4. X-Frame-Options
    xfo = headers_lower.get("x-frame-options")
    if xfo:
        if "allow-from" in xfo:
            findings.append(Finding(
                header="X-Frame-Options", status="WEAK", severity="MEDIUM", value=headers_exact.get("x-frame-options"),
                description="ALLOW-FROM is obsolete and weakly supported.", recommendation="Use CSP frame-ancestors instead."
            ))
        else:
            findings.append(Finding(
                header="X-Frame-Options", status="STRONG", severity="INFO", value=headers_exact.get("x-frame-options"),
                description="X-Frame-Options is configured.", recommendation=None
            ))
    else:
        findings.append(Finding(
            header="X-Frame-Options", status="MISSING", severity="MEDIUM", value=None,
            description="X-Frame-Options header is missing.", recommendation="Implement X-Frame-Options to prevent clickjacking."
        ))

    # 5. X-Content-Type-Options
    xcto = headers_lower.get("x-content-type-options")
    if xcto == "nosniff":
        findings.append(Finding(
            header="X-Content-Type-Options", status="STRONG", severity="INFO", value=headers_exact.get("x-content-type-options"),
            description="X-Content-Type-Options is configured.", recommendation=None
        ))
    elif xcto:
        findings.append(Finding(
            header="X-Content-Type-Options", status="INVALID", severity="MEDIUM", value=headers_exact.get("x-content-type-options"),
            description="Invalid value for X-Content-Type-Options.", recommendation="Set X-Content-Type-Options to 'nosniff'."
        ))
    else:
        findings.append(Finding(
            header="X-Content-Type-Options", status="MISSING", severity="MEDIUM", value=None,
            description="X-Content-Type-Options header is missing.", recommendation="Set X-Content-Type-Options to 'nosniff'."
        ))

    # 6. Referrer-Policy
    rp = headers_lower.get("referrer-policy")
    if rp:
        findings.append(Finding(
            header="Referrer-Policy", status="STRONG", severity="INFO", value=headers_exact.get("referrer-policy"),
            description="Referrer-Policy is configured.", recommendation=None
        ))
    else:
        findings.append(Finding(
            header="Referrer-Policy", status="MISSING", severity="LOW", value=None,
            description="Referrer-Policy header is missing.", recommendation="Implement Referrer-Policy to protect user privacy."
        ))

    # 7. Permissions-Policy
    pp = headers_lower.get("permissions-policy")
    if pp:
        findings.append(Finding(
            header="Permissions-Policy", status="STRONG", severity="INFO", value=headers_exact.get("permissions-policy"),
            description="Permissions-Policy is configured.", recommendation=None
        ))
    else:
        findings.append(Finding(
            header="Permissions-Policy", status="MISSING", severity="LOW", value=None,
            description="Permissions-Policy header is missing.", recommendation="Implement Permissions-Policy to restrict browser features."
        ))

    # 8. Server disclosure
    server = headers_lower.get("server")
    x_powered_by = headers_lower.get("x-powered-by")
    
    if server or x_powered_by:
        value = headers_exact.get("server", "") + (" | " + headers_exact.get("x-powered-by", "") if x_powered_by else "")
        value = value.strip(" | ")
        findings.append(Finding(
            header="Server Information Disclosure", status="INFO", severity="INFO", value=value,
            description="Server or X-Powered-By header is present, leaking technology stack.", recommendation="Remove Server and X-Powered-By headers if possible.",
            finding_category="INFORMATIONAL"
        ))
    else:
        findings.append(Finding(
            header="Server Information Disclosure", status="STRONG", severity="INFO", value=None,
            description="No server information leaked.", recommendation=None,
            finding_category="INFORMATIONAL"
        ))

    return findings
