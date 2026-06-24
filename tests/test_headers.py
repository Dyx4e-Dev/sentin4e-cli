import pytest
from guardcli.headers import analyze_security_headers

# --- HSTS Tests ---

def test_hsts_parsing_case_insensitive():
    """HSTS with weird casing and spacing should be recognized as STRONG."""
    headers = {
        "sTrIcT-TrAnSpOrT-SeCuRiTy": "  max-age = 31536000 ; iNcLuDeSuBdOmAiNs"
    }
    findings = analyze_security_headers(headers, is_https=True)
    hsts = next(f for f in findings if f.header == "Strict-Transport-Security")
    assert hsts.status == "STRONG"

def test_hsts_weak_max_age():
    """HSTS with max-age under 1 year should be WEAK."""
    headers = {
        "Strict-Transport-Security": "max-age=123"
    }
    findings = analyze_security_headers(headers, is_https=True)
    hsts = next(f for f in findings if f.header == "Strict-Transport-Security")
    assert hsts.status == "WEAK"

def test_hsts_missing_includesubdomains():
    """HSTS with sufficient max-age but no includeSubDomains should be WEAK."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000"
    }
    findings = analyze_security_headers(headers, is_https=True)
    hsts = next(f for f in findings if f.header == "Strict-Transport-Security")
    assert hsts.status == "WEAK"

def test_hsts_with_preload():
    """HSTS with max-age, includeSubDomains, and preload should be STRONG."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"
    }
    findings = analyze_security_headers(headers, is_https=True)
    hsts = next(f for f in findings if f.header == "Strict-Transport-Security")
    assert hsts.status == "STRONG"

def test_duplicate_headers_simulate_joined():
    """HTTP clients join duplicate headers with commas. First max-age wins."""
    headers = {
        "Strict-Transport-Security": "max-age=31536000, max-age=123"
    }
    findings = analyze_security_headers(headers, is_https=True)
    hsts = next(f for f in findings if f.header == "Strict-Transport-Security")
    # First max-age matches 31536000, but no includeSubdomains present
    assert hsts.status == "WEAK"

# --- CSP Directive-Aware Tests ---

def test_csp_script_src_unsafe_inline_unmitigated():
    """unsafe-inline in script-src without nonce/hash/strict-dynamic = INSECURE."""
    headers = {
        "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline';"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    assert csp.status == "INSECURE"

def test_csp_style_src_unsafe_inline_only():
    """unsafe-inline in style-src ONLY (no script-src issue) = ACCEPTABLE."""
    headers = {
        "Content-Security-Policy": "default-src 'none'; script-src github.githubassets.com; style-src 'unsafe-inline' github.githubassets.com;"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    assert csp.status == "ACCEPTABLE"
    assert "style-src" in csp.description

def test_csp_script_src_unsafe_inline_with_nonce():
    """unsafe-inline in script-src WITH nonce = ACCEPTABLE (browser ignores inline)."""
    headers = {
        "Content-Security-Policy": "script-src 'nonce-abc123' 'unsafe-inline';"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    assert csp.status == "ACCEPTABLE"
    assert "mitigated" in csp.description

def test_csp_script_src_unsafe_eval_without_strict_dynamic():
    """unsafe-eval in script-src without strict-dynamic = WEAK."""
    headers = {
        "Content-Security-Policy": "script-src 'self' 'unsafe-eval';"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    assert csp.status == "WEAK"

def test_csp_script_src_unsafe_eval_with_strict_dynamic():
    """unsafe-eval in script-src WITH strict-dynamic = ACCEPTABLE."""
    headers = {
        "Content-Security-Policy": "script-src 'nonce-abc' 'strict-dynamic' 'unsafe-eval' 'unsafe-inline';"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    assert csp.status in ("ACCEPTABLE",)  # mitigated by strict-dynamic + nonce

def test_csp_report_only_fallback():
    """CSP-Report-Only with safe config = ACCEPTABLE (not enforced)."""
    headers = {
        "Content-Security-Policy-Report-Only": "default-src 'self'"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy-Report-Only")
    assert csp.status == "ACCEPTABLE"
    assert "Report-Only" in csp.description

def test_csp_report_only_with_strict_dynamic_and_nonce():
    """Google-style CSP-Report-Only with nonce + strict-dynamic + unsafe-eval/inline = ACCEPTABLE."""
    headers = {
        "Content-Security-Policy-Report-Only": "object-src 'none';base-uri 'self';script-src 'nonce-abc123' 'strict-dynamic' 'report-sample' 'unsafe-eval' 'unsafe-inline' https: http:;report-uri https://csp.withgoogle.com/csp/gws"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy-Report-Only")
    assert csp.status == "ACCEPTABLE"

def test_csp_strong_policy():
    """Fully strict CSP with no unsafe directives = STRONG."""
    headers = {
        "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';"
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    assert csp.status == "STRONG"

def test_csp_missing():
    """No CSP header at all = MISSING."""
    headers = {}
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    assert csp.status == "MISSING"

# --- GitHub Real-World Simulation ---

def test_github_csp_style_unsafe_inline():
    """GitHub-style CSP: unsafe-inline only in style-src, script-src is clean."""
    headers = {
        "Content-Security-Policy": (
            "default-src 'none'; "
            "script-src github.githubassets.com; "
            "style-src 'unsafe-inline' github.githubassets.com; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'"
        )
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    # unsafe-inline is ONLY in style-src, script-src is fine
    assert csp.status == "ACCEPTABLE", f"Expected ACCEPTABLE, got {csp.status}: {csp.description}"
    assert csp.status != "INSECURE"

# --- Cloudflare Real-World Simulation ---

def test_cloudflare_csp_unsafe_inline_in_script_and_style():
    """Cloudflare-style CSP: unsafe-inline AND unsafe-eval in script-src without strict-dynamic."""
    headers = {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://static.cloudflareinsights.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:;"
        )
    }
    findings = analyze_security_headers(headers, is_https=True)
    csp = next(f for f in findings if f.header == "Content-Security-Policy")
    # unsafe-inline in script-src without nonce/hash/strict-dynamic = INSECURE
    assert csp.status == "INSECURE"

# --- Case insensitivity ---

def test_case_insensitive_header_lookup():
    """All headers should be found regardless of casing."""
    headers = {
        "STRICT-TRANSPORT-SECURITY": "max-age=31536000; includeSubDomains",
        "CONTENT-SECURITY-POLICY": "default-src 'self'",
        "X-FRAME-OPTIONS": "DENY",
        "X-CONTENT-TYPE-OPTIONS": "nosniff",
        "REFERRER-POLICY": "strict-origin-when-cross-origin",
        "PERMISSIONS-POLICY": "geolocation=()",
        "SERVER": "Apache"
    }
    findings = analyze_security_headers(headers, is_https=True)
    statuses = {f.header: f.status for f in findings}
    assert statuses["Strict-Transport-Security"] == "STRONG"
    assert statuses["Content-Security-Policy"] == "STRONG"
    assert statuses["X-Frame-Options"] == "STRONG"
    assert statuses["X-Content-Type-Options"] == "STRONG"
    assert statuses["Referrer-Policy"] == "STRONG"
    assert statuses["Permissions-Policy"] == "STRONG"

# --- Server Disclosure ---

def test_server_disclosure_is_informational():
    """Server header disclosure should be INFO, not penalized."""
    headers = {
        "Server": "nginx/1.18.0"
    }
    findings = analyze_security_headers(headers, is_https=True)
    server = next(f for f in findings if f.header == "Server Information Disclosure")
    assert server.status == "INFO"
    assert server.severity == "INFO"
