from guardcli.scanner.headers import scan_headers
from guardcli.models.report import Severity

def test_scan_headers_all_missing():
    headers = {}
    findings = scan_headers(headers)
    
    assert len(findings) == 7
    fail_findings = [f for f in findings if f.status in ("FAIL", "WARN")]
    # All but server disclosure should fail/warn when empty
    assert len(fail_findings) == 6 

def test_hsts_present():
    headers = {"strict-transport-security": "max-age=31536000"}
    findings = scan_headers(headers)
    
    hsts_finding = next(f for f in findings if "HSTS" in f.check_name)
    assert hsts_finding.status == "PASS"

def test_server_disclosure():
    headers = {"server": "nginx/1.20"}
    findings = scan_headers(headers)
    
    server_finding = next(f for f in findings if "Server Disclosure" in f.check_name)
    assert server_finding.status == "WARN"
    assert server_finding.severity == Severity.LOW
