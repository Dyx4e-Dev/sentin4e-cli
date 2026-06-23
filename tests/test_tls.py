from guardcli.scanner.tls import check_https
from guardcli.models.report import Severity

def test_check_https_pass():
    finding = check_https("https://example.com")
    assert finding.status == "PASS"

def test_check_https_fail():
    finding = check_https("http://example.com")
    assert finding.status == "FAIL"
    assert finding.severity == Severity.CRITICAL
