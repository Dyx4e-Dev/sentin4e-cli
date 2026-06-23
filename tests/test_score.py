from guardcli.scanner.score import calculate_score
from guardcli.models.report import Finding, Severity

def test_perfect_score():
    findings = [
        Finding(check_name="Check 1", status="PASS", severity=Severity.INFO, message="", recommendation="")
    ]
    score, risk = calculate_score(findings)
    assert score == 100
    assert risk == "Low"

def test_critical_finding():
    findings = [
        Finding(check_name="Check 1", status="PASS", severity=Severity.INFO, message="", recommendation=""),
        Finding(check_name="Check 2", status="FAIL", severity=Severity.CRITICAL, message="", recommendation="")
    ]
    score, risk = calculate_score(findings)
    assert score == 80
    assert risk == "Critical"

def test_multiple_findings():
    findings = [
        Finding(check_name="Check 2", status="FAIL", severity=Severity.MEDIUM, message="", recommendation=""),
        Finding(check_name="Check 3", status="FAIL", severity=Severity.LOW, message="", recommendation="")
    ]
    score, risk = calculate_score(findings)
    assert score == 85
    assert risk == "Medium"
