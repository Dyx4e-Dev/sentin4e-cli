from guardcli.scanner.score import calculate_score
from guardcli.models.report import Finding, Severity

def test_score_low_risk():
    findings = [
        Finding(check_name="C1", status="FAIL", severity=Severity.LOW, message="", recommendation="")
    ]
    score, risk = calculate_score(findings)
    assert score == 95
    assert risk == "Low"

def test_score_medium_risk():
    findings = [
        Finding(check_name="C1", status="FAIL", severity=Severity.CRITICAL, message="", recommendation="")
    ]
    score, risk = calculate_score(findings)
    assert score == 80
    assert risk == "Medium"

def test_score_high_risk():
    findings = [
        Finding(check_name="C1", status="FAIL", severity=Severity.CRITICAL, message="", recommendation=""),
        Finding(check_name="C2", status="FAIL", severity=Severity.CRITICAL, message="", recommendation="")
    ]
    score, risk = calculate_score(findings)
    assert score == 60
    assert risk == "High"

def test_score_critical_risk():
    findings = [
        Finding(check_name="C1", status="FAIL", severity=Severity.CRITICAL, message="", recommendation=""),
        Finding(check_name="C2", status="FAIL", severity=Severity.CRITICAL, message="", recommendation=""),
        Finding(check_name="C3", status="FAIL", severity=Severity.CRITICAL, message="", recommendation=""),
        Finding(check_name="C4", status="FAIL", severity=Severity.CRITICAL, message="", recommendation="")
    ]
    score, risk = calculate_score(findings)
    assert score == 20
    assert risk == "Critical"
