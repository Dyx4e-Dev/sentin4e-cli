import pytest
from guardcli.schemas import Finding
from guardcli.scoring import calculate_score

def test_perfect_score():
    findings = [
        Finding(header="HTTPS", status="STRONG", severity="INFO", description=""),
        Finding(header="Strict-Transport-Security", status="STRONG", severity="INFO", description=""),
        Finding(header="Content-Security-Policy", status="STRONG", severity="INFO", description=""),
        Finding(header="X-Frame-Options", status="STRONG", severity="INFO", description=""),
        Finding(header="X-Content-Type-Options", status="STRONG", severity="INFO", description=""),
        Finding(header="Referrer-Policy", status="STRONG", severity="INFO", description=""),
        Finding(header="Permissions-Policy", status="STRONG", severity="INFO", description=""),
        Finding(header="Server Information Disclosure", status="STRONG", severity="INFO", description=""),
    ]
    score, grade, audit_log = calculate_score(findings)
    assert score == 100
    assert grade == "A"
    assert all(a.penalty == 0 for a in audit_log)

def test_missing_hsts_score():
    findings = [
        Finding(header="Strict-Transport-Security", status="MISSING", severity="MEDIUM", description=""),
    ]
    score, grade, audit_log = calculate_score(findings)
    assert score == 90  # 100 - 10
    assert grade == "A"

def test_insecure_csp_score():
    findings = [
        Finding(header="Content-Security-Policy", status="INSECURE", severity="CRITICAL", description=""),
    ]
    score, grade, audit_log = calculate_score(findings)
    assert score == 80  # 100 - 20
    assert grade == "B"

def test_weak_csp_score():
    findings = [
        Finding(header="Content-Security-Policy", status="WEAK", severity="MEDIUM", description=""),
    ]
    score, grade, audit_log = calculate_score(findings)
    assert score == 90  # 100 - 10
    assert grade == "A"

def test_informational_server_disclosure():
    findings = [
        Finding(header="Server Information Disclosure", status="INFO", severity="INFO", description=""),
    ]
    score, grade, audit_log = calculate_score(findings)
    assert score == 100  # 100 - 0
    assert grade == "A"
    
def test_missing_multiple_headers():
    findings = [
        Finding(header="Strict-Transport-Security", status="MISSING", severity="MEDIUM", description=""), # 10
        Finding(header="Content-Security-Policy", status="MISSING", severity="CRITICAL", description=""), # 20
        Finding(header="X-Content-Type-Options", status="MISSING", severity="MEDIUM", description=""), # 10
    ]
    score, grade, audit_log = calculate_score(findings)
    assert score == 60 # 100 - 10 - 20 - 10
    assert grade == "C"
