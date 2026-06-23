from typing import List, Tuple
from guardcli.models.report import Finding, Severity
from guardcli.scanner.weights import SEVERITY_WEIGHTS

def calculate_score(findings: List[Finding]) -> Tuple[int, str]:
    """
    Calculates the security score out of 100 based on the findings.
    Also determines the overall risk level based on the final score.
    """
    score = 100

    for finding in findings:
        if finding.status != "PASS":
            score -= SEVERITY_WEIGHTS.get(finding.severity, 0)

    score = max(0, score)
    
    if score >= 90:
        risk = "Low"
    elif score >= 75:
        risk = "Medium"
    elif score >= 50:
        risk = "High"
    else:
        risk = "Critical"

    return score, risk
