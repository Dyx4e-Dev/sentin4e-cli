from typing import List, Tuple
from guardcli.models.report import Finding, Severity
from guardcli.scanner.weights import SEVERITY_WEIGHTS

def calculate_score(findings: List[Finding]) -> Tuple[int, str]:
    """
    Calculates the security score out of 100 based on the findings.
    Also determines the overall risk level.
    """
    score = 100
    highest_severity = Severity.INFO

    for finding in findings:
        if finding.status != "PASS":
            score -= SEVERITY_WEIGHTS.get(finding.severity, 0)
            
            # Determine highest risk
            if SEVERITY_WEIGHTS[finding.severity] > SEVERITY_WEIGHTS[highest_severity]:
                highest_severity = finding.severity

    score = max(0, score)
    
    # Map max severity encountered to overall Risk Level
    # If there are no non-passing findings, risk is None or Low.
    if highest_severity == Severity.INFO:
        risk = "Low"
    elif highest_severity == Severity.LOW:
        risk = "Low"
    elif highest_severity == Severity.MEDIUM:
        risk = "Medium"
    elif highest_severity == Severity.HIGH:
        risk = "High"
    elif highest_severity == Severity.CRITICAL:
        risk = "Critical"
    else:
        risk = "Unknown"

    # Additional score bounds check for risk mapping, in case multiple low findings drop score significantly
    if score < 50 and risk in ("Low", "Medium"):
        risk = "High"

    return score, risk
