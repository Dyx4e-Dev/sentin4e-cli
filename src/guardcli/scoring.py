from typing import List, Tuple
from guardcli.schemas import Finding, AuditEntry

def calculate_score(findings: List[Finding]) -> Tuple[int, str, List[AuditEntry]]:
    """
    Calculate the linear score based on security findings and audit history.
    """
    base_score = 100
    
    # Base penalty weights for MISSING or INSECURE findings
    penalty_weights = {
        "CRITICAL": 20,
        "MEDIUM": 10,
        "LOW": 5,
        "INFO": 0
    }

    # Custom override table for exact deduction logic
    custom_penalties = {
        "HTTPS": {"MISSING": 30, "WEAK": 15},
        "Strict-Transport-Security": {"MISSING": 10, "WEAK": 5, "INVALID": 10},
        "Content-Security-Policy": {"MISSING": 20, "INSECURE": 20, "WEAK": 10, "ACCEPTABLE": 0},
        "Content-Security-Policy-Report-Only": {"ACCEPTABLE": 5, "WEAK": 10, "INSECURE": 20}, # if we fallback to report-only
        "X-Content-Type-Options": {"MISSING": 10, "INVALID": 10},
        "X-Frame-Options": {"MISSING": 10, "WEAK": 5},
        "Referrer-Policy": {"MISSING": 5},
        "Permissions-Policy": {"MISSING": 5},
        "Server Information Disclosure": {"INFO": 0}, # Informational, no penalty
        "Excessive Header Count": {"INVALID": 15},
        "Duplicate Security Headers": {"INVALID": 10},
        "Response Parsing Failure": {"INVALID": 10}
    }
    
    total_penalty = 0
    audit_log: List[AuditEntry] = []
    
    for f in findings:
        penalty = 0
        if f.status not in ("STRONG", "PRESENT"):
            # Check if there is a custom override
            if f.header in custom_penalties and f.status in custom_penalties[f.header]:
                penalty = custom_penalties[f.header][f.status]
            else:
                # Default penalty
                penalty = penalty_weights.get(f.severity, 0)
                
            total_penalty += penalty
            
        f.penalty = penalty
        audit_log.append(AuditEntry(header=f.header, status=f.status, penalty=penalty))
        
    final_score = max(0, base_score - total_penalty)
    grade = get_risk_level(final_score)
    
    return final_score, grade, audit_log

def get_risk_level(score: int) -> str:
    """
    Map a numerical score to a security grade.
    """
    if score >= 90:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 50:
        return "C"
    elif score >= 30:
        return "D"
    else:
        return "F"
