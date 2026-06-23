from guardcli.models.report import Severity

# Weight values for different severity levels, used to reduce score from 100.
SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 10,
    Severity.HIGH: 15,
    Severity.CRITICAL: 20,
}
