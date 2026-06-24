from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

@dataclass
class Finding:
    """Represents a single security header finding."""
    header: str
    status: str  # "STRONG", "ACCEPTABLE", "WEAK", "INSECURE", "PRESENT", "MISSING", "INVALID"
    severity: str  # "INFO", "LOW", "MEDIUM", "CRITICAL"
    description: str
    value: Optional[str] = None
    recommendation: Optional[str] = None
    penalty: int = 0
    finding_confidence: str = "VERIFIED"  # "VERIFIED", "ESTIMATED", "HEURISTIC"
    finding_category: str = "SECURITY"    # "SECURITY", "INFRASTRUCTURE", "NETWORK", "COMPLIANCE", "INFORMATIONAL"
    evidence: Optional[str] = None

@dataclass
class TargetInfo:
    """Information about the scanned target."""
    url: str
    status_code: int
    ip: Optional[str] = None
    waf_detected: str = "UNKNOWN"
    scan_context: str = "FULL_SCAN"
    analysis_confidence: str = "HIGH"
    analysis_reliability: str = "RELIABLE"
    scan_integrity: str = "COMPLETE"
    analysis_mode: str = "NORMAL_SCAN"
    parsed_via: str = "requests/http.client"

@dataclass
class ScanMeta:
    """Metadata regarding the scan itself."""
    scan_duration_ms: int
    scanner_name: str = "GuardCLI"
    version: str = "1.0.0"
    report_version: str = "2.0"
    scan_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

@dataclass
class ScanSummary:
    """Summary of the scan results."""
    score: Optional[int]
    grade: Optional[str]
    total_findings: int

@dataclass
class AuditEntry:
    header: str
    status: str
    penalty: int

@dataclass
class ScanResult:
    """Container for the summary and individual findings."""
    summary: ScanSummary
    headers: List[Finding]
    audit: List[AuditEntry] = field(default_factory=list)
    diagnostics: Optional[Dict[str, Any]] = None
    analysis_limitations: Optional[List[str]] = None

@dataclass
class ReportV2:
    """Version 2 of the GuardCLI JSON report schema."""
    meta: ScanMeta
    target: TargetInfo
    results: ScanResult

