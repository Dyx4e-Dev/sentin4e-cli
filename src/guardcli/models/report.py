from enum import Enum
from typing import List
from pydantic import BaseModel, Field

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Finding(BaseModel):
    check_name: str
    status: str
    severity: Severity
    message: str
    recommendation: str

class Report(BaseModel):
    target: str
    score: int
    risk: str
    findings: List[Finding] = Field(default_factory=list)
