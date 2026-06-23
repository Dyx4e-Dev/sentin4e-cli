from typing import Any, Dict
from guardcli.models.report import Report

def report_to_dict(report: Report) -> Dict[str, Any]:
    """Serializes the Report model to a dictionary."""
    return report.model_dump()
