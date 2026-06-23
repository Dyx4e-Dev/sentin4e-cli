import json
from pathlib import Path
from guardcli.models.report import Report
from guardcli.output.serializers import report_to_dict

def export_json(report: Report, file_path: str) -> None:
    """Exports a Report to a JSON file."""
    data = report_to_dict(report)
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
