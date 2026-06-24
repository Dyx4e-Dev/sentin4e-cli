import json
from dataclasses import asdict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from guardcli.schemas import ReportV2

console = Console()

def get_status_color(status: str) -> str:
    """Return a rich color tag based on the security status."""
    if status in ("PRESENT", "STRONG"):
        return "green"
    elif status == "ACCEPTABLE":
        return "green yellow"
    elif status == "WEAK":
        return "yellow"
    elif status in ("MISSING", "INVALID", "INSECURE"):
        return "red"
    else:
        return "white"

def get_severity_color(severity: str) -> str:
    """Return a rich color tag based on the severity level."""
    if severity == "CRITICAL":
        return "bold red"
    elif severity == "MEDIUM":
        return "yellow"
    elif severity == "LOW":
        return "cyan"
    else:
        return "white"

def render_report(report: ReportV2) -> None:
    """
    Renders the Report object to the terminal using Rich.
    """
    console.print()
    
    # Target Info Panel
    target_info = (
        f"[bold]Target:[/bold] {report.target.url}\n"
        f"[bold]Status Code:[/bold] {report.target.status_code}\n"
        f"[bold]WAF Detected:[/bold] {report.target.waf_detected}\n"
        f"[bold]Analysis Mode:[/bold] {report.target.analysis_mode}\n"
        f"[bold]Parsed Via:[/bold] {report.target.parsed_via}\n"
        f"[bold]Confidence:[/bold] {report.target.analysis_confidence}\n"
        f"[bold]Reliability:[/bold] {report.target.analysis_reliability}\n"
        f"[bold]Scan Integrity:[/bold] {report.target.scan_integrity}"
    )
    console.print(Panel(target_info, title="[bold blue]Scan Target[/bold blue]", border_style="blue"))
    
    # Partial Analysis Banner
    if report.target.analysis_reliability != "RELIABLE":
        banner = (
            "[bold red]PARTIAL ANALYSIS[/bold red]\n\n"
            "This report was generated using fallback inspection or encountered a failure.\n"
            "Some findings could not be fully verified.\n"
            "Security posture score has been suppressed."
        )
        if report.results.analysis_limitations:
            banner += "\n\n[bold]Reason:[/bold]\n" + "\n".join(f"- {reason}" for reason in report.results.analysis_limitations)
        console.print(Panel(banner, border_style="red"))

    # Diagnostics Panel
    if report.results.diagnostics:
        diag = report.results.diagnostics
        diag_text = ""
        if "root_cause" in diag:
            diag_text += f"[bold]Root Cause:[/bold]\n{diag['root_cause']}\n\n"
        
        diag_text += "[bold]Observed:[/bold]\n"
        for k, v in diag.items():
            if k not in ("root_cause", "possible_infrastructure_issues"):
                diag_text += f"- {k}: {v}\n"
                
        if "possible_infrastructure_issues" in diag:
            diag_text += "\n[bold yellow]Possible Infrastructure Issues:[/bold yellow]\n"
            for issue in diag["possible_infrastructure_issues"]:
                diag_text += f"- {issue}\n"
                
        console.print(Panel(diag_text.strip(), title="[bold yellow]Diagnostics[/bold yellow]", border_style="yellow"))

    # Score Panel
    score = report.results.summary.score
    grade = report.results.summary.grade
    
    if score is None:
        score_panel = "[bold]Score:[/bold] N/A\n[bold]Grade:[/bold] N/A"
        console.print(Panel(score_panel, title="[bold magenta]Security Posture[/bold magenta]", border_style="magenta"))
    else:
        if score >= 90:
            score_color = "green"
        elif score >= 70:
            score_color = "yellow"
        elif score >= 50:
            score_color = "orange3"
        else:
            score_color = "red"
            
        score_panel = (
            f"[bold]Score:[/bold] [{score_color}]{score}/100[/{score_color}]\n"
            f"[bold]Grade:[/bold] [{score_color}]{grade}[/{score_color}]"
        )
        console.print(Panel(score_panel, title="[bold magenta]Security Posture[/bold magenta]", border_style="magenta"))
    
    # Findings Table
    table = Table(title="Security Headers Analysis", show_header=True, header_style="bold cyan")
    table.add_column("Header")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Description / Recommendation")
    
    for f in report.results.headers:
        status_styled = f"[{get_status_color(f.status)}]{f.status}[/]"
        severity_styled = f"[{get_severity_color(f.severity)}]{f.severity}[/]"
        
        desc = f.description
        if f.recommendation:
            desc += f"\n[dim]{f.recommendation}[/dim]"
            
        desc += f"\n[dim italic]Confidence: {f.finding_confidence} | Category: {f.finding_category}[/dim italic]"
            
        table.add_row(f.header, status_styled, severity_styled, desc)
        
    console.print(table)
    console.print()

def export_json(report: ReportV2, path: str, version: str = "v2") -> None:
    """
    Exports the report to a JSON file safely.
    """
    try:
        with open(path, "w", encoding="utf-8") as f:
            if version == "v1":
                # Convert to V1 format for legacy compat
                v1_dict = {
                    "url": report.target.url,
                    "score": report.results.summary.score,
                    "grade": report.results.summary.grade,
                    "findings": [asdict(finding) for finding in report.results.headers]
                }
                json.dump(v1_dict, f, indent=2)
            else:
                json.dump(asdict(report), f, indent=2)
    except PermissionError:
        raise Exception(f"Permission denied: Cannot write to {path}")
    except OSError as e:
        raise Exception(f"OS error occurred while writing to {path}: {str(e)}")
    except Exception as e:
        raise Exception(f"Unexpected error during JSON serialization: {str(e)}")
