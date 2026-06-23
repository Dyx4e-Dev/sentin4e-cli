from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from guardcli.models.report import Report, Severity

console = Console()

def get_color_for_status(status: str) -> str:
    if status == "PASS":
        return "green"
    elif status == "WARN":
        return "yellow"
    else:
        return "red"

def render_report(report: Report) -> None:
    """Renders the scan report to the terminal using rich."""
    console.print()
    console.print(f"[bold cyan]Target:[/bold cyan] {report.target}")
    console.print()

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Status", style="bold", width=8)
    table.add_column("Check", style="cyan")
    table.add_column("Severity")
    table.add_column("Message")

    for finding in report.findings:
        color = get_color_for_status(finding.status)
        
        severity_color = "white"
        if finding.severity == Severity.CRITICAL:
            severity_color = "bold red"
        elif finding.severity == Severity.HIGH:
            severity_color = "red"
        elif finding.severity == Severity.MEDIUM:
            severity_color = "yellow"
        elif finding.severity == Severity.LOW:
            severity_color = "blue"

        table.add_row(
            f"[{color}]{finding.status}[/{color}]",
            finding.check_name,
            f"[{severity_color}]{finding.severity.value}[/{severity_color}]",
            finding.message
        )

    console.print(table)
    console.print()
    
    score_color = "green" if report.score >= 80 else "yellow" if report.score >= 50 else "red"
    risk_color = "green" if report.risk == "Low" else "yellow" if report.risk == "Medium" else "red"

    summary_text = Text()
    summary_text.append("Score: ", style="bold")
    summary_text.append(f"{report.score}/100\n", style=f"bold {score_color}")
    summary_text.append("Risk: ", style="bold")
    summary_text.append(f"{report.risk}", style=f"bold {risk_color}")

    console.print(Panel(summary_text, title="Summary", expand=False))
    console.print()
