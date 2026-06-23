import sys
import time
import typer
import httpx
from rich.console import Console
from guardcli import __version__
from guardcli.utils.validator import validate_url
from guardcli.utils.logger import setup_logger
from guardcli.scanner.headers import scan_headers
from guardcli.scanner.tls import check_https
from guardcli.scanner.score import calculate_score
from guardcli.output.terminal import render_report
from guardcli.output.json_export import export_json
from guardcli.models.report import Report
from guardcli.exceptions import GuardCLIError, InvalidTargetError, TLSValidationError, ScanTimeoutError

app = typer.Typer(help="GuardCLI - Defensive cybersecurity CLI tool.", no_args_is_help=True)
console = Console()

def perform_scan(url: str, timeout: int, verbose: bool, retries: int = 3) -> Report:
    """Performs the actual scanning logic with retries and TLS validation."""
    logger = setup_logger(verbose)
    target = validate_url(url)
    
    last_error = None
    for attempt in range(retries):
        try:
            logger.debug(f"Attempt {attempt + 1}/{retries} connecting to {target}...")
            with httpx.Client(timeout=timeout, verify=True) as client:
                response = client.get(target, follow_redirects=True)
                
            findings = []
            findings.append(check_https(str(response.url)))
            findings.extend(scan_headers(dict(response.headers)))
            
            score, risk = calculate_score(findings)
            
            return Report(
                target=target,
                score=score,
                risk=risk,
                findings=findings
            )
        except httpx.TimeoutException:
            last_error = ScanTimeoutError(f"Connection to {target} timed out after {timeout} seconds.")
            logger.debug(str(last_error))
        except httpx.ConnectError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e) or "ssl" in str(e).lower():
                raise TLSValidationError(f"TLS/SSL validation failed for {target}: {str(e)}")
            last_error = GuardCLIError(f"Failed to connect to {target}: {str(e)}")
            logger.debug(str(last_error))
        except httpx.RequestError as e:
            last_error = GuardCLIError(f"Failed to connect to {target}: {str(e)}")
            logger.debug(str(last_error))
            
        time.sleep(1) # simple backoff
        
    raise last_error

@app.command()
def scan(
    url: str = typer.Argument(..., help="The target URL to scan"),
    timeout: int = typer.Option(10, help="Connection timeout in seconds"),
    output: str = typer.Option(None, "--output", "-o", help="Path to export JSON report"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging")
):
    """Scan a target URL for security headers and configurations."""
    try:
        with console.status(f"[bold green]Scanning {url}...") as status:
            report = perform_scan(url, timeout, verbose)
            
        render_report(report)
        
        if output:
            export_json(report, output)
            console.print(f"[bold green]Report exported to {output}[/bold green]")
            
    except GuardCLIError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

@app.command()
def headers(url: str = typer.Argument(..., help="The target URL to inspect")):
    """Quickly fetch and display HTTP headers only."""
    try:
        target = validate_url(url)
        with httpx.Client(timeout=10, verify=False) as client:
            response = client.get(target, follow_redirects=True)
            
        console.print(f"\n[bold cyan]Headers for {target}:[/bold cyan]")
        for k, v in response.headers.items():
            console.print(f"[bold]{k}:[/bold] {v}")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

@app.command()
def export(
    url: str = typer.Argument(..., help="The target URL to scan"),
    output: str = typer.Option("report.json", "--output", "-o"),
    verbose: bool = typer.Option(False, "--verbose", "-v")
):
    """Scan and export the results to JSON without rendering terminal output."""
    try:
        report = perform_scan(url, 10, verbose)
        export_json(report, output)
        console.print(f"Exported JSON to {output}")
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

@app.command()
def doctor():
    """Check system requirements and dependencies."""
    console.print("[bold cyan]GuardCLI System Check[/bold cyan]")
    console.print(f"Python Version: {sys.version.split(' ')[0]}")
    console.print(f"GuardCLI Version: {__version__}")
    
    # Check basic network connectivity
    try:
        httpx.get("https://1.1.1.1", timeout=5, verify=False)
        console.print("Network: [green]OK[/green] (Able to reach 1.1.1.1)")
    except Exception:
        console.print("Network: [red]FAIL[/red] (Unable to reach the internet)")

@app.command()
def version():
    """Show the current version."""
    console.print(f"GuardCLI version {__version__}")

if __name__ == "__main__":
    app()
