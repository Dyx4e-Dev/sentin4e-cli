import sys
import time
import traceback
from urllib.parse import urlparse
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentin4e.schemas import ReportV2, ScanMeta, TargetInfo, ScanResult, ScanSummary, Finding, AuditEntry
from sentin4e.retry import fetch_with_redirect_history
from sentin4e.waf_detector import detect_waf, analyze_response_context, is_parked_domain
from sentin4e.headers import analyze_security_headers
from sentin4e.scoring import calculate_score
from sentin4e.formatter import render_report, export_json
from sentin4e.exceptions import Sentin4eException, ExcessiveHeadersError
from sentin4e.raw_inspect import raw_inspect

app = typer.Typer(help="Sentin4e - Defensive cybersecurity CLI tool.", no_args_is_help=True, add_help_option=False)
console = Console()
__version__ = "1.0.0"

from typing import Optional
from sentin4e.dashboard import render_dashboard, render_help

def version_callback(value: bool):
    """Callback for rendering the dynamic version dashboard."""
    if value:
        render_dashboard(app)
        raise typer.Exit()

def help_callback(value: bool):
    """Callback for rendering the dynamic help system."""
    if value:
        render_help(app)
        raise typer.Exit()

@app.callback(invoke_without_command=True)
def main(
    version: Optional[bool] = typer.Option(
        None, "-v", "--version", callback=version_callback, is_eager=True, help="Show dynamic version dashboard."
    ),
    help_option: Optional[bool] = typer.Option(
        None, "--help", "-h", callback=help_callback, is_eager=True, help="Show dynamic help system."
    )
):
    """Sentin4e - Defensive cybersecurity CLI tool."""
    pass

def _render_fallback_report(url: str, inspection, user_agent: str, debug: bool) -> ReportV2:
    """Render a fallback report when normal parsing fails due to excessive headers."""
    start_time = time.time()

    console.print("\n[bold yellow]⚠ Fallback Inspection Mode[/bold yellow]")
    console.print("[dim]Standard HTTP client rejected the response (>100 headers).[/dim]")
    console.print("[dim]Using raw TLS socket to extract diagnostics.[/dim]\n")

    if not inspection.success:
        console.print(f"[bold red]Raw inspection failed:[/bold red] {inspection.error}")
        raise typer.Exit(code=1)

    # Status line
    console.print(Panel(
        f"[bold]Status Line:[/bold] {inspection.status_line}\n"
        f"[bold]Status Code:[/bold] {inspection.status_code}\n"
        f"[bold]Server:[/bold] {inspection.server_header or 'N/A'}\n"
        f"[bold]Total Headers Observed:[/bold] {inspection.total_header_count}\n"
        f"[bold]Raw Bytes Read:[/bold] {inspection.raw_bytes_read}\n"
        f"[bold]Truncated:[/bold] {inspection.truncated}",
        title="[bold blue]Raw Inspection Result[/bold blue]",
        border_style="blue"
    ))

    # Header Statistics Table
    stats_table = Table(title="Header Statistics (Top Duplicates)", show_header=True, header_style="bold cyan")
    stats_table.add_column("Header Name")
    stats_table.add_column("Occurrences", justify="right")

    duplicates_found = 0
    security_headers = {"x-frame-options", "content-security-policy", "x-content-type-options", "strict-transport-security", "x-xss-protection"}
    dup_security_headers_count = 0
    for name, count in inspection.top_duplicates:
        color = "red" if count > 10 else ("yellow" if count > 1 else "green")
        stats_table.add_row(name, f"[{color}]{count}[/{color}]")
        if count > 1:
            duplicates_found += 1
        if count > 10 and name.lower() in security_headers:
            dup_security_headers_count += 1

    console.print(stats_table)

    if debug:
        console.print("\n[bold cyan]First 50 Headers (Raw):[/bold cyan]")
        for name, value in inspection.headers:
            display_val = value if len(value) <= 80 else value[:77] + "..."
            console.print(f"  {name}: {display_val}")

    raw_header_dict = {}
    for name, value in inspection.headers:
        raw_header_dict[name] = value
    
    waf_detected = detect_waf(raw_header_dict, {})
    if waf_detected == "NOT_DETECTED":
        waf_detected = "UNKNOWN"
        
    findings = []
    
    # Analyze headers via standard engine, but override confidence
    is_https = urlparse(url).scheme == "https"
    base_findings = analyze_security_headers(raw_header_dict, is_https)
    for bf in base_findings:
        # Confidence Propagation Rule: UNRELIABLE -> HEURISTIC (except HTTPS which is verified by socket)
        if bf.header == "HTTPS":
            bf.finding_confidence = "VERIFIED"
        else:
            bf.finding_confidence = "HEURISTIC"
        findings.append(bf)

    top_dup_desc = ""
    if inspection.top_duplicates:
        top_name, top_count = inspection.top_duplicates[0]
        if top_count > 1:
            top_dup_desc = f" Most duplicated header: '{top_name}' ({top_count} occurrences)."

    findings.append(Finding(
        header="Excessive Header Count",
        status="INVALID",
        severity="MEDIUM",
        value=f"{inspection.total_header_count} headers observed",
        description=f"Server returned more than 100 HTTP headers, causing standard HTTP clients to reject the response.{top_dup_desc}",
        recommendation="Investigate server configuration for duplicate or unnecessary headers.",
        finding_category="INFRASTRUCTURE",
        finding_confidence="VERIFIED"
    ))

    findings.append(Finding(
        header="Response Parsing Failure",
        status="INVALID",
        severity="MEDIUM",
        value=None,
        description="Standard HTTP clients were unable to parse the response due to excessive header count. Some HTTP clients, SDKs, monitoring tools, and scanners may fail to process this response correctly.",
        recommendation="Resolve header limits.",
        finding_category="NETWORK",
        finding_confidence="VERIFIED"
    ))
    
    if duplicates_found > 0:
        findings.append(Finding(
            header="Duplicate Security Headers",
            status="INVALID",
            severity="MEDIUM",
            value=f"{duplicates_found} headers duplicated",
            description="Security header is repeated an excessive number of times. This may indicate reverse proxy misconfiguration, WAF misconfiguration, recursive header injection, or duplicated middleware configuration.",
            recommendation="Consolidate duplicate headers.",
            finding_category="INFRASTRUCTURE",
            finding_confidence="VERIFIED"
        ))

    waf_detected = detect_waf(dict(inspection.headers), {}) if inspection.headers else "UNKNOWN"
    
    diagnostics = {
        "root_cause": 'http.client.HTTPException("got more than 100 headers")',
        "observed_total_headers": inspection.total_header_count,
        "raw_tls_socket_used": True
    }
    
    if dup_security_headers_count > 0:
        diagnostics["possible_infrastructure_issues"] = [
            "Reverse Proxy Header Duplication",
            "Recursive Middleware Injection",
            "WAF Header Injection Loop",
            "Multi-Layer CDN Header Stacking"
        ]

    # Calculate audit log penalties, but suppress the final score/grade
    _, _, audit_log = calculate_score(findings)
    score = None
    grade = None

    scan_duration_ms = int((time.time() - start_time) * 1000)

    report = ReportV2(
        meta=ScanMeta(scanner_name="Sentin4e", version=__version__, scan_duration_ms=scan_duration_ms, report_version="2.0"),
        target=TargetInfo(
            url=url,
            status_code=inspection.status_code,
            waf_detected=waf_detected,
            scan_context="FALLBACK_INSPECTION",
            analysis_confidence="LOW",
            analysis_reliability="UNRELIABLE",
            scan_integrity="PARTIAL",
            analysis_mode="FALLBACK_INSPECTION",
            parsed_via="Raw TLS Socket"
        ),
        results=ScanResult(
            summary=ScanSummary(score=score, grade=grade, total_findings=len(findings)),
            headers=findings,
            audit=audit_log,
            diagnostics=diagnostics,
            analysis_limitations=["Standard HTTP parser failed.", "Some findings could not be fully verified."]
        )
    )

    return report


def perform_scan(url: str, timeout: int = 10, verbose: bool = False, debug: bool = False, user_agent: str = "Sentin4e-Analyzer/1.0", insecure: bool = False):
    """Perform a security scan against the target URL."""
    start_time = time.time()
    
    parsed = urlparse(url)
    if not parsed.scheme and not url.startswith("http"):
        url = "https://" + url
        parsed = urlparse(url)
        
    if parsed.scheme not in ["http", "https"] or not parsed.netloc:
        console.print("[bold red]Error:[/bold red] Invalid URL. No hostname detected or invalid scheme.")
        raise typer.Exit(code=1)
        
    try:
        response, history = fetch_with_redirect_history(
            url, 
            max_retries=3, 
            timeout=timeout,
            insecure=insecure,
            user_agent=user_agent
        )
    except ExcessiveHeadersError as e:
        if debug:
            console.print("\n[bold cyan]--- DEBUG INFO ---[/bold cyan]")
            console.print(f"Target URL: {url}")
            console.print(f"User-Agent: {user_agent}")
            console.print(f"Exception: {e.__class__.__name__}: {e}")
            if e.original_exception:
                tb_lines = traceback.format_exception(
                    type(e.original_exception), e.original_exception,
                    e.original_exception.__traceback__
                )
                console.print("Exception Chain:")
                console.print("".join(tb_lines))

        inspection = raw_inspect(url, timeout=timeout, user_agent=user_agent)
        report = _render_fallback_report(url, inspection, user_agent, debug)
        raw_headers = dict(inspection.headers) if inspection.headers else {}
        normalized_headers = {k.lower(): v.lower() for k, v in raw_headers.items()}
        return report, raw_headers, normalized_headers

    except Sentin4eException as e:
        console.print(f"\n[bold red]Scan failed:[/bold red] {e.__class__.__name__}")
        console.print(f"[bold yellow]Message:[/bold yellow] {str(e)}")
        
        if debug:
            console.print("\n[bold cyan]--- DEBUG INFO ---[/bold cyan]")
            console.print(f"Target URL: {url}")
            console.print(f"User-Agent: {user_agent}")
            console.print("Exception Chain:")
            if e.original_exception:
                tb_lines = traceback.format_exception(type(e.original_exception), e.original_exception, e.original_exception.__traceback__)
                console.print("".join(tb_lines))
            else:
                console.print("No underlying exception trace available.")
        
        # Build FAILED report
        is_ssl_err = "SSL" in e.__class__.__name__
        scan_duration_ms = int((time.time() - start_time) * 1000)
        report = ReportV2(
            meta=ScanMeta(scanner_name="Sentin4e", version=__version__, scan_duration_ms=scan_duration_ms, report_version="2.0"),
            target=TargetInfo(
                url=url,
                status_code=0,
                waf_detected="UNKNOWN",
                scan_context="ABORT",
                analysis_confidence="LOW",
                analysis_reliability="UNRELIABLE",
                scan_integrity="FAILED",
                analysis_mode="TIMEOUT_RECOVERY" if "Timeout" in e.__class__.__name__ else "SSL_FAILURE" if is_ssl_err else "UNKNOWN_ERROR",
                parsed_via="N/A"
            ),
            results=ScanResult(
                summary=ScanSummary(score=None, grade=None, total_findings=0),
                headers=[],
                audit=[],
                diagnostics={"root_cause": str(e), "exception": e.__class__.__name__},
                analysis_limitations=["Scan completely failed to connect or fetch response."]
            )
        )
        # We don't exit here, we allow rendering of the failed report
        return report, {}, {}

    if debug:
        console.print("\n[bold cyan]--- DEBUG INFO ---[/bold cyan]")
        console.print(f"Target URL: {url}")
        console.print(f"User-Agent: {user_agent}")
        console.print(f"Final Status Code: {response.status_code}")
        console.print("Redirect Chain:")
        for idx, r in enumerate(history):
            console.print(f"  {idx+1}. {r.url} -> {r.status_code}")
        if not history:
            console.print("  None")
        console.print("--------------------\n")

    body = response.text if response.text else ""
    parked = is_parked_domain(body)
    context_type, context_msg = analyze_response_context(response.status_code, is_parked=parked)
    
    if verbose:
        console.print(f"\n[cyan]Context:[/cyan] {context_msg}")
        
    if context_type == "ABORT":
        console.print(f"\n[bold red]Scan aborted:[/bold red] {context_msg}")
        raise typer.Exit(code=1)
        
    waf_detected = detect_waf(dict(response.headers), dict(response.cookies))
    
    parsed_url = urlparse(response.url)
    is_https = parsed_url.scheme == "https"
    
    raw_headers = dict(response.headers)
    normalized_headers = {k.lower(): v.lower() for k, v in raw_headers.items()}
    
    if len(raw_headers) > 100:
        console.print("[bold yellow]Warning:[/bold yellow] Target returned more than 100 headers. Only processing the first 100 to prevent DoS.")
        limited_headers = dict(list(raw_headers.items())[:100])
        findings = analyze_security_headers(limited_headers, is_https)
    else:
        findings = analyze_security_headers(raw_headers, is_https)
    
    score, grade, audit_log = calculate_score(findings)
    scan_duration_ms = int((time.time() - start_time) * 1000)
    
    report = ReportV2(
        meta=ScanMeta(scanner_name="Sentin4e", version=__version__, scan_duration_ms=scan_duration_ms, report_version="2.0"),
        target=TargetInfo(
            url=response.url, 
            status_code=response.status_code, 
            waf_detected=waf_detected, 
            scan_context=context_type,
            analysis_confidence="HIGH" if context_type != "PARTIAL_SCAN" else "MEDIUM",
            analysis_reliability="RELIABLE" if context_type != "PARTIAL_SCAN" else "PARTIAL",
            scan_integrity="COMPLETE" if context_type != "PARTIAL_SCAN" else "PARTIAL",
            analysis_mode="NORMAL_SCAN" if context_type != "PARTIAL_SCAN" else "PARTIAL_ANALYSIS",
            parsed_via="requests/http.client"
        ),
        results=ScanResult(summary=ScanSummary(score=score, grade=grade, total_findings=len(findings)), headers=findings, audit=audit_log)
    )
    
    return report, raw_headers, normalized_headers

@app.command()
def scan(
    url: str = typer.Argument(..., help="The target URL to scan"),
    timeout: int = typer.Option(10, help="Global connection timeout in seconds"),
    insecure: bool = typer.Option(False, "--insecure", "-k", help="Disable SSL certificate verification"),
    json_export: str = typer.Option(None, "--json", help="Path to export JSON report (v2)"),
    json_v1_export: str = typer.Option(None, "--json-v1", help="Path to export legacy JSON report (v1)"),
    user_agent: str = typer.Option("Sentin4e-Analyzer/1.0", "--user-agent", "-ua", help="Custom User-Agent"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug output for root cause analysis"),
    audit: bool = typer.Option(False, "--audit", help="Enable internal audit mode to print raw and normalized headers and penalties")
):
    """Scan a target URL for security headers and configurations."""
    with console.status(f"[bold green]Scanning {url}...") as status:
        report, raw_headers, normalized_headers = perform_scan(url, timeout, verbose, debug, user_agent, insecure=insecure)
        
    if audit:
        console.print("\n[bold magenta]--- INTERNAL AUDIT MODE ---[/bold magenta]")
        console.print("[bold cyan]RAW HEADERS:[/bold cyan]")
        for k, v in raw_headers.items():
            console.print(f"  {k}: {v}")
            
        console.print("\n[bold cyan]NORMALIZED HEADERS:[/bold cyan]")
        for k, v in normalized_headers.items():
            console.print(f"  {k}: {v}")
            
        console.print("\n[bold cyan]ANALYSIS RESULT & PENALTY APPLIED:[/bold cyan]")
        for f in report.results.audit:
            console.print(f"  {f.header} -> {f.status} (Penalty: {f.penalty})")
            
        console.print(f"\n[bold cyan]FINAL SCORE BREAKDOWN:[/bold cyan]")
        console.print(f"  Base Score: 100")
        for f in report.results.audit:
            if f.penalty > 0:
                console.print(f"  - {f.penalty} ({f.header} is {f.status})")
        console.print(f"  Total Penalty: {sum(f.penalty for f in report.results.audit)}")
        console.print(f"  Final Score: {report.results.summary.score}/100")
        console.print("[bold magenta]---------------------------[/bold magenta]\n")

    render_report(report)
    
    try:
        if json_export:
            export_json(report, json_export, version="v2")
            console.print(f"[bold green]Report exported to {json_export}[/bold green]")
        if json_v1_export:
            export_json(report, json_v1_export, version="v1")
            console.print(f"[bold green]Legacy Report exported to {json_v1_export}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Export Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

    if report.target.scan_integrity == "FAILED":
        raise typer.Exit(code=1)

@app.command()
def doctor():
    """Run internal system diagnostics."""
    console.print("[bold cyan]Sentin4e System Check[/bold cyan]")
    console.print(f"Python Version: {sys.version.split(' ')[0]}")
    console.print(f"Sentin4e Version: {__version__}")

@app.command()
def shell():
    """Start the interactive Sentin4e security shell."""
    try:
        from sentin4e.shell import run_shell
        run_shell()
    except Exception as e:
        console.print(f"[bold red]Shell Error:[/bold red] {e}")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
