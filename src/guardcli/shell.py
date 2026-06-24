import os
import sys
import shlex
import time
from typing import List, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guardcli.cli import perform_scan, app as cli_app
from guardcli.formatter import render_report
from guardcli.dashboard import get_project_metadata, discover_features, discover_cli_commands

console = Console()

COMMANDS = [
    "help",
    "version",
    "features",
    "scan",
    "clear",
    "banner",
    "exit",
    "quit",
]

guard_completer = WordCompleter(COMMANDS, ignore_case=True)

def show_banner():
    """Displays the interactive shell banner."""
    metadata = get_project_metadata()
    version = metadata.get("version", "Unknown")
    author = metadata.get("author", "Dyx4e")
    
    banner_text = f"""[bold cyan]
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗  ██████╗██╗     ██╗
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║     ██║
██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║     ██║     ██║
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║     ██║     ██║
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝╚██████╗███████╗██║
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚══════╝╚═╝[/bold cyan]

[bold]GuardCLI Security Audit Framework[/bold]
Version : [yellow]{version}[/yellow]
Author  : [green]{author}[/green]
"""
    console.print(banner_text)
    console.print("Type [bold yellow]help[/bold yellow] for available commands.")

def run_shell():
    """Runs the GuardCLI interactive shell."""
    session = PromptSession(
        history=InMemoryHistory(),
        completer=guard_completer,
        complete_while_typing=True,
    )

    show_banner()

    while True:
        try:
            text = session.prompt("guard > ").strip()
        except KeyboardInterrupt:
            continue
        except EOFError:
            break

        if not text:
            continue

        try:
            parts = shlex.split(text)
        except ValueError as e:
            console.print(f"[red]Error parsing command:[/red] {e}")
            continue

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ["exit", "quit"]:
            break
        elif cmd == "clear":
            # clear the screen
            os.system("cls" if os.name == "nt" else "clear")
        elif cmd == "banner":
            show_banner()
        elif cmd == "version":
            metadata = get_project_metadata()
            console.print(f"GuardCLI version [bold yellow]{metadata.get('version', 'Unknown')}[/bold yellow]")
        elif cmd == "features":
            # Reuse dynamic feature discovery
            categories, total_modules, total_functions = discover_features()
            console.print(f"\n[bold]Discovered Categories ({total_modules} modules, {total_functions} functions):[/bold]\n")
            for cat_name, funcs in categories.items():
                console.print(f"[bold cyan]{cat_name}[/bold cyan]")
                for f in sorted(funcs):
                    console.print(f"  - {f}")
            console.print()
        elif cmd == "help":
            console.print(Panel(
                "[bold]help[/bold]     - Show this help message\n"
                "[bold]version[/bold]  - Show GuardCLI version\n"
                "[bold]features[/bold] - Discover active internal capabilities dynamically\n"
                "[bold]scan[/bold]     - Run a security scan (e.g. scan https://example.com)\n"
                "[bold]clear[/bold]    - Clear the terminal screen\n"
                "[bold]banner[/bold]   - Show startup banner\n"
                "[bold]exit/quit[/bold] - Exit the shell",
                title="[bold blue]GuardCLI Shell Commands[/bold blue]",
                border_style="blue"
            ))
        elif cmd == "scan":
            if not args:
                console.print("[red]Usage:[/red] scan <url>")
                continue
            
            url = args[0]
            # Call perform_scan directly
            try:
                # We can handle basic flags if needed or just default them
                # For simplicity, just run a standard scan unless we want to parse kwargs
                report, _, _ = perform_scan(
                    url=url,
                    timeout=10,
                    verbose=False,
                    debug=False,
                    user_agent="GuardCLI-Analyzer/1.0",
                    insecure=False
                )
                render_report(report)
            except Exception as e:
                console.print(f"[bold red]Scan Error:[/bold red] {str(e)}")
        else:
            console.print(f"[red]Unknown command:[/red] {cmd}. Type 'help' for available commands.")

if __name__ == "__main__":
    run_shell()
