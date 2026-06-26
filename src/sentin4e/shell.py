# mypy: ignore-errors
import os
import sys
import shlex
import time
from typing import List, Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentin4e.cli import perform_scan, app as cli_app
from sentin4e.formatter import render_report
from sentin4e.dashboard import get_project_metadata, discover_features, discover_cli_commands

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

sentin4e_completer = WordCompleter(COMMANDS, ignore_case=True)

def show_banner():
    """Displays the interactive shell banner."""
    metadata = get_project_metadata()
    version = metadata.get("version", "Unknown")
    author = metadata.get("author", "Dyx4e")
    
    banner_text = f"""[bold red]
       ...                                       s       .                                             
   .x888888hx    :                              :8      @88>                        xeee               
  d88888888888hxx                u.    u.      .88      %8P      u.    u.          d888R               
 8" ... `"*8888%`       .u     x@88k u@88c.   :888ooo    .     x@88k u@88c.       d8888R         .u    
!  "   ` .xnxx.      ud8888.  ^"8888""8888" -*8888888  .@88u  ^"8888""8888"      @ 8888R      ud8888.  
X X   .H8888888%:  :888'8888.   8888  888R    8888    ''888E`   8888  888R     .P  8888R    :888'8888. 
X 'hn8888888*"   > d888 '88%"   8888  888R    8888      888E    8888  888R    :F   8888R    d888 '88%" 
X: `*88888%`     ! 8888.+"      8888  888R    8888      888E    8888  888R   x"    8888R    8888.+"    
'8h.. ``     ..x8> 8888L        8888  888R   .8888Lu=   888E    8888  888R  d8eeeee88888eer 8888L      
 `88888888888888f  '8888c. .+  "*88*" 8888"  ^%888*     888&   "*88*" 8888"        8888R    '8888c. .+ 
  '%8888888888*"    "88888%      ""   'Y"      'Y"      R888"    ""   'Y"          8888R     "88888%   
     ^"****""`        "YP'                               ""                     "*%%%%%%**~    "YP'    
                                            By : {author} - v{version}[/bold red]
"""
    console.print(
        Align.center(
            banner_text,
            vertical="middle"
            )
    )
    console.print(Panel(
                "[bold]help[/bold]     - Show this help message\n"
                "[bold]version[/bold]  - Show Sentin4e version\n"
                "[bold]features[/bold] - Discover active internal capabilities dynamically\n"
                "[bold]scan[/bold]     - Run a security scan (e.g. scan https://example.com)\n"
                "[bold]clear[/bold]    - Clear the terminal screen\n"
                "[bold]banner[/bold]   - Show startup banner\n"
                "[bold]exit/quit[/bold] - Exit the shell",
                title="[bold blue]Sentin4e Shell Commands[/bold blue]",
                border_style="blue"
            ))

def run_shell():
    """Runs the Sentin4e interactive shell."""
    session = PromptSession(
        history=InMemoryHistory(),
        completer=sentin4e_completer,
        complete_while_typing=True,
    )

    show_banner()

    while True:
        try:
            text = session.prompt("sentin4e > ").strip()
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
            console.print(f"Sentin4e version [bold yellow]{metadata.get('version', 'Unknown')}[/bold yellow]")
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
                "[bold]version[/bold]  - Show Sentin4e version\n"
                "[bold]features[/bold] - Discover active internal capabilities dynamically\n"
                "[bold]scan[/bold]     - Run a security scan (e.g. scan https://example.com)\n"
                "[bold]clear[/bold]    - Clear the terminal screen\n"
                "[bold]banner[/bold]   - Show startup banner\n"
                "[bold]exit/quit[/bold] - Exit the shell",
                title="[bold blue]Sentin4e Shell Commands[/bold blue]",
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
                    user_agent="Sentin4e-Analyzer/1.0",
                    insecure=False
                )
                render_report(report)
            except Exception as e:
                console.print(f"[bold red]Scan Error:[/bold red] {str(e)}")
        else:
            console.print(f"[red]Unknown command:[/red] {cmd}. Type 'help' for available commands.")

if __name__ == "__main__":
    run_shell()
