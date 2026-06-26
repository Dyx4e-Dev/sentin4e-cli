# mypy: ignore-errors
import importlib
import inspect
import pkgutil
import platform
import sys
import tomllib
from pathlib import Path
from typing import Dict, List, Any, Tuple

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns
from rich.rule import Rule

import sentin4e

console = Console()

def get_project_metadata() -> Dict[str, str]:
    """Parse pyproject.toml and gather runtime information."""
    metadata = {
        "version": "0.1.1",
        "author": "Dyx4e",
        "project_name": "sentin4e",
        "description": "Defensive cybersecurity CLI tool.",
        "license": "MIT License",
        "repository": "https://github.com/Dyx4e-Dev/sentin4e",
        "python_version": f"{platform.python_version()} ({platform.python_implementation()})",
        "platform": platform.platform()
    }
    
    # Try to find pyproject.toml
    project_root = Path(__file__).parent.parent.parent
    pyproject_path = project_root / "pyproject.toml"
    
    if pyproject_path.exists():
        try:
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
                poetry_data = data.get("tool", {}).get("poetry", {})
                
                if poetry_data:
                    metadata["version"] = poetry_data.get("version", metadata["version"])
                    metadata["project_name"] = poetry_data.get("name", metadata["project_name"])
                    metadata["description"] = poetry_data.get("description", metadata["description"])
                    metadata["license"] = poetry_data.get("license", metadata["license"])
                    metadata["repository"] = poetry_data.get("repository", metadata["repository"])
                    
                    authors = poetry_data.get("authors", [])
                    if authors:
                        metadata["author"] = authors[0]
        except Exception:
            pass

    return metadata

def discover_features() -> Tuple[Dict[str, List[str]], int, int]:
    """Inspect sentin4e package and group functions into categories."""
    package = sentin4e
    categories = {}
    total_modules = 0
    total_functions = 0
    
    # Default category mappings based on module names
    category_map = {
        "scoring": "Security Analysis",
        "headers": "Header Analysis",
        "retry": "Network Analysis",
        "raw_inspect": "Infrastructure Analysis",
        "waf_detector": "WAF Detection",
        "formatter": "Reporting",
        "schemas": "Diagnostics",
        "cli": "Utilities",
        "dashboard": "Diagnostics",
        "exceptions": "Utilities"
    }

    for _, modname, _ in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        try:
            module = importlib.import_module(modname)
            total_modules += 1
            
            # Use short module name
            short_name = modname.split(".")[-1]
            cat_name = category_map.get(short_name, "Utilities")
            
            if cat_name not in categories:
                categories[cat_name] = []
                
            for name, obj in inspect.getmembers(module, inspect.isfunction):
                if not name.startswith("_") and obj.__module__ == modname:
                    categories[cat_name].append(name)
                    total_functions += 1
                    
        except ImportError:
            continue

    return categories, total_modules, total_functions

def discover_cli_commands(app: typer.Typer) -> Tuple[Dict[str, Any], int, int, int]:
    """Inspect Typer app and extract commands, subcommands, options, and flags."""
    click_obj = typer.main.get_command(app)
    
    commands_info = {}
    total_cmds = 0
    total_options = 0
    total_flags = 0
    
    def process_command(cmd, name=""):
        nonlocal total_cmds, total_options, total_flags
        
        info = {
            "name": name or cmd.name,
            "help": cmd.help or "",
            "params": [],
            "subcommands": {}
        }
        
        for param in getattr(cmd, "params", []):
            if param.param_type_name == "option":
                is_flag = getattr(param, "is_flag", False)
                if is_flag:
                    total_flags += 1
                else:
                    total_options += 1
                    
                info["params"].append({
                    "name": "/".join(getattr(param, "opts", [param.name])),
                    "is_flag": is_flag,
                    "help": getattr(param, "help", "")
                })
            elif param.param_type_name == "argument":
                info["params"].append({
                    "name": param.name,
                    "is_flag": False,
                    "help": "Argument"
                })
                
        if hasattr(cmd, "commands"):
            for sub_name, sub_cmd in cmd.commands.items():
                total_cmds += 1
                info["subcommands"][sub_name] = process_command(sub_cmd, sub_name)
                
        return info
        
    # Main CLI is considered 1 command if it has subcommands, or itself is the command
    if hasattr(click_obj, "commands"):
        for sub_name, sub_cmd in click_obj.commands.items():
            total_cmds += 1
            commands_info[sub_name] = process_command(sub_cmd, sub_name)
    else:
        total_cmds += 1
        commands_info[click_obj.name] = process_command(click_obj, click_obj.name)
        
    return commands_info, total_cmds, total_options, total_flags

def run_health_check(app: typer.Typer, commands_info: Dict[str, Any], metadata: Dict[str, str]) -> Tuple[str, List[str]]:
    """Audit codebase for undocumented commands, mismatches, etc."""
    warnings = []
    
    # 1. Version Mismatch Detection
    pyproject_version = metadata["version"]
    runtime_version = getattr(sentin4e, "__version__", "")
    
    if pyproject_version != "UNKNOWN" and runtime_version != "UNKNOWN" and pyproject_version != runtime_version:
        warnings.append(f"Version Mismatch: pyproject.toml ({pyproject_version}) != sentin4e.__version__ ({runtime_version})")
        
    # 2. Duplicate command detection
    # Handled by Typer implicitly, but we can verify names
    seen_cmds = set()
    def check_dupes(cmds):
        for c in cmds.values():
            if c["name"] in seen_cmds:
                warnings.append(f"Duplicate command registered: {c['name']}")
            seen_cmds.add(c["name"])
            check_dupes(c["subcommands"])
    check_dupes(commands_info)
    
    # 3. Missing help text detection
    def check_help(cmds):
        for c in cmds.values():
            if not c["help"]:
                warnings.append(f"Command '{c['name']}' is missing help text")
            for p in c["params"]:
                if not p["help"]:
                    warnings.append(f"Parameter '{p['name']}' in command '{c['name']}' is missing help text")
            check_help(c["subcommands"])
    check_help(commands_info)
    
    # 4. Missing docstring detection in modules
    package = sentin4e
    for _, modname, _ in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
        try:
            module = importlib.import_module(modname)
            for name, obj in inspect.getmembers(module, inspect.isfunction):
                if not name.startswith("_") and obj.__module__ == modname:
                    if not obj.__doc__:
                        warnings.append(f"Public function '{name}' in '{modname}' is missing a docstring")
        except ImportError:
            pass

    if warnings:
        return "WARNINGS FOUND", warnings
    return "CLEAN", []

def render_dashboard(app: typer.Typer) -> None:
    """Print the dynamic dashboard and exit."""
    # 1. ASCII Banner
    banner = """[bold cyan]
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
                                        v0.1.1[/bold cyan]
    [/bold cyan]"""
    from rich.panel import Panel
    from rich.align import Align

    console.print(Align.center(banner))

    
    # Gathering data
    metadata = get_project_metadata()
    categories, total_modules, total_functions = discover_features()
    commands_info, total_cmds, total_options, total_flags = discover_cli_commands(app)
    health_status, warnings = run_health_check(app, commands_info, metadata)

    # 2. Project Information Panel
    proj_info = (
        f"[bold]Version     :[/bold] {metadata['version']}\n"
        f"[bold]Codename    :[/bold] Sentinel\n"
        f"[bold]Author      :[/bold] {metadata['author']}\n"
        f"[bold]Python      :[/bold] {metadata['python_version']}\n"
        f"[bold]Platform    :[/bold] {metadata['platform']}\n"
        f"[bold]License     :[/bold] {metadata['license']}\n"
        f"[bold]Repository  :[/bold] {metadata['repository']}"
    )
    console.print(Panel(proj_info, title="[bold magenta]Project Information[/bold magenta]", border_style="magenta"))
    # 7. Footer
    console.print()
    console.print(Rule(style="dim"))
    console.print("[dim italic]Trust the evidence, not the score.[/dim italic]", justify="center")
    console.print(Rule(style="dim"))

def render_help(app: typer.Typer) -> None:
    """Print the dynamic help documentation and exit."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.tree import Tree
    from rich.columns import Columns
    
    metadata = get_project_metadata()
    categories, _, _ = discover_features()
    commands_info, _, _, _ = discover_cli_commands(app)
    
    # Project Info
    info_text = (
        f"[bold cyan]Project Name:[/bold cyan] {metadata['project_name']}\n"
        f"[bold cyan]Current Version:[/bold cyan] {metadata['version']}\n"
        f"[bold cyan]Author:[/bold cyan] {metadata['author']}\n"
        f"[bold cyan]Description:[/bold cyan] {metadata['description']}\n"
        f"[bold cyan]Repository URL:[/bold cyan] {metadata['repository']}"
    )
    console.print(Panel(info_text, title="[bold magenta]Sentin4e Help[/bold magenta]", border_style="magenta"))
    
    # Available Commands
    cmd_table = Table(title="[bold green]AVAILABLE COMMANDS[/bold green]", show_header=True, header_style="bold blue")
    cmd_table.add_column("Command", style="cyan")
    cmd_table.add_column("Description")
    
    def add_cmds_to_table(cmds, prefix=""):
        for c in cmds.values():
            cmd_table.add_row(f"{prefix}{c['name']}", c['help'] or "No description provided.")
            add_cmds_to_table(c["subcommands"], prefix + c["name"] + " ")
            
    add_cmds_to_table(commands_info)
    console.print(cmd_table)
    console.print()
    
    # Available Flags
    flag_table = Table(title="[bold green]AVAILABLE FLAGS[/bold green]", show_header=True, header_style="bold blue")
    flag_table.add_column("Flag / Option", style="yellow")
    flag_table.add_column("Command", style="cyan")
    flag_table.add_column("Description")
    
    def extract_flags(cmds, cmd_name="Global"):
        for c in cmds.values():
            for p in c["params"]:
                flag_table.add_row(p["name"], cmd_name if cmd_name != "Global" else c["name"], p["help"])
            extract_flags(c["subcommands"], c["name"])
            
    extract_flags(commands_info)
    console.print(flag_table)
    console.print()
    
    # Scan Modes, Output Formats, Reliability Modes
    modes_col = Columns([
        Panel("[cyan]FULL_SCAN[/cyan]\n[cyan]PARTIAL_SCAN[/cyan]\n[cyan]FALLBACK_INSPECTION[/cyan]", title="[bold]SCAN MODES[/bold]", border_style="blue"),
        Panel("[yellow]JSON V2 (--json)[/yellow]\n[yellow]JSON V1 (--json-v1)[/yellow]\n[yellow]CLI Standard[/yellow]", title="[bold]OUTPUT FORMATS[/bold]", border_style="yellow"),
        Panel("[green]RELIABLE[/green]\n[green]PARTIAL[/green]\n[green]UNRELIABLE[/green]", title="[bold]RELIABILITY MODES[/bold]", border_style="green")
    ])
    console.print(modes_col)
    console.print()
    
    # Discovered Features Categorized
    cat_tree = Tree("[bold magenta]DISCOVERED CAPABILITIES[/bold magenta]")
    for cat_name in ["Security Analysis", "Infrastructure Analysis", "Network Analysis", "Reporting", "Diagnostics", "WAF Detection", "Header Analysis"]:
        if cat_name in categories and categories[cat_name]:
            node = cat_tree.add(f"[bold cyan]{cat_name.upper()}[/bold cyan]")
            for feat in sorted(categories[cat_name]):
                node.add(feat)
    console.print(Panel(cat_tree, border_style="magenta"))
    
    # Usage Examples
    console.print("\n[bold yellow]USAGE EXAMPLES:[/bold yellow]")
    if "scan" in commands_info:
        console.print("  [cyan]sentin4e scan https://example.com[/cyan]")
        console.print("  [cyan]sentin4e scan https://example.com --audit[/cyan]")
        console.print("  [cyan]sentin4e scan https://example.com --json report.json[/cyan]")
        console.print("  [cyan]sentin4e scan https://example.com -k -v[/cyan]")
    if "doctor" in commands_info:
        console.print("  [cyan]sentin4e doctor[/cyan]")
    console.print()
