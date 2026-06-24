import pytest
import typer
from guardcli.dashboard import get_project_metadata, discover_features, discover_cli_commands, run_health_check

def test_get_project_metadata():
    metadata = get_project_metadata()
    assert "version" in metadata
    assert "author" in metadata
    assert "project_name" in metadata
    assert "python_version" in metadata

def test_discover_features():
    categories, modules, functions = discover_features()
    assert modules > 0
    assert functions > 0
    assert "Security Analysis" in categories or "Header Analysis" in categories

def test_discover_cli_commands():
    app = typer.Typer()
    @app.command()
    def test_cmd(arg1: str, flag1: bool = typer.Option(False, "--flag1")):
        """Test Help"""
        pass
    
    commands_info, total_cmds, total_options, total_flags = discover_cli_commands(app)
    assert total_cmds >= 1
    assert "test-cmd" in commands_info
    assert commands_info["test-cmd"]["help"] == "Test Help"
    assert len(commands_info["test-cmd"]["params"]) >= 2

def test_run_health_check():
    app = typer.Typer()
    metadata = {
        "version": "1.0.0"
    }
    commands_info = {
        "good_cmd": {
            "name": "good_cmd",
            "help": "Good Help",
            "params": [{"name": "param1", "is_flag": False, "help": "Good Param Help"}],
            "subcommands": {}
        },
        "bad_cmd": {
            "name": "bad_cmd",
            "help": "",
            "params": [],
            "subcommands": {}
        }
    }
    
    status, warnings = run_health_check(app, commands_info, metadata)
    assert status == "WARNINGS FOUND"
    assert any("missing help text" in w for w in warnings)
