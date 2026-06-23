from typer.testing import CliRunner
from guardcli.cli import app
from guardcli import __version__
import json
import os

runner = CliRunner()

def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout

def test_doctor_command():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "GuardCLI System Check" in result.stdout
    assert "Python Version" in result.stdout

def test_scan_command_valid():
    # We test with example.com which is normally available
    result = runner.invoke(app, ["scan", "example.com"])
    assert result.exit_code == 0
    assert "Target:" in result.stdout
    assert "Score:" in result.stdout

def test_scan_command_export():
    output_file = "test_output.json"
    result = runner.invoke(app, ["scan", "example.com", "-o", output_file])
    assert result.exit_code == 0
    assert os.path.exists(output_file)
    with open(output_file, "r") as f:
        data = json.load(f)
        assert data["target"] == "https://example.com"
    os.remove(output_file)

def test_headers_command():
    result = runner.invoke(app, ["headers", "example.com"])
    assert result.exit_code == 0
    assert "Headers for https://example.com:" in result.stdout

def test_export_command():
    output_file = "test_export_only.json"
    result = runner.invoke(app, ["export", "example.com", "-o", output_file])
    assert result.exit_code == 0
    assert os.path.exists(output_file)
    os.remove(output_file)

def test_scan_invalid_url():
    result = runner.invoke(app, ["scan", "http://"])
    assert result.exit_code == 1
    assert "Error:" in result.stdout
