import pytest
from unittest.mock import patch, MagicMock

from sentin4e.shell import run_shell, show_banner

@patch("sentin4e.shell.get_project_metadata")
@patch("sentin4e.shell.console.print")
def test_show_banner(mock_print, mock_metadata):
    mock_metadata.return_value = {"version": "0.1.1", "author": "TestAuthor"}
    show_banner()
    
    # Verify console.print was called with the banner text containing "TestAuthor"
    assert mock_print.call_count >= 2
    banner_call_args = mock_print.call_args_list[0][0][0]
    assert "TestAuthor" in banner_call_args
    assert "0.1.1" in banner_call_args

@patch("sentin4e.shell.PromptSession")
def test_shell_exit_command(mock_prompt_session):
    # Simulate user typing 'exit'
    mock_session_instance = MagicMock()
    mock_session_instance.prompt.side_effect = ["exit"]
    mock_prompt_session.return_value = mock_session_instance
    
    # run_shell should return immediately without exceptions
    run_shell()
    
    mock_session_instance.prompt.assert_called_once_with("sentin4e > ")

@patch("sentin4e.shell.console.print")
@patch("sentin4e.shell.PromptSession")
def test_shell_help_command(mock_prompt_session, mock_print):
    # Simulate user typing 'help' then 'exit'
    mock_session_instance = MagicMock()
    mock_session_instance.prompt.side_effect = ["help", "exit"]
    mock_prompt_session.return_value = mock_session_instance
    
    run_shell()
    
    # Verify a Panel object was printed containing "Sentin4e Shell Commands"
    assert mock_print.call_count > 0
    from rich.panel import Panel
    help_printed = any(
        "Sentin4e Shell Commands" in str(args[0][0].title) 
        for args in mock_print.call_args_list if isinstance(args[0][0], Panel)
    )
    assert help_printed

@patch("sentin4e.shell.console.print")
@patch("sentin4e.shell.PromptSession")
@patch("sentin4e.shell.get_project_metadata")
def test_shell_version_command(mock_metadata, mock_prompt_session, mock_print):
    mock_metadata.return_value = {"version": "1.2.3"}
    
    mock_session_instance = MagicMock()
    mock_session_instance.prompt.side_effect = ["version", "exit"]
    mock_prompt_session.return_value = mock_session_instance
    
    run_shell()
    
    version_printed = any(
        "1.2.3" in str(args[0][0]) 
        for args in mock_print.call_args_list if isinstance(args[0][0], str)
    )
    assert version_printed

@patch("sentin4e.shell.perform_scan")
@patch("sentin4e.shell.render_report")
@patch("sentin4e.shell.PromptSession")
def test_shell_scan_command(mock_prompt_session, mock_render_report, mock_perform_scan):
    # Simulate user typing 'scan https://example.com' then 'exit'
    mock_session_instance = MagicMock()
    mock_session_instance.prompt.side_effect = ["scan https://example.com", "exit"]
    mock_prompt_session.return_value = mock_session_instance
    
    mock_perform_scan.return_value = ("fake_report", {}, {})
    
    run_shell()
    
    # Verify perform_scan was called correctly
    mock_perform_scan.assert_called_once_with(
        url="https://example.com",
        timeout=10,
        verbose=False,
        debug=False,
        user_agent="Sentin4e-Analyzer/1.0",
        insecure=False
    )
    
    mock_render_report.assert_called_once_with("fake_report")

@patch("sentin4e.shell.console.print")
@patch("sentin4e.shell.PromptSession")
def test_shell_unknown_command(mock_prompt_session, mock_print):
    mock_session_instance = MagicMock()
    mock_session_instance.prompt.side_effect = ["foobar", "exit"]
    mock_prompt_session.return_value = mock_session_instance
    
    run_shell()
    
    unknown_printed = any(
        "Unknown command" in str(args[0][0]) 
        for args in mock_print.call_args_list if isinstance(args[0][0], str)
    )
    assert unknown_printed
