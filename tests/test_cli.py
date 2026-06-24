import os
import json
import http.client
from unittest.mock import patch, MagicMock
from typer.testing import CliRunner
import requests
import urllib3

from guardcli.cli import app
from guardcli.waf_detector import is_parked_domain
from guardcli.retry import _classify_exception
from guardcli.exceptions import (
    ExcessiveHeadersError,
    MalformedResponseError,
    ConnectionClosedError,
    RedirectLoopError,
    SSLValidationError,
    TimeoutError,
    UnknownNetworkError
)

runner = CliRunner()

def test_invalid_url():
    result = runner.invoke(app, ["scan", "http://"])
    assert result.exit_code == 1
    assert "Invalid URL. No hostname detected or invalid scheme." in result.stdout

def test_parked_domain():
    html = "<html><body>Welcome to godaddy.com, this domain is registered at GoDaddy!</body></html>"
    assert is_parked_domain(html) == True
    html2 = "<html><body>My actual app</body></html>"
    assert is_parked_domain(html2) == False

def build_nested_exception(root_exc):
    # Builds requests.exceptions.ConnectionError(urllib3.exceptions.ProtocolError('Connection aborted.', root_exc))
    proto_err = urllib3.exceptions.ProtocolError("Connection aborted.", root_exc)
    req_err = requests.exceptions.ConnectionError("Connection aborted.", proto_err)
    req_err.__cause__ = proto_err
    proto_err.__cause__ = root_exc
    return req_err

def test_classify_excessive_headers():
    root = http.client.HTTPException("got more than 100 headers")
    err = build_nested_exception(root)
    classified = _classify_exception(err)
    assert isinstance(classified, ExcessiveHeadersError)
    assert classified.original_exception == err

def test_classify_line_too_long():
    root = http.client.LineTooLong("line is too long")
    err = build_nested_exception(root)
    classified = _classify_exception(err)
    assert isinstance(classified, MalformedResponseError)
    assert "LineTooLong" in str(classified)

def test_classify_remote_disconnected():
    root = http.client.RemoteDisconnected("Remote end closed connection without response")
    err = build_nested_exception(root)
    classified = _classify_exception(err)
    assert isinstance(classified, ConnectionClosedError)

def test_classify_bad_status_line():
    root = http.client.BadStatusLine("<html>")
    err = build_nested_exception(root)
    classified = _classify_exception(err)
    assert isinstance(classified, MalformedResponseError)
    assert "invalid HTTP status line" in str(classified)

@patch("guardcli.retry.requests.Session.get")
def test_cli_debug_output_for_bad_status_line(mock_get):
    root = http.client.BadStatusLine("<html>")
    err = build_nested_exception(root)
    mock_get.side_effect = err
    
    result = runner.invoke(app, ["scan", "https://example.com", "--debug"])
    assert result.exit_code == 1
    assert "MalformedResponseError" in result.stdout
    assert "--- DEBUG INFO ---" in result.stdout
    assert "Target URL: https://example.com" in result.stdout
    assert "Exception Chain:" in result.stdout
    assert "BadStatusLine" in result.stdout

@patch("guardcli.retry.requests.Session.get")
def test_ssl_error(mock_get):
    mock_get.side_effect = requests.exceptions.SSLError("certificate verify failed")
    result = runner.invoke(app, ["scan", "https://example.com"])
    stdout_flat = result.stdout.replace('\n', '')
    assert result.exit_code == 1
    assert "SSLValidationError" in stdout_flat

@patch("guardcli.retry.requests.Session.get")
def test_redirect_loop(mock_get):
    mock_get.side_effect = requests.exceptions.TooManyRedirects("Exceeded 30 redirects")
    result = runner.invoke(app, ["scan", "https://example.com"])
    stdout_flat = result.stdout.replace('\n', '')
    assert result.exit_code == 1
    assert "RedirectLoopError" in stdout_flat

@patch("guardcli.retry.requests.Session.get")
def test_timeout(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout("Read timed out")
    result = runner.invoke(app, ["scan", "https://example.com", "--timeout", "1"])
    stdout_flat = result.stdout.replace('\n', '')
    assert result.exit_code == 1
    assert "TimeoutError" in stdout_flat
