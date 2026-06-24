"""Tests for the raw_inspect module and fallback inspection flow."""
import pytest
from unittest.mock import patch, MagicMock
from sentin4e.raw_inspect import raw_inspect, _parse_raw_response, RawInspectionResult


class TestParseRawResponse:
    """Unit tests for the raw HTTP response parser."""

    def test_parse_simple_response(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx\r\n"
            b"Content-Type: text/html\r\n"
            b"\r\n"
            b"<html></html>"
        )
        result = RawInspectionResult()
        _parse_raw_response(raw, result)

        assert result.status_line == "HTTP/1.1 200 OK"
        assert result.status_code == 200
        assert result.server_header == "nginx"
        assert result.total_header_count == 2
        assert len(result.headers) == 2
        assert result.truncated is False

    def test_parse_duplicate_headers(self):
        lines = [b"HTTP/1.1 200 OK\r\n"]
        # Simulate 150 X-Robots-Tag headers
        for i in range(150):
            lines.append(f"X-Robots-Tag: noindex-{i}\r\n".encode())
        lines.append(b"Server: Apache\r\n")
        lines.append(b"\r\n")
        raw = b"".join(lines)

        result = RawInspectionResult()
        _parse_raw_response(raw, result)

        assert result.status_code == 200
        assert result.total_header_count == 151  # 150 x-robots-tag + 1 server
        assert result.server_header == "Apache"
        assert len(result.headers) == 50  # Capped at 50
        assert result.duplicate_counts["x-robots-tag"] == 150
        assert result.top_duplicates[0] == ("x-robots-tag", 150)

    def test_parse_truncated_response(self):
        """Response without \\r\\n\\r\\n should be marked truncated."""
        raw = b"HTTP/1.1 200 OK\r\nServer: test\r\nContent-Type: text/html\r\n"
        result = RawInspectionResult()
        _parse_raw_response(raw, result)

        assert result.truncated is True
        assert result.status_code == 200
        assert result.server_header == "test"

    def test_parse_403_response(self):
        raw = (
            b"HTTP/1.1 403 Forbidden\r\n"
            b"Server: cloudflare\r\n"
            b"\r\n"
        )
        result = RawInspectionResult()
        _parse_raw_response(raw, result)

        assert result.status_code == 403
        assert result.server_header == "cloudflare"

    def test_parse_malformed_header_lines_skipped(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"this-is-not-a-header\r\n"
            b"Server: nginx\r\n"
            b"\r\n"
        )
        result = RawInspectionResult()
        _parse_raw_response(raw, result)

        assert result.total_header_count == 1  # Only "Server" parsed
        assert result.server_header == "nginx"

    def test_parse_empty_data(self):
        result = RawInspectionResult()
        _parse_raw_response(b"", result)
        assert result.status_line == ""

    def test_duplicate_stats_sorted(self):
        lines = [b"HTTP/1.1 200 OK\r\n"]
        for _ in range(5):
            lines.append(b"X-Custom-A: value\r\n")
        for _ in range(20):
            lines.append(b"X-Custom-B: value\r\n")
        for _ in range(2):
            lines.append(b"X-Custom-C: value\r\n")
        lines.append(b"\r\n")
        raw = b"".join(lines)

        result = RawInspectionResult()
        _parse_raw_response(raw, result)

        # top_duplicates should be sorted by count descending
        names = [name for name, _ in result.top_duplicates]
        counts = [count for _, count in result.top_duplicates]
        assert counts == sorted(counts, reverse=True)
        assert result.top_duplicates[0] == ("x-custom-b", 20)


class TestRawInspectIntegration:
    """Tests for the raw_inspect function with mocked sockets."""

    @patch("sentin4e.raw_inspect.socket.create_connection")
    @patch("sentin4e.raw_inspect.ssl.create_default_context")
    def test_successful_https_inspection(self, mock_ssl_ctx, mock_create_conn):
        raw_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache\r\n"
            b"X-Robots-Tag: noindex\r\n"
            b"X-Robots-Tag: nofollow\r\n"
            b"\r\n"
        )

        mock_raw_sock = MagicMock()
        mock_create_conn.return_value = mock_raw_sock

        mock_tls_sock = MagicMock()
        mock_tls_sock.recv.side_effect = [raw_response, b""]
        mock_ssl_ctx.return_value.wrap_socket.return_value = mock_tls_sock

        result = raw_inspect("https://example.com", timeout=5)

        assert result.success is True
        assert result.status_code == 200
        assert result.server_header == "Apache"
        assert result.total_header_count == 3
        assert result.duplicate_counts["x-robots-tag"] == 2

    @patch("sentin4e.raw_inspect.socket.create_connection")
    def test_socket_timeout(self, mock_create_conn):
        import socket
        mock_create_conn.side_effect = socket.timeout("timed out")

        result = raw_inspect("https://example.com", timeout=1)

        assert result.success is False
        assert "timed out" in result.error.lower()

    @patch("sentin4e.raw_inspect.socket.create_connection")
    @patch("sentin4e.raw_inspect.ssl.create_default_context")
    def test_ssl_error(self, mock_ssl_ctx, mock_create_conn):
        import ssl
        mock_raw_sock = MagicMock()
        mock_create_conn.return_value = mock_raw_sock
        mock_ssl_ctx.return_value.wrap_socket.side_effect = ssl.SSLError("certificate verify failed")

        result = raw_inspect("https://example.com")

        assert result.success is False
        assert "ssl" in result.error.lower()

    def test_no_hostname(self):
        result = raw_inspect("https://")
        assert result.success is False
        assert "hostname" in result.error.lower()


class TestFallbackCLIFlow:
    """Test the fallback flow in the CLI when ExcessiveHeadersError is raised."""

    @patch("sentin4e.raw_inspect.socket.create_connection")
    @patch("sentin4e.raw_inspect.ssl.create_default_context")
    @patch("sentin4e.retry.requests.Session.get")
    def test_excessive_headers_triggers_fallback(self, mock_get, mock_ssl_ctx, mock_create_conn):
        import http.client
        import urllib3
        import requests
        from typer.testing import CliRunner
        from sentin4e.cli import app

        # Make the normal HTTP client fail with ExcessiveHeadersError
        root = http.client.HTTPException("got more than 100 headers")
        proto_err = urllib3.exceptions.ProtocolError("Connection aborted.", root)
        req_err = requests.exceptions.ConnectionError("Connection aborted.", proto_err)
        req_err.__cause__ = proto_err
        proto_err.__cause__ = root
        mock_get.side_effect = req_err

        # Make the raw socket return a response with many headers
        lines = [b"HTTP/1.1 200 OK\r\n", b"Server: Apache\r\n"]
        for i in range(130):
            lines.append(f"X-Robots-Tag: noindex-{i}\r\n".encode())
        lines.append(b"\r\n")
        raw_response = b"".join(lines)

        mock_raw_sock = MagicMock()
        mock_create_conn.return_value = mock_raw_sock
        mock_tls_sock = MagicMock()
        mock_tls_sock.recv.side_effect = [raw_response, b""]
        mock_ssl_ctx.return_value.wrap_socket.return_value = mock_tls_sock

        runner = CliRunner()
        result = runner.invoke(app, ["scan", "https://example.com"])

        assert result.exit_code == 0
        assert "Fallback Inspection Mode" in result.stdout
        assert "Excessive Header Count" in result.stdout
        assert "FALLBACK_INSPECTION" in result.stdout
