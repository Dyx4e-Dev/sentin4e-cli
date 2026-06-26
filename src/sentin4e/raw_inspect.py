# mypy: ignore-errors
"""
Raw TLS socket inspector for fallback analysis when http.client rejects
responses with excessive headers (>100).

Opens a raw socket, sends a minimal HTTP/1.1 GET, reads the first 16KB,
and parses what it can without relying on http.client's strict parser.
"""
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
from collections import Counter
from dataclasses import dataclass, field


MAX_READ_BYTES = 16384  # 16KB
MAX_HEADERS_TO_PARSE = 500  # Safety cap for parsing loop
SOCKET_TIMEOUT = 10


@dataclass
class RawInspectionResult:
    """Result of a raw socket inspection."""
    success: bool = False
    status_line: str = ""
    status_code: int = 0
    headers: List[Tuple[str, str]] = field(default_factory=list)
    total_header_count: int = 0
    duplicate_counts: Dict[str, int] = field(default_factory=dict)
    top_duplicates: List[Tuple[str, int]] = field(default_factory=list)
    server_header: Optional[str] = None
    error: Optional[str] = None
    raw_bytes_read: int = 0
    truncated: bool = False


def raw_inspect(url: str, timeout: int = SOCKET_TIMEOUT, user_agent: str = "Sentin4e-Analyzer/1.0") -> RawInspectionResult:
    """
    Open a raw TLS/TCP socket to the target, send a minimal HTTP/1.1 GET,
    read the first 16KB of the response, and parse status line + headers.

    Args:
        url: The target URL (must be http:// or https://).
        timeout: Socket timeout in seconds.
        user_agent: User-Agent header to send.

    Returns:
        RawInspectionResult with parsed data or error information.
    """
    result = RawInspectionResult()

    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port
    use_tls = parsed.scheme == "https"

    if not hostname:
        result.error = "No hostname found in URL."
        return result

    if port is None:
        port = 443 if use_tls else 80

    path = parsed.path or "/"

    raw_sock = None
    sock = None
    try:
        # 1. Open raw TCP socket
        raw_sock = socket.create_connection((hostname, port), timeout=timeout)

        # 2. Wrap with TLS if HTTPS
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(raw_sock, server_hostname=hostname)
        else:
            sock = raw_sock
            raw_sock = None  # Prevent double-close

        # 3. Send minimal HTTP/1.1 request
        request_line = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request_line.encode("ascii"))

        # 4. Read first 16KB
        data = b""
        while len(data) < MAX_READ_BYTES:
            try:
                chunk = sock.recv(MAX_READ_BYTES - len(data))
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        result.raw_bytes_read = len(data)

    except socket.timeout:
        result.error = f"Socket timed out after {timeout}s."
        return result
    except ssl.SSLError as e:
        result.error = f"SSL error during raw inspection: {e}"
        return result
    except OSError as e:
        result.error = f"Socket error: {e}"
        return result
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass

    if not data:
        result.error = "No data received from server."
        return result

    # 5. Parse the response
    try:
        _parse_raw_response(data, result)
    except Exception as e:
        result.error = f"Failed to parse raw response: {e}"

    return result


def _parse_raw_response(data: bytes, result: RawInspectionResult) -> None:
    """
    Parse raw HTTP response bytes into status line and headers.
    Tolerant parser — does not raise on malformed lines, just skips them.
    """
    # Split headers from body at the first \r\n\r\n
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        # No complete header block found — might be truncated
        header_block = data
        result.truncated = True
    else:
        header_block = data[:header_end]

    # Decode tolerantly
    try:
        text = header_block.decode("utf-8", errors="replace")
    except Exception:
        text = header_block.decode("latin-1", errors="replace")

    lines = text.split("\r\n")
    if not lines:
        result.error = "Empty response."
        return

    # First line is the status line
    result.status_line = lines[0]
    parts = lines[0].split(" ", 2)
    if len(parts) >= 2:
        try:
            result.status_code = int(parts[1])
        except ValueError:
            pass

    # Parse headers (all remaining lines)
    all_header_names: List[str] = []
    header_count = 0

    for line in lines[1:]:
        if not line:
            continue
        if header_count >= MAX_HEADERS_TO_PARSE:
            result.truncated = True
            break

        colon_idx = line.find(":")
        if colon_idx == -1:
            continue  # Not a valid header line

        name = line[:colon_idx].strip()
        value = line[colon_idx + 1:].strip()
        header_count += 1
        all_header_names.append(name.lower())

        # Keep the first 50 headers for display
        if len(result.headers) < 50:
            result.headers.append((name, value))

        # Extract server header
        if name.lower() == "server" and result.server_header is None:
            result.server_header = value

    result.total_header_count = header_count
    result.success = True

    # Compute duplicate statistics
    counter = Counter(all_header_names)
    result.duplicate_counts = dict(counter)
    # Top duplicates: sorted by count descending, show all with count > 1, plus the rest
    result.top_duplicates = counter.most_common(10)
