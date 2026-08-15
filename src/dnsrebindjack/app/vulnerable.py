"""Intentionally vulnerable check-then-fetch-by-hostname teaching engine.

This module demonstrates the DNS-rebinding flaw. It must only be reachable behind the Compose
profile plus explicit environment acknowledgement enforced by :mod:`dnsrebindjack.app.main`.
"""

from __future__ import annotations

import http.client
import ssl

from dnsrebindjack.app.constants import COMPLETED_VERDICT, UNREACHABLE_VERDICT
from dnsrebindjack.app.fetch import FetchResult, parse_target, resolve_ipv4
from dnsrebindjack.netblocks import is_blocked


def _hostname_request(url: str, *, timeout: float) -> tuple[int, str, str]:
    """Fetch by hostname, deliberately allowing a fresh connect-time DNS resolution."""
    parsed = parse_target(url)
    host = parsed.hostname
    assert host is not None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection_type = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_type(host, port=port, timeout=timeout)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    try:
        connection.request("GET", path, headers={"Host": parsed.netloc, "Connection": "close"})
        assert connection.sock is not None
        connected_ip = str(connection.sock.getpeername()[0])
        response = connection.getresponse()
        body = response.read(64 * 1024).decode("utf-8", errors="replace")
        return response.status, body, connected_ip
    finally:
        connection.close()


def vulnerable_fetch(url: str, *, timeout: float = 3.0) -> FetchResult:
    """Validate one DNS answer, then intentionally re-resolve the hostname to connect."""
    try:
        parsed = parse_target(url)
        host = parsed.hostname
        assert host is not None
        validated_ip = resolve_ipv4(host)
    except (ValueError, OSError):
        return FetchResult(verdict=UNREACHABLE_VERDICT, rejection_class="unreachable")

    if is_blocked(validated_ip):
        return FetchResult(
            verdict=UNREACHABLE_VERDICT,
            validated_ip=validated_ip,
            rejection_class="disallowed-address",
        )

    try:
        status, body, connected_ip = _hostname_request(url, timeout=timeout)
    except (ValueError, OSError, http.client.HTTPException, ssl.SSLError):
        return FetchResult(
            verdict=UNREACHABLE_VERDICT,
            validated_ip=validated_ip,
            rejection_class="unreachable",
        )

    return FetchResult(
        verdict=COMPLETED_VERDICT,
        validated_ip=validated_ip,
        connected_ip=connected_ip,
        http_status=status,
        body=body,
    )
