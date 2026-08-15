"""Resolve-once, validate, and connect-to-pinned secure fetch engine."""

from __future__ import annotations

import http.client
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from dnsrebindjack.app.constants import COMPLETED_VERDICT, UNREACHABLE_VERDICT
from dnsrebindjack.netblocks import is_blocked

Resolve = Callable[[str], str]


@dataclass(frozen=True)
class FetchResult:
    verdict: str
    validated_ip: str | None = None
    connected_ip: str | None = None
    http_status: int | None = None
    body: str | None = None
    rejection_class: str | None = None


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose hostname identity and socket destination are distinct."""

    def __init__(self, host: str, pinned_ip: str, port: int, timeout: float) -> None:
        super().__init__(host=host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS equivalent: connect to the IP while retaining hostname SNI/verification."""

    def __init__(self, host: str, pinned_ip: str, port: int, timeout: float) -> None:
        context = ssl.create_default_context()
        super().__init__(host=host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._ssl_context = context

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._ssl_context.wrap_socket(raw, server_hostname=self.host)


def resolve_ipv4(host: str) -> str:
    """Perform the sole A lookup used by the secure path."""
    return socket.gethostbyname(host)


def parse_target(url: str) -> SplitResult:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
        raise ValueError("target must be an absolute HTTP(S) URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URL credentials are not supported")
    return parsed


def _pinned_request(parsed: SplitResult, pinned_ip: str, *, timeout: float) -> tuple[int, str, str]:
    host = parsed.hostname
    assert host is not None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection_type = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    connection = connection_type(host, pinned_ip, port, timeout)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    host_header = host if parsed.port is None else f"{host}:{parsed.port}"
    try:
        connection.request("GET", path, headers={"Host": host_header, "Connection": "close"})
        assert connection.sock is not None
        connected_ip = str(connection.sock.getpeername()[0])
        if connected_ip != pinned_ip:
            raise ConnectionError("connected peer differed from the vetted address")
        response = connection.getresponse()
        body = response.read(64 * 1024).decode("utf-8", errors="replace")
        return response.status, body, connected_ip
    finally:
        connection.close()


def secure_fetch(
    url: str,
    *,
    resolver: Resolve = resolve_ipv4,
    timeout: float = 3.0,
) -> FetchResult:
    """Fetch ``url`` without a hostname-resolution time-of-check/time-of-use gap."""
    try:
        parsed = parse_target(url)
        host = parsed.hostname
        assert host is not None
        validated_ip = resolver(host)
    except (ValueError, OSError):
        return FetchResult(verdict=UNREACHABLE_VERDICT, rejection_class="unreachable")

    if is_blocked(validated_ip):
        return FetchResult(
            verdict=UNREACHABLE_VERDICT,
            validated_ip=validated_ip,
            rejection_class="disallowed-address",
        )

    try:
        status, body, connected_ip = _pinned_request(parsed, validated_ip, timeout=timeout)
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
