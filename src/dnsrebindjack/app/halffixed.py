"""Half-fixed teaching engine: a plausible anti-rebinding guard that still fails.

This module demonstrates that *more checks* are not the fix. It validates the first resolution
against the egress policy, then applies a visible guard — re-validating the short-lived cached
first answer immediately before the request — but still hands the hostname to the HTTP client, so
the connection performs a fresh connect-time resolution the guard never pinned. Against the demo
resolver's flipping attacker record the guard passes while the flip still reaches the internal
service.

It must only be reachable behind the Compose profile plus explicit environment acknowledgement
enforced by :mod:`dnsrebindjack.app.main`.
"""

from __future__ import annotations

import http.client
import ssl

from dnsrebindjack.app.constants import COMPLETED_VERDICT, UNREACHABLE_VERDICT
from dnsrebindjack.app.fetch import FetchResult, parse_target, resolve_ipv4
from dnsrebindjack.app.vulnerable import _hostname_request
from dnsrebindjack.netblocks import is_blocked


def half_fixed_fetch(url: str, *, timeout: float = 3.0) -> FetchResult:
    """Cache the vetted answer, re-check it, then intentionally re-resolve to connect."""
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

    # The plausible-but-failing guard: cache the first answer for the request's duration and
    # re-validate it immediately before connecting. This never issues a second resolution (the
    # demo resolver flips on the second lookup), and the connection still resolves the hostname
    # afresh — a resolution the guard did not pin.
    guard_ip = validated_ip
    if is_blocked(guard_ip):
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
        guard="cached-recheck",
    )
