"""Integration tests over the hermetic in-network fixture topology.

These run inside the `verify` compose service, which is attached to both fixture networks and uses
the demo resolver as its ONLY DNS. They assert the resolver's rebinding flip and stable legitimate
answer, that the internal-only service is reachable in-network and serves its marker (with an
observable inbound signal), that the benign upstream is reachable, that names resolve only through
the demo resolver (no real DNS), and that there is no route to the public internet.
"""

from __future__ import annotations

import socket

import httpx
import pytest
from dnslib import QTYPE, RCODE, DNSRecord

from dnsrebindjack.fixtures import data
from dnsrebindjack.netblocks import is_blocked

pytestmark = pytest.mark.topology

_CONTROL = f"http://{data.RESOLVER_IP}:8053"
_INTERNAL = f"http://{data.INTERNAL_IP}"
_UPSTREAM = f"http://{data.UPSTREAM_IP}"


def _dns_response(name: str, qtype: str) -> DNSRecord:
    """Send one DNS query straight to the demo resolver (bypassing the stub resolver) and parse."""
    request = DNSRecord.question(name, qtype)
    last_error: Exception | None = None
    for _ in range(3):
        try:
            raw = request.send(data.RESOLVER_IP, 53, tcp=False, timeout=5)
            return DNSRecord.parse(raw)
        except TimeoutError as exc:  # pragma: no cover - transient UDP loss
            last_error = exc
    raise AssertionError(f"resolver did not answer {qtype} {name}: {last_error}")


def _query_a(name: str) -> str | None:
    response = _dns_response(name, "A")
    for rr in response.rr:
        if QTYPE[rr.rtype] == "A":
            return str(rr.rdata)
    return None


def _reset_resolver() -> None:
    httpx.post(f"{_CONTROL}/reset", timeout=5).raise_for_status()


def _resolver_log() -> list[dict[str, object]]:
    resp = httpx.get(f"{_CONTROL}/log", timeout=5)
    resp.raise_for_status()
    return list(resp.json()["queries"])


def test_resolver_flips_attacker_name_across_lookups() -> None:
    # The core proof that this is rebinding and not a static misconfiguration: the same name yields
    # two different answers across successive lookups — allowed first, internal next.
    _reset_resolver()
    first = _query_a(data.ATTACKER_NAME)
    second = _query_a(data.ATTACKER_NAME)
    assert first == data.ALLOWED_FIRST_IP
    assert second == data.INTERNAL_IP
    assert first != second
    assert not is_blocked(first)  # the validation lookup passes the egress policy
    assert is_blocked(second)  # the connect-time lookup lands in a blocked range


def test_resolver_is_stable_for_the_legit_name() -> None:
    first = _query_a(data.LEGIT_NAME)
    second = _query_a(data.LEGIT_NAME)
    assert first == second == data.UPSTREAM_IP
    assert not is_blocked(first)


def test_resolver_answers_are_observable_in_the_log() -> None:
    _reset_resolver()
    _query_a(data.ATTACKER_NAME)
    log = _resolver_log()
    attacker_a = [e for e in log if e["name"] == data.ATTACKER_NAME and e["qtype"] == "A"]
    assert attacker_a, "resolver log did not record the attacker A query"
    assert attacker_a[0]["answer"] == data.ALLOWED_FIRST_IP


def test_resolver_returns_nxdomain_for_unknown_names() -> None:
    response = _dns_response("nonexistent.invalid.example", "A")
    assert response.header.rcode == RCODE.NXDOMAIN


def test_internal_service_reachable_in_network_and_serves_marker() -> None:
    resp = httpx.get(f"{_INTERNAL}/", timeout=5)
    assert resp.status_code == 200
    assert data.INTERNAL_MARKER in resp.text
    assert resp.text == data.INTERNAL_PAYLOAD
    assert is_blocked(data.INTERNAL_IP)


def test_internal_service_inbound_signal_counts_contacts() -> None:
    httpx.post(f"{_INTERNAL}/_signal/reset", timeout=5).raise_for_status()
    assert httpx.get(f"{_INTERNAL}/_signal", timeout=5).json()["contacts"] == 0
    httpx.get(f"{_INTERNAL}/internal/fleet-config", timeout=5)
    signal = httpx.get(f"{_INTERNAL}/_signal", timeout=5).json()
    assert signal["contacts"] == 1
    assert "/internal/fleet-config" in signal["paths"]


def test_upstream_reachable_serves_benign_content() -> None:
    resp = httpx.get(f"{_UPSTREAM}/", timeout=5)
    assert resp.status_code == 200
    assert resp.text == data.BENIGN_PAYLOAD
    assert data.INTERNAL_MARKER not in resp.text
    assert not is_blocked(data.UPSTREAM_IP)


def test_container_uses_the_demo_resolver_for_names() -> None:
    # gethostbyname goes through the stub resolver -> the demo resolver (the container's only DNS).
    assert socket.gethostbyname(data.LEGIT_NAME) == data.UPSTREAM_IP


def test_no_real_dns_for_unknown_names() -> None:
    # A non-demo name does not resolve: the demo resolver is authoritative-only, with no recursion.
    with pytest.raises(socket.gaierror):
        socket.gethostbyname("example.com")


def test_no_public_egress() -> None:
    # Both fixture networks are `internal: true`, so there is no route off-network.
    with pytest.raises((httpx.ConnectError, httpx.ConnectTimeout)):
        httpx.get("http://8.8.8.8/", timeout=2)
