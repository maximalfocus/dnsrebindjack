from __future__ import annotations

from dnsrebindjack.fixtures import data
from dnsrebindjack.netblocks import is_blocked


def test_internal_and_resolver_addresses_are_blocked() -> None:
    assert is_blocked(data.INTERNAL_IP)  # 10.10.0.9
    assert is_blocked(data.RESOLVER_IP)  # 10.10.0.53


def test_documentation_range_not_blocked() -> None:
    # The benign upstream and the attacker name's first (allowed) answer live in a documentation
    # range, outside every block.
    assert not is_blocked(data.UPSTREAM_IP)  # 203.0.113.20
    assert not is_blocked(data.ALLOWED_FIRST_IP)  # 203.0.113.10
    assert not is_blocked("192.0.2.10")


def test_private_loopback_linklocal_cgnat_and_unspecified_blocked() -> None:
    for ip in (
        "10.13.37.10",
        "127.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",
        "169.254.169.254",
        "0.0.0.0",
    ):
        assert is_blocked(ip)


def test_public_addresses_not_blocked() -> None:
    # Reserved documentation addresses (RFC 5737 TEST-NET-2/TEST-NET-1) stand in for ordinary
    # public targets: outside every blocked range, and not a real host.
    for ip in ("198.51.100.10", "192.0.2.20"):
        assert not is_blocked(ip)


def test_ipv6_ranges() -> None:
    assert is_blocked("::1")
    assert is_blocked("fe80::1")
    assert is_blocked("fc00::1")
    # RFC 3849 documentation prefix: global-scope IPv6, outside every blocked range.
    assert not is_blocked("2001:db8::1")
