"""Canonical blocked-address ranges for the demo egress policy.

These are the ranges the secure fetch path treats as internal / non-routable and refuses to
reach, and the same definition the SLICE-001 topology verification uses to assert where each
fixture lives. Documentation ranges (e.g. ``203.0.113.0/24``) are deliberately NOT blocked: the
benign upstream fixture — and the attacker name's first, allowed answer — live there, representing
ordinary public targets.
"""

from __future__ import annotations

import ipaddress
from typing import Final

BLOCKED_CIDRS: Final = (
    "0.0.0.0/8",  # this-network / unspecified
    "10.0.0.0/8",  # private (the internal-only service lives here)
    "100.64.0.0/10",  # carrier-grade NAT
    "127.0.0.0/8",  # loopback
    "169.254.0.0/16",  # link-local
    "172.16.0.0/12",  # private
    "192.168.0.0/16",  # private
    "240.0.0.0/4",  # reserved
    "255.255.255.255/32",  # limited broadcast
    "::1/128",  # loopback (IPv6)
    "::/128",  # unspecified (IPv6)
    "fc00::/7",  # unique-local (IPv6)
    "fe80::/10",  # link-local (IPv6)
)

_NETWORKS: Final = tuple(ipaddress.ip_network(cidr) for cidr in BLOCKED_CIDRS)


def is_blocked(ip: str) -> bool:
    """Return ``True`` if ``ip`` falls in any blocked range."""
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in _NETWORKS)
