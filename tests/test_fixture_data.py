from __future__ import annotations

import ipaddress
import json

from dnsrebindjack.fixtures import data
from dnsrebindjack.netblocks import is_blocked


def test_names_use_reserved_example_tld() -> None:
    assert data.ATTACKER_NAME.endswith(".example")
    assert data.LEGIT_NAME.endswith(".example")


def test_addresses_fall_in_the_expected_ranges() -> None:
    # First (validation) answer and the upstream are allowed documentation range; the flipped
    # answer and the resolver are blocked private range.
    doc = ipaddress.ip_network("203.0.113.0/24")
    assert ipaddress.ip_address(data.ALLOWED_FIRST_IP) in doc
    assert ipaddress.ip_address(data.UPSTREAM_IP) in doc
    assert ipaddress.ip_address(data.INTERNAL_IP) in ipaddress.ip_network("10.0.0.0/8")
    assert ipaddress.ip_address(data.RESOLVER_IP) in ipaddress.ip_network("10.0.0.0/8")
    assert not is_blocked(data.ALLOWED_FIRST_IP)
    assert not is_blocked(data.UPSTREAM_IP)
    assert is_blocked(data.INTERNAL_IP)


def test_the_flip_targets_differ_and_straddle_the_egress_policy() -> None:
    # The whole point: the same name's two answers land on opposite sides of the egress policy.
    assert data.ALLOWED_FIRST_IP != data.INTERNAL_IP
    assert not is_blocked(data.ALLOWED_FIRST_IP)
    assert is_blocked(data.INTERNAL_IP)


def test_internal_payload_declares_itself_internal_and_fictional() -> None:
    doc = json.loads(data.INTERNAL_PAYLOAD)
    assert doc["classification"] == data.INTERNAL_MARKER
    assert data.INTERNAL_MARKER in data.INTERNAL_PAYLOAD
    assert "FICTIONAL" in doc["_warning"]


def test_internal_payload_leaks_no_real_credential() -> None:
    doc = json.loads(data.INTERNAL_PAYLOAD)
    # The one "secret-shaped" value is conspicuously fictional, and nothing resembles a real key.
    assert "FICTIONAL" in doc["fleet"]["rotation_hint"]
    for leak in ("aws_secret", "akia", "private_key", "-----begin"):
        assert leak not in data.INTERNAL_PAYLOAD.lower()


def test_benign_payload_is_benign_and_fictional() -> None:
    doc = json.loads(data.BENIGN_PAYLOAD)
    assert doc["status"] == "ok"
    assert doc["service"] == data.LEGIT_NAME
    assert "FICTIONAL" in data.BENIGN_PAYLOAD


def test_serialized_payloads_are_stable_strings() -> None:
    for value in (data.INTERNAL_PAYLOAD, data.BENIGN_PAYLOAD):
        assert isinstance(value, str)
        assert value.endswith("\n")
