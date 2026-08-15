from __future__ import annotations

import pytest

import dnsrebindjack.app.fetch as fetch
from dnsrebindjack.app.constants import COMPLETED_VERDICT, UNREACHABLE_VERDICT


def test_secure_fetch_resolves_once_and_pins_that_address(monkeypatch: pytest.MonkeyPatch) -> None:
    lookups: list[str] = []

    def resolver(host: str) -> str:
        lookups.append(host)
        return "203.0.113.20"

    def request(parsed: object, pinned_ip: str, *, timeout: float) -> tuple[int, str, str]:
        del parsed, timeout
        return 200, "benign", pinned_ip

    monkeypatch.setattr(fetch, "_pinned_request", request)
    result = fetch.secure_fetch("http://hooks.partner.example/deliver", resolver=resolver)
    assert lookups == ["hooks.partner.example"]
    assert result.verdict == COMPLETED_VERDICT
    assert result.validated_ip == result.connected_ip == "203.0.113.20"
    assert result.body == "benign"


def test_secure_fetch_rejects_blocked_address_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_connect(parsed: object, pinned_ip: str, *, timeout: float) -> tuple[int, str, str]:
        raise AssertionError("blocked address reached the request boundary")

    monkeypatch.setattr(fetch, "_pinned_request", must_not_connect)
    result = fetch.secure_fetch(
        "http://probe.attacker.example/internal", resolver=lambda host: "10.10.0.9"
    )
    assert result.verdict == UNREACHABLE_VERDICT
    assert result.validated_ip == "10.10.0.9"
    assert result.connected_ip is None
    assert result.body is None


def test_invalid_and_unreachable_targets_share_generic_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(parsed: object, pinned_ip: str, *, timeout: float) -> tuple[int, str, str]:
        raise ConnectionError("unreachable")

    monkeypatch.setattr(fetch, "_pinned_request", unavailable)
    blocked = fetch.secure_fetch("http://probe.attacker.example/", resolver=lambda host: "10.0.0.9")
    unreachable = fetch.secure_fetch(
        "http://probe.attacker.example/", resolver=lambda host: "203.0.113.10"
    )
    invalid = fetch.secure_fetch("file:///etc/passwd")
    assert {blocked.verdict, unreachable.verdict, invalid.verdict} == {UNREACHABLE_VERDICT}


def test_url_credentials_are_rejected_before_resolution() -> None:
    resolved = False

    def resolver(host: str) -> str:
        nonlocal resolved
        resolved = True
        return "203.0.113.20"

    result = fetch.secure_fetch("http://demo-token@hooks.partner.example/", resolver=resolver)
    assert result.verdict == UNREACHABLE_VERDICT
    assert not resolved
