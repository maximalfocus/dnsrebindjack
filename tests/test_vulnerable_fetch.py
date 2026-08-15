from __future__ import annotations

import pytest

import dnsrebindjack.app.vulnerable as vulnerable
from dnsrebindjack.app.constants import COMPLETED_VERDICT, UNREACHABLE_VERDICT


def test_vulnerable_fetch_checks_then_fetches_by_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []

    def resolve(host: str) -> str:
        order.append(f"check:{host}")
        return "203.0.113.10"

    def request(url: str, *, timeout: float) -> tuple[int, str, str]:
        del timeout
        order.append(f"connect:{url}")
        return 200, "internal", "10.10.0.9"

    monkeypatch.setattr(vulnerable, "resolve_ipv4", resolve)
    monkeypatch.setattr(vulnerable, "_hostname_request", request)
    result = vulnerable.vulnerable_fetch("http://probe.attacker.example/internal")
    assert order == [
        "check:probe.attacker.example",
        "connect:http://probe.attacker.example/internal",
    ]
    assert result.verdict == COMPLETED_VERDICT
    assert result.validated_ip == "203.0.113.10"
    assert result.connected_ip == "10.10.0.9"


def test_vulnerable_fetch_still_blocks_disallowed_first_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_connect(url: str, *, timeout: float) -> tuple[int, str, str]:
        raise AssertionError("disallowed first answer reached connect boundary")

    monkeypatch.setattr(vulnerable, "resolve_ipv4", lambda host: "10.10.0.9")
    monkeypatch.setattr(vulnerable, "_hostname_request", must_not_connect)
    result = vulnerable.vulnerable_fetch("http://probe.attacker.example/")
    assert result.verdict == UNREACHABLE_VERDICT
    assert result.connected_ip is None
