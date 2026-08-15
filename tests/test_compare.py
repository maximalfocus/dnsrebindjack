"""The scripted comparison runner fails closed when an expected outcome is not observed."""

from __future__ import annotations

import pytest

from dnsrebindjack.app.constants import COMPLETED_VERDICT
from dnsrebindjack.demo import compare
from dnsrebindjack.fixtures import data


class _FakeResponse:
    def __init__(self, payload: object) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self._payload


def _scripted_breach(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate every variant reaching the internal service and disclosing its marker."""

    def post(url: str, **kwargs: object) -> _FakeResponse:
        del kwargs
        if url.endswith("/probe"):
            return _FakeResponse(
                {"id": "t1", "verdict": COMPLETED_VERDICT, "http_status": 200, "body": "internal"}
            )
        return _FakeResponse({"id": "t1"})

    def get(url: str, **kwargs: object) -> _FakeResponse:
        del kwargs
        if url.endswith("/audit"):
            return _FakeResponse(
                {"events": [{"validated_ip": "203.0.113.10", "connected_ip": data.INTERNAL_IP}]}
            )
        if url.endswith("/log"):
            return _FakeResponse(
                {
                    "queries": [
                        {"name": data.ATTACKER_NAME, "qtype": "A", "answer": data.INTERNAL_IP}
                    ]
                }
            )
        return _FakeResponse({"contacts": 1})

    monkeypatch.setattr(compare.httpx, "post", post)
    monkeypatch.setattr(compare.httpx, "get", get)


def test_compare_exits_nonzero_when_expected_outcomes_are_not_observed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _scripted_breach(monkeypatch)
    assert compare.main() == 1
