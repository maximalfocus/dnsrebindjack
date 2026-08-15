"""Vulnerable variant acceptance over the real flipping DNS and HTTP boundary."""

from __future__ import annotations

import os

import httpx
import pytest

from dnsrebindjack.app.constants import COMPLETED_VERDICT
from dnsrebindjack.config import SEED_TENANTS
from dnsrebindjack.fixtures import data

pytestmark = [
    pytest.mark.topology,
    pytest.mark.skipif(
        os.environ.get("RUN_VULNERABLE_TOPOLOGY") != "true",
        reason="run by the opt-in vulnerable Compose verification phase",
    ),
]

_APP = "http://vulnerable:8080"
_RESOLVER = f"http://{data.RESOLVER_IP}:8053"
_INTERNAL = f"http://{data.INTERNAL_IP}"
_TOKEN = SEED_TENANTS[0]["token"]
_HEADERS = {"Authorization": f"Bearer {_TOKEN}"}


def _reset() -> None:
    httpx.post(f"{_RESOLVER}/reset", timeout=5).raise_for_status()
    httpx.post(f"{_INTERNAL}/_signal/reset", timeout=5).raise_for_status()


def _probe(name: str, url: str) -> dict[str, object]:
    target = httpx.post(
        f"{_APP}/targets", headers=_HEADERS, json={"name": name, "url": url}, timeout=5
    )
    target.raise_for_status()
    result = httpx.post(f"{_APP}/targets/{target.json()['id']}/probe", headers=_HEADERS, timeout=8)
    result.raise_for_status()
    return dict(result.json())


def test_vulnerable_attacker_rebinds_to_internal_service_and_discloses_marker() -> None:
    _reset()
    result = _probe("attacker", f"http://{data.ATTACKER_NAME}/internal/fleet-config")
    assert result["verdict"] == COMPLETED_VERDICT
    assert data.INTERNAL_MARKER in str(result["body"])

    queries = httpx.get(f"{_RESOLVER}/log", timeout=5).json()["queries"]
    answers = [
        q["answer"] for q in queries if q["name"] == data.ATTACKER_NAME and q["qtype"] == "A"
    ]
    assert answers == [data.ALLOWED_FIRST_IP, data.INTERNAL_IP]
    assert httpx.get(f"{_INTERNAL}/_signal", timeout=5).json()["contacts"] == 1

    audit = httpx.get(f"{_APP}/audit", headers=_HEADERS, timeout=5).json()["events"][-1]
    assert audit["validated_ip"] == data.ALLOWED_FIRST_IP
    assert audit["connected_ip"] == data.INTERNAL_IP
    assert data.INTERNAL_MARKER not in str(audit)
    assert _TOKEN not in str(audit)


def test_vulnerable_legitimate_probe_still_succeeds() -> None:
    _reset()
    result = _probe("partner", f"http://{data.LEGIT_NAME}/deliver")
    assert result["verdict"] == COMPLETED_VERDICT
    assert result["body"] == data.BENIGN_PAYLOAD
