"""Secure-app acceptance at the real in-network HTTP/DNS boundary."""

from __future__ import annotations

import httpx
import pytest

from dnsrebindjack.app.constants import COMPLETED_VERDICT, UNREACHABLE_VERDICT
from dnsrebindjack.config import SEED_TENANTS
from dnsrebindjack.fixtures import data

pytestmark = pytest.mark.topology

_APP = "http://secure:8080"
_RESOLVER = f"http://{data.RESOLVER_IP}:8053"
_INTERNAL = f"http://{data.INTERNAL_IP}"
_TOKEN = SEED_TENANTS[0]["token"]
_HEADERS = {"Authorization": f"Bearer {_TOKEN}"}


def _reset() -> None:
    httpx.post(f"{_RESOLVER}/reset", timeout=5).raise_for_status()
    httpx.post(f"{_INTERNAL}/_signal/reset", timeout=5).raise_for_status()


def _register_and_probe(name: str, url: str) -> httpx.Response:
    created = httpx.post(
        f"{_APP}/targets", headers=_HEADERS, json={"name": name, "url": url}, timeout=5
    )
    created.raise_for_status()
    return httpx.post(f"{_APP}/targets/{created.json()['id']}/probe", headers=_HEADERS, timeout=8)


def test_secure_legitimate_probe_succeeds_through_pinned_address() -> None:
    _reset()
    response = _register_and_probe("partner", f"http://{data.LEGIT_NAME}/deliver")
    response.raise_for_status()
    result = response.json()
    assert result["verdict"] == COMPLETED_VERDICT
    assert result["http_status"] == 200
    assert result["body"] == data.BENIGN_PAYLOAD
    queries = httpx.get(f"{_RESOLVER}/log", timeout=5).json()["queries"]
    answers = [q["answer"] for q in queries if q["name"] == data.LEGIT_NAME and q["qtype"] == "A"]
    assert answers == [data.UPSTREAM_IP]


def test_secure_attacker_probe_never_reresolves_or_contacts_internal_service() -> None:
    _reset()
    response = _register_and_probe("attacker", f"http://{data.ATTACKER_NAME}/internal/fleet-config")
    response.raise_for_status()
    result = response.json()
    assert result["verdict"] == UNREACHABLE_VERDICT
    assert result["http_status"] is None
    assert result["body"] is None

    queries = httpx.get(f"{_RESOLVER}/log", timeout=5).json()["queries"]
    answers = [
        q["answer"] for q in queries if q["name"] == data.ATTACKER_NAME and q["qtype"] == "A"
    ]
    assert answers == [data.ALLOWED_FIRST_IP]
    assert httpx.get(f"{_INTERNAL}/_signal", timeout=5).json()["contacts"] == 0

    audit = httpx.get(f"{_APP}/audit", headers=_HEADERS, timeout=5).json()["events"][-1]
    assert audit["validated_ip"] == data.ALLOWED_FIRST_IP
    assert audit["connected_ip"] is None
    serialized = str(audit)
    assert data.INTERNAL_MARKER not in serialized
    assert _TOKEN not in serialized


def test_auth_failures_are_uniform_generic_401() -> None:
    bodies = []
    for headers in ({}, {"Authorization": "Basic nope"}, {"Authorization": "Bearer unknown"}):
        response = httpx.post(
            f"{_APP}/targets", headers=headers, json={"name": "x", "url": "http://x.example/"}
        )
        assert response.status_code == 401
        bodies.append(response.content)
    assert len(set(bodies)) == 1
    assert _TOKEN.encode() not in bodies[0]
