"""Deterministic three-variant comparison runner (FR-012).

Brings the whole walkthrough to one command: for each variant (secure, vulnerable, half-fixed)
it resets the resolver flip state and the internal service's inbound signal, probes the attacker
name and the legitimate partner name against fresh state, and prints a readable verdict — the
egress check result, both DNS answers observed, where the fetch landed, and whether internal
content was disclosed. It asserts the expected outcome of every axis and exits non-zero on any
mismatch, so the scripted comparison is itself a check.

Run inside the demo network as ``python -m dnsrebindjack.demo.compare``; the runner service in
``docker-compose.yml`` does exactly that.
"""

from __future__ import annotations

import sys

import httpx

from dnsrebindjack.app.constants import COMPLETED_VERDICT, UNREACHABLE_VERDICT
from dnsrebindjack.config import SEED_TENANTS
from dnsrebindjack.fixtures import data
from dnsrebindjack.netblocks import is_blocked

_APPS: dict[str, str] = {
    "secure": "http://secure:8080",
    "vulnerable": "http://vulnerable:8080",
    "half-fixed": "http://half-fixed:8080",
}
_RESOLVER = f"http://{data.RESOLVER_IP}:8053"
_INTERNAL = f"http://{data.INTERNAL_IP}"
_TOKEN = SEED_TENANTS[0]["token"]
_HEADERS = {"Authorization": f"Bearer {_TOKEN}"}
_ATTACKER_URL = f"http://{data.ATTACKER_NAME}/internal/fleet-config"
_LEGIT_URL = f"http://{data.LEGIT_NAME}/deliver"

_problems: list[str] = []


def _check(condition: bool, message: str) -> None:
    if not condition:
        _problems.append(message)


def _reset() -> None:
    httpx.post(f"{_RESOLVER}/reset", timeout=5).raise_for_status()
    httpx.post(f"{_INTERNAL}/_signal/reset", timeout=5).raise_for_status()


def _probe(
    app: str, name: str, url: str
) -> tuple[dict[str, object], dict[str, object], list[str], int]:
    target = httpx.post(
        f"{app}/targets", headers=_HEADERS, json={"name": name, "url": url}, timeout=5
    )
    target.raise_for_status()
    target_id = str(target.json()["id"])
    result = httpx.post(f"{app}/targets/{target_id}/probe", headers=_HEADERS, timeout=8)
    result.raise_for_status()
    # The addresses the egress policy validated and actually connected to live in the audit
    # event (the probe response deliberately omits them).
    audit = httpx.get(f"{app}/audit", headers=_HEADERS, timeout=5).json()["events"][-1]
    log = httpx.get(f"{_RESOLVER}/log", timeout=5).json()["queries"]
    answers = [
        str(q["answer"]) for q in log if q["name"] == data.ATTACKER_NAME and q["qtype"] == "A"
    ]
    contacts = int(httpx.get(f"{_INTERNAL}/_signal", timeout=5).json()["contacts"])
    return result.json(), audit, answers, contacts


def _run_attacker_scenario(label: str, app: str) -> None:
    _reset()
    result, audit, answers, contacts = _probe(app, f"attacker-{label}", _ATTACKER_URL)
    verdict = str(result["verdict"])
    validated_ip = audit["validated_ip"]
    connected_ip = audit["connected_ip"]
    disclosed = data.INTERNAL_MARKER in str(result["body"])
    egress = (
        "allowed" if validated_ip is not None and not is_blocked(str(validated_ip)) else "blocked"
    )

    print(f"[{label}] attacker probe: {data.ATTACKER_NAME}")
    print(f"  egress check : {validated_ip} ({egress})")
    print(f"  dns answers  : {' -> '.join(answers) if answers else '(none)'}")
    print(f"  landed on    : {connected_ip or '(none)'}")
    print(
        f"  internal     : {'contacted (' + str(contacts) + ')' if contacts else 'not contacted'}"
    )
    print(
        f"  disclosure   : {'YES - ' + data.INTERNAL_MARKER + ' returned' if disclosed else 'no'}"
    )

    if label == "secure":
        _check(
            verdict == UNREACHABLE_VERDICT,
            f"{label}: expected {UNREACHABLE_VERDICT}, got {verdict}",
        )
        _check(connected_ip is None, f"{label}: must never connect to any peer")
        _check(contacts == 0, f"{label}: internal service was contacted ({contacts})")
        _check(not disclosed, f"{label}: internal content was disclosed")
        _check(
            answers == [data.ALLOWED_FIRST_IP],
            f"{label}: expected one lookup [{data.ALLOWED_FIRST_IP}], got {answers}",
        )
    else:
        _check(
            verdict == COMPLETED_VERDICT, f"{label}: expected {COMPLETED_VERDICT}, got {verdict}"
        )
        _check(
            connected_ip == data.INTERNAL_IP,
            f"{label}: expected to land on {data.INTERNAL_IP}, got {connected_ip}",
        )
        _check(contacts == 1, f"{label}: expected one internal contact, got {contacts}")
        _check(disclosed, f"{label}: {data.INTERNAL_MARKER} was not disclosed")
        _check(
            answers == [data.ALLOWED_FIRST_IP, data.INTERNAL_IP],
            f"{label}: expected two differing answers, got {answers}",
        )


def _run_legit_scenario(label: str, app: str) -> None:
    _reset()
    result, _audit, _answers, _contacts = _probe(app, f"partner-{label}", _LEGIT_URL)
    verdict = str(result["verdict"])
    body = str(result["body"])
    ok = verdict == COMPLETED_VERDICT and body == data.BENIGN_PAYLOAD
    print(f"[{label}] legitimate probe: {data.LEGIT_NAME} -> {'ok' if ok else 'FAILED'}")
    _check(ok, f"{label}: legitimate probe failed (verdict={verdict})")


def main() -> int:
    print("dnsrebindjack demo — deterministic three-variant comparison")
    print(
        f"resolver: {data.RESOLVER_IP}  internal: {data.INTERNAL_IP}  upstream: {data.UPSTREAM_IP}"
    )
    for label, app in _APPS.items():
        print(f"--- {label} ---")
        _run_attacker_scenario(label, app)
        _run_legit_scenario(label, app)
    if _problems:
        print("comparison FAILED:")
        for problem in _problems:
            print(f"  - {problem}")
        return 1
    print(
        "comparison passed: secure blocks, vulnerable and half-fixed bypass, "
        "legitimate use preserved."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
