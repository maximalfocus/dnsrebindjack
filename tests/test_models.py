from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from dnsrebindjack.config import SEED_TENANTS, SNIPPET_MAX_BYTES
from dnsrebindjack.models import WebhookTarget
from dnsrebindjack.probes import append_probe, deterministic_id, list_probes, snippet
from tests.helpers import fresh_session, get_tenant


def test_seed_tenants_present(session: Session) -> None:
    tenant = get_tenant(session, 0)
    assert tenant.name == SEED_TENANTS[0]["name"]
    assert tenant.token == SEED_TENANTS[0]["token"]


def test_register_webhook_target(session: Session) -> None:
    tenant = get_tenant(session, 0)
    target = WebhookTarget(
        id="11111111-1111-4111-8111-111111111111",
        tenant_id=tenant.id,
        name="partner-hook",
        url="http://hooks.partner.example/deliver",
    )
    session.add(target)
    session.flush()
    session.refresh(tenant)
    assert [t.url for t in tenant.targets] == ["http://hooks.partner.example/deliver"]


def test_append_returns_uuid_and_retains_fields(session: Session) -> None:
    tenant = get_tenant(session, 0)
    record = append_probe(
        session,
        tenant=tenant,
        target_url="http://probe.attacker.example/",
        verdict="completed",
        validated_ip="203.0.113.10",
        connected_ip="10.10.0.9",
        http_status=200,
        latency_ms=12,
        body="internal-only body",
    )
    uuid.UUID(record.id)  # parses as a valid UUID
    assert record.target_url == "http://probe.attacker.example/"
    assert record.verdict == "completed"
    assert record.validated_ip == "203.0.113.10"
    assert record.connected_ip == "10.10.0.9"
    assert record.http_status == 200
    assert record.latency_ms == 12
    assert record.body_snippet == "internal-only body"
    assert record.tenant_id == tenant.id


def test_ids_are_deterministic_across_fresh_state() -> None:
    runs: list[tuple[str, str]] = []
    for _ in range(2):
        s = fresh_session()
        tenant = get_tenant(s, 0)
        r1 = append_probe(s, tenant=tenant, target_url="a", verdict="completed")
        r2 = append_probe(s, tenant=tenant, target_url="b", verdict="rejected")
        runs.append((r1.id, r2.id))
        s.close()
    assert runs[0] == runs[1]
    assert runs[0][0] != runs[0][1]
    assert runs[0][0] == deterministic_id(SEED_TENANTS[0]["id"], 0)


def test_ordering_and_isolation_between_tenants() -> None:
    s = fresh_session()
    acme = get_tenant(s, 0)
    globex = get_tenant(s, 1)
    append_probe(s, tenant=acme, target_url="a1", verdict="completed")
    append_probe(s, tenant=globex, target_url="b1", verdict="rejected")
    append_probe(s, tenant=acme, target_url="a2", verdict="completed")

    assert [p.target_url for p in list_probes(s, acme)] == ["a1", "a2"]
    assert [p.target_url for p in list_probes(s, globex)] == ["b1"]
    s.close()


def test_snippet_caps_bytes() -> None:
    big = "x" * (SNIPPET_MAX_BYTES + 100)
    capped = snippet(big)
    assert len(capped.encode("utf-8")) == SNIPPET_MAX_BYTES
    assert snippet("short") == "short"


def test_no_mutation_or_delete_api() -> None:
    import dnsrebindjack.probes as probes

    for forbidden in ("delete_probe", "update_probe", "remove_probe", "clear_probes"):
        assert not hasattr(probes, forbidden)
