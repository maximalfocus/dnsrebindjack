"""Append-only probe-record service.

Record identifiers are deterministic UUID strings derived from the owning tenant and the
per-tenant insertion index, so a fresh run against fresh state produces identical output. This
module deliberately exposes no update or delete operation: records are append-only.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from dnsrebindjack.config import SNIPPET_MAX_BYTES
from dnsrebindjack.models import ProbeRecord, Tenant

# Fixed namespace so record identifiers are reproducible across fresh runs.
_PROBE_NAMESPACE = uuid.UUID("d1f5eb1d-0000-4000-8000-000000000000")


def snippet(body: str) -> str:
    """Length-cap a fetched body to ``SNIPPET_MAX_BYTES`` bytes without splitting UTF-8."""
    encoded = body.encode("utf-8")[:SNIPPET_MAX_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def deterministic_id(tenant_id: str, index: int) -> str:
    """The reproducible UUID identifier for the ``index``-th probe of ``tenant_id``."""
    return str(uuid.uuid5(_PROBE_NAMESPACE, f"{tenant_id}:{index}"))


def _next_index(session: Session, tenant_id: str) -> int:
    count = session.scalar(
        select(func.count()).select_from(ProbeRecord).where(ProbeRecord.tenant_id == tenant_id)
    )
    return count or 0


def append_probe(
    session: Session,
    *,
    tenant: Tenant,
    target_url: str,
    verdict: str,
    validated_ip: str | None = None,
    connected_ip: str | None = None,
    http_status: int | None = None,
    latency_ms: int | None = None,
    body: str | None = None,
) -> ProbeRecord:
    """Append one probe record for ``tenant`` and return it."""
    index = _next_index(session, tenant.id)
    record = ProbeRecord(
        id=deterministic_id(tenant.id, index),
        tenant_id=tenant.id,
        target_url=target_url,
        verdict=verdict,
        validated_ip=validated_ip,
        connected_ip=connected_ip,
        http_status=http_status,
        latency_ms=latency_ms,
        body_snippet=snippet(body) if body is not None else None,
    )
    session.add(record)
    session.flush()
    return record


def list_probes(session: Session, tenant: Tenant) -> list[ProbeRecord]:
    """Return ``tenant``'s probe records in stable insertion order."""
    return list(
        session.scalars(
            select(ProbeRecord).where(ProbeRecord.tenant_id == tenant.id).order_by(ProbeRecord.seq)
        )
    )
