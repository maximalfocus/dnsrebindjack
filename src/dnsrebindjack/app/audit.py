"""Structured probe audit event.

Emitted once per probe to stdout (the demo operator's observability channel) and retained in a
small in-process ring for tests and the scripted demo. It records the outcome — the verdict, the
address the egress policy validated, and the address actually connected to — so "where did the
fetch land?" is legible. It NEVER includes fetched content (no internal payload), tenant tokens,
Authorization headers, or PII: only the fictional tenant name and target host appear.
"""

from __future__ import annotations

import json
import uuid
from typing import Final

# Fixed namespace so a correlation id is reproducible for identical probes across fresh runs.
_AUDIT_NAMESPACE = uuid.UUID("a0d17000-0000-4000-8000-000000000000")

_MAX_RETAINED: Final = 200
_RECENT: list[dict[str, object]] = []


def emit_probe_event(
    *,
    tenant_name: str,
    target_host: str,
    verdict: str,
    validated_ip: str | None,
    connected_ip: str | None,
    http_status: int | None,
    rejection_class: str | None,
    guard: str | None = None,
) -> dict[str, object]:
    """Emit and return one probe audit event (returned and retained for testability)."""
    request_id = str(
        uuid.uuid5(_AUDIT_NAMESPACE, f"{tenant_name}:{target_host}:{verdict}:{rejection_class}")
    )
    event: dict[str, object] = {
        "event": "probe",
        "request_id": request_id,
        "tenant": tenant_name,
        "target_host": target_host,
        "verdict": verdict,
        "validated_ip": validated_ip,
        "connected_ip": connected_ip,
        "http_status": http_status,
        "rejection_class": rejection_class,
        "guard": guard,
    }
    print(json.dumps(event), flush=True)
    _RECENT.append(event)
    del _RECENT[:-_MAX_RETAINED]
    return event


def recent_events() -> list[dict[str, object]]:
    return list(_RECENT)


def reset_events() -> None:
    _RECENT.clear()
