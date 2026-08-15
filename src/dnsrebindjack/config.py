"""Deterministic, wholly fictional configuration for the webhook-integrations demo product."""

from __future__ import annotations

from typing import Final, TypedDict


class SeedTenant(TypedDict):
    id: str
    name: str
    token: str


# Fixed fictional tenants. Tokens are conspicuously demo-only; they are never real secrets and
# their unpredictability is never relied on as a security control.
SEED_TENANTS: Final[tuple[SeedTenant, ...]] = (
    {
        "id": "00000000-0000-0000-0000-000000000001",
        "name": "acme-widgets",
        "token": "demo-token-acme-FICTIONAL",
    },
    {
        "id": "00000000-0000-0000-0000-000000000002",
        "name": "globex-events",
        "token": "demo-token-globex-FICTIONAL",
    },
)

# Stored fetched-body snippets are capped to this many bytes.
SNIPPET_MAX_BYTES: Final = 512
