"""Shared, wholly fictional constants for the in-network fixtures.

Nothing here is a real host, name, or address. Names use RFC 2606 ``.example``; addresses use
RFC 5737 documentation space (``203.0.113.0/24``, treated as allowed/public) and RFC 1918 private
space (treated as internal/blocked). The internal payload declares its fictional nature in its own
contents.
"""

from __future__ import annotations

import json
from typing import Final

# --- In-network fixture identities. docker-compose.yml binds these exact addresses/names. ---

# The legitimate partner endpoint: a stable, allowed public-range address.
LEGIT_NAME: Final = "hooks.partner.example"
UPSTREAM_IP: Final = "203.0.113.20"

# The attacker-controlled endpoint: its DNS answer FLIPS across lookups. The first (validation)
# lookup returns an allowed public-range address; every subsequent (connect-time) lookup returns
# the internal blocked-range address.
ATTACKER_NAME: Final = "probe.attacker.example"
ALLOWED_FIRST_IP: Final = "203.0.113.10"  # allowed at check time (nothing actually serves here)
INTERNAL_IP: Final = "10.10.0.9"  # the internal-only service (blocked range)

# The demo-owned authoritative resolver — the application's ONLY DNS.
RESOLVER_IP: Final = "10.10.0.53"

FICTIONAL_NOTICE: Final = (
    "FICTIONAL DEMO FIXTURE - invented for the dnsrebindjack DNS-rebinding teaching demo; "
    "grants no access to any real system."
)

# The obvious marker that proves internal-only content was disclosed. Tests assert its presence.
INTERNAL_MARKER: Final = "INTERNAL-ONLY"

_INTERNAL_DOC: Final = {
    "document": "fleet-config",
    "classification": INTERNAL_MARKER,
    "note": (
        f"{INTERNAL_MARKER} synthetic internal fleet configuration for the dnsrebindjack DEMO. "
        "This service is reachable only inside the demo network and is never published to the host."
    ),
    "fleet": {
        "region": "demo-internal",
        "nodes": ["fleet-node-a", "fleet-node-b"],
        "rotation_hint": "FICTIONAL-not-a-real-secret",
    },
    "_warning": FICTIONAL_NOTICE,
}
INTERNAL_PAYLOAD: Final = json.dumps(_INTERNAL_DOC, indent=2) + "\n"

_BENIGN_DOC: Final = {
    "status": "ok",
    "service": LEGIT_NAME,
    "note": "FICTIONAL benign partner endpoint for the dnsrebindjack demo.",
}
BENIGN_PAYLOAD: Final = json.dumps(_BENIGN_DOC, indent=2) + "\n"
