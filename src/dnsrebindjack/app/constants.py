"""Fixed, generic response bodies shared by every application entry point.

The unauthorized body is a byte-identical constant so authentication failures reveal nothing about
which part failed. Probe *failures* are rendered from a probe record whose verdict is the single
generic ``unreachable`` — a blocked address and an empty/unreachable endpoint are indistinguishable
to the caller (no oracle).
"""

from __future__ import annotations

import json
from typing import Final

# Missing, malformed, and unknown credentials return exactly this body with a 401 status.
GENERIC_UNAUTHORIZED_JSON: Final = json.dumps({"error": "unauthorized"}, indent=2) + "\n"

# The single generic verdict for every failed probe (disallowed address OR empty/unreachable).
UNREACHABLE_VERDICT: Final = "unreachable"
COMPLETED_VERDICT: Final = "completed"
