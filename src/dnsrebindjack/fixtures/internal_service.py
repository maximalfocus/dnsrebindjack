"""Internal-only service on a blocked-range address, reachable only inside the demo network.

Serves a distinctly fictional internal-only payload (carrying an obvious ``INTERNAL-ONLY … DEMO``
marker) and exposes an inbound signal — a contact counter — so tests and the walkthrough can see,
from the internal service's OWN side, whether a probe ever reached it. ``/healthz`` and the signal
endpoints are excluded from the counter; every other request counts as a contact.
"""

from __future__ import annotations

import threading
from typing import Final

from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from dnsrebindjack.fixtures import data

app = FastAPI(title="dnsrebindjack internal-only service", redirect_slashes=False)

_lock: Final = threading.Lock()
_contacts: list[str] = []


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/_signal")
def signal() -> JSONResponse:
    """The inbound signal: how many times this service has been contacted, and by which paths."""
    with _lock:
        return JSONResponse({"contacts": len(_contacts), "paths": list(_contacts)})


@app.post("/_signal/reset", response_class=PlainTextResponse)
def signal_reset() -> str:
    with _lock:
        _contacts.clear()
    return "reset"


@app.get("/{path:path}")
def internal(path: str) -> Response:
    with _lock:
        _contacts.append("/" + path)
    print(f"[internal-service] CONTACTED path=/{path}", flush=True)
    return Response(content=data.INTERNAL_PAYLOAD, media_type="application/json")
