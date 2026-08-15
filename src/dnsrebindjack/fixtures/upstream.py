"""Benign upstream fixture on an allowed documentation-range address.

This is the one legitimate probe target (``hooks.partner.example`` resolves here). It serves
deterministic, benign fictional content for any path.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse, Response

from dnsrebindjack.fixtures import data

app = FastAPI(title="dnsrebindjack benign upstream fixture", redirect_slashes=False)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/{path:path}")
def benign(path: str) -> Response:
    return Response(content=data.BENIGN_PAYLOAD, media_type="application/json")
