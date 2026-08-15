"""Secure-by-default webhook-integrations application."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import func, select

from dnsrebindjack.app.audit import emit_probe_event, recent_events
from dnsrebindjack.app.auth import CurrentTenant, Unauthorized
from dnsrebindjack.app.constants import GENERIC_UNAUTHORIZED_JSON
from dnsrebindjack.app.deps import SessionDep
from dnsrebindjack.app.fetch import FetchResult, secure_fetch
from dnsrebindjack.app.schemas import AuditView, ProbeView, TargetCreate, TargetView
from dnsrebindjack.db import make_engine, make_sessionmaker, seed_tenants
from dnsrebindjack.models import WebhookTarget
from dnsrebindjack.probes import append_probe

_TARGET_NAMESPACE = uuid.UUID("d3a5e700-0000-4000-8000-000000000000")


def _selected_fetcher() -> Callable[[str], FetchResult]:
    variant = os.environ.get("APP_VARIANT", "secure")
    if variant == "secure":
        return secure_fetch
    if variant == "vulnerable":
        if os.environ.get("ALLOW_VULNERABLE_DEMO") != "true":
            raise RuntimeError(
                "vulnerable variant requires the vulnerable Compose profile and "
                "ALLOW_VULNERABLE_DEMO=true"
            )
        from dnsrebindjack.app.vulnerable import vulnerable_fetch

        return vulnerable_fetch
    if variant == "half-fixed":
        if os.environ.get("ALLOW_VULNERABLE_DEMO") != "true":
            raise RuntimeError(
                "half-fixed variant requires the half-fixed Compose profile and "
                "ALLOW_VULNERABLE_DEMO=true"
            )
        from dnsrebindjack.app.halffixed import half_fixed_fetch

        return half_fixed_fetch
    raise RuntimeError(f"unsupported APP_VARIANT: {variant}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    fetcher = _selected_fetcher()
    database_url = os.environ.get("DATABASE_URL", "sqlite+pysqlite:////tmp/dnsrebindjack.db")
    engine = make_engine(database_url)
    sessionmaker = make_sessionmaker(engine)
    with sessionmaker() as session:
        seed_tenants(session)
        session.commit()
    app.state.sessionmaker = sessionmaker
    app.state.fetcher = fetcher
    try:
        yield
    finally:
        engine.dispose()


app = FastAPI(title="dnsrebindjack secure app", lifespan=lifespan, redirect_slashes=False)


@app.exception_handler(Unauthorized)
def unauthorized_handler(request: Request, exc: Unauthorized) -> Response:
    del request, exc
    return Response(
        content=GENERIC_UNAUTHORIZED_JSON,
        status_code=status.HTTP_401_UNAUTHORIZED,
        media_type="application/json",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.post("/targets", response_model=TargetView, status_code=status.HTTP_201_CREATED)
def create_target(payload: TargetCreate, tenant: CurrentTenant, session: SessionDep) -> TargetView:
    index = session.scalar(
        select(func.count()).select_from(WebhookTarget).where(WebhookTarget.tenant_id == tenant.id)
    )
    target = WebhookTarget(
        id=str(uuid.uuid5(_TARGET_NAMESPACE, f"{tenant.id}:{index or 0}")),
        tenant_id=tenant.id,
        name=payload.name,
        url=payload.url,
    )
    session.add(target)
    session.commit()
    return TargetView(id=target.id, name=target.name, url=target.url)


@app.post("/targets/{target_id}/probe", response_model=ProbeView)
def probe_target(
    target_id: str, request: Request, tenant: CurrentTenant, session: SessionDep
) -> ProbeView:
    target = session.scalar(
        select(WebhookTarget).where(
            WebhookTarget.id == target_id, WebhookTarget.tenant_id == tenant.id
        )
    )
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="target not found")

    fetcher = request.app.state.fetcher
    result: FetchResult = fetcher(target.url)
    record = append_probe(
        session,
        tenant=tenant,
        target_url=target.url,
        verdict=result.verdict,
        validated_ip=result.validated_ip,
        connected_ip=result.connected_ip,
        http_status=result.http_status,
        body=result.body,
    )
    session.commit()
    emit_probe_event(
        tenant_name=tenant.name,
        target_host=urlsplit(target.url).hostname or "invalid.example",
        verdict=result.verdict,
        validated_ip=result.validated_ip,
        connected_ip=result.connected_ip,
        http_status=result.http_status,
        rejection_class=result.rejection_class,
        guard=result.guard,
    )
    return ProbeView(
        id=record.id,
        target_url=target.url,
        verdict=result.verdict,
        http_status=result.http_status,
        body=result.body,
    )


@app.get("/audit", response_model=AuditView)
def audit(tenant: CurrentTenant) -> AuditView:
    return AuditView(events=[event for event in recent_events() if event["tenant"] == tenant.name])
