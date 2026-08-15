"""Demo authentication for the fictional webhook-integrations product.

Demo-only tenant credentials. Any authentication failure yields one uniform, generic ``401`` that
reveals nothing about which part failed. Tokens are never written to logs, audit events, or probe
records; this module never logs the token it receives.
"""

from __future__ import annotations

from typing import Final

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from dnsrebindjack.models import Tenant

# One generic message for every failure mode (missing, malformed, or unknown token).
GENERIC_401_DETAIL: Final = "authentication required"


def token_from_header(authorization: str | None) -> str | None:
    """Extract a bearer token from an ``Authorization`` header value, or ``None``."""
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = value.strip()
    return token or None


def authenticate(session: Session, token: str | None) -> Tenant | None:
    """Return the tenant owning ``token``, or ``None`` if the token is missing/unknown."""
    if not token:
        return None
    return session.scalars(select(Tenant).where(Tenant.token == token)).first()


def require_tenant(session: Session, token: str | None) -> Tenant:
    """Return the authenticated tenant or raise a uniform generic ``401``."""
    tenant = authenticate(session, token)
    if tenant is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=GENERIC_401_DETAIL)
    return tenant
