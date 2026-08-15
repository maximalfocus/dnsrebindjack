"""Demo bearer authentication for the application entry points.

Static, unmistakably demo-only tenant tokens. Missing, malformed, and unknown credentials all
raise :class:`Unauthorized`, which the application renders as one generic ``401`` with the standard
bearer challenge and a byte-identical body. Tokens are never logged or stored.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy import select

from dnsrebindjack.auth import token_from_header
from dnsrebindjack.models import Tenant


class Unauthorized(Exception):
    """Raised for any authentication failure; rendered as a generic 401."""


def get_current_tenant(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Tenant:
    token = token_from_header(authorization)
    if token is None:
        raise Unauthorized()
    with request.app.state.sessionmaker() as session:
        tenant = session.scalar(select(Tenant).where(Tenant.token == token))
        if tenant is None:
            raise Unauthorized()
        # Return a detached identity so callers need no live session for the tenant's fields.
        return Tenant(id=tenant.id, name=tenant.name, token=tenant.token)


CurrentTenant = Annotated[Tenant, Depends(get_current_tenant)]
