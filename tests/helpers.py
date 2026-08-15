from __future__ import annotations

from sqlalchemy.orm import Session

from dnsrebindjack.config import SEED_TENANTS
from dnsrebindjack.db import make_engine, make_sessionmaker, seed_tenants
from dnsrebindjack.models import Tenant


def fresh_session() -> Session:
    """A session over a brand-new in-memory database seeded with the fixed tenants."""
    engine = make_engine()
    session = make_sessionmaker(engine)()
    seed_tenants(session)
    session.commit()
    return session


def get_tenant(session: Session, index: int) -> Tenant:
    tenant = session.get(Tenant, SEED_TENANTS[index]["id"])
    assert tenant is not None
    return tenant
