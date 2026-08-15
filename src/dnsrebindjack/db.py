"""Engine, session, and deterministic tenant seeding."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from dnsrebindjack.config import SEED_TENANTS
from dnsrebindjack.models import Base, Tenant


def make_engine(url: str = "sqlite+pysqlite:///:memory:") -> Engine:
    # Sync FastAPI endpoints run in a threadpool, so a file-backed SQLite connection may be used
    # across threads; disable SQLite's same-thread guard for that case.
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, future=True, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, future=True, expire_on_commit=False)


def seed_tenants(session: Session) -> None:
    """Insert the fixed fictional tenants if they are not already present (idempotent)."""
    for tenant in SEED_TENANTS:
        if session.get(Tenant, tenant["id"]) is None:
            session.add(Tenant(id=tenant["id"], name=tenant["name"], token=tenant["token"]))
    session.flush()
