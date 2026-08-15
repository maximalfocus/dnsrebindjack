"""SQLAlchemy 2.0 models for the fictional webhook-integrations product.

A tenant registers webhook targets and the server records the result of each reachability probe.
The probe record captures the two addresses that make DNS rebinding legible: the address the
egress check *validated* and the address the connection actually *reached*.
"""

from __future__ import annotations

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    token: Mapped[str] = mapped_column(String(128), unique=True)

    targets: Mapped[list[WebhookTarget]] = relationship(
        back_populates="tenant", order_by="WebhookTarget.seq"
    )
    probes: Mapped[list[ProbeRecord]] = relationship(
        back_populates="tenant", order_by="ProbeRecord.seq"
    )


class WebhookTarget(Base):
    """A tenant-registered outbound webhook URL that the server can reachability-probe."""

    __tablename__ = "webhook_targets"

    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    name: Mapped[str] = mapped_column(String(128))
    url: Mapped[str] = mapped_column(Text)

    tenant: Mapped[Tenant] = relationship(back_populates="targets")


class ProbeRecord(Base):
    """An append-only record of one reachability probe and its outcome."""

    __tablename__ = "probe_records"

    # Internal monotonic ordering key (stable insertion order); not the public identity.
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Public identifier: a deterministic UUID string (see probes.append_probe).
    id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    target_url: Mapped[str] = mapped_column(Text)
    # Generic outcome verdict (e.g. completed / rejected / unreachable); never an oracle.
    verdict: Mapped[str] = mapped_column(String(32))
    # The address the egress check validated, and the address the connection actually reached.
    validated_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    connected_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    body_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="probes")
