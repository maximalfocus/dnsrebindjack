"""Public request and response shapes shared by every demo variant."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=2048)


class TargetView(BaseModel):
    id: str
    name: str
    url: str


class ProbeView(BaseModel):
    id: str
    target_url: str
    verdict: str
    http_status: int | None = None
    body: str | None = None


class AuditView(BaseModel):
    events: list[dict[str, object]]
