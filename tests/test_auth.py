from __future__ import annotations

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from dnsrebindjack.auth import (
    GENERIC_401_DETAIL,
    authenticate,
    require_tenant,
    token_from_header,
)
from dnsrebindjack.config import SEED_TENANTS
from tests.helpers import get_tenant


def test_authenticate_accepts_seed_token(session: Session) -> None:
    tenant = get_tenant(session, 0)
    assert authenticate(session, SEED_TENANTS[0]["token"]) is tenant


def test_authenticate_rejects_unknown_missing_and_empty(session: Session) -> None:
    assert authenticate(session, "nope") is None
    assert authenticate(session, None) is None
    assert authenticate(session, "") is None


def test_require_tenant_raises_generic_401(session: Session) -> None:
    with pytest.raises(HTTPException) as excinfo:
        require_tenant(session, "wrong-token")
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == GENERIC_401_DETAIL


def test_generic_401_detail_leaks_no_token() -> None:
    lowered = GENERIC_401_DETAIL.lower()
    for token in SEED_TENANTS:
        assert token["token"].lower() not in lowered
    assert "token" not in lowered  # the message names nothing about credentials


def test_token_from_header_parses_bearer() -> None:
    assert token_from_header("Bearer abc123") == "abc123"
    assert token_from_header("bearer   spaced  ") == "spaced"


def test_token_from_header_rejects_other_schemes_and_blanks() -> None:
    assert token_from_header(None) is None
    assert token_from_header("") is None
    assert token_from_header("Basic abc") is None
    assert token_from_header("Bearer ") is None
