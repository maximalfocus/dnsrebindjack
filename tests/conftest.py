from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy.orm import Session

from tests.helpers import fresh_session


@pytest.fixture
def session() -> Iterator[Session]:
    s = fresh_session()
    try:
        yield s
    finally:
        s.close()
