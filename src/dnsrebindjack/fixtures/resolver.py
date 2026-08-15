"""Demo-owned controllable authoritative resolver — the "new form" this demo introduces.

A small, purpose-built DNS responder that the application is configured to use as its ONLY
resolver. It makes DNS rebinding legible and testable: the answer for the attacker-controlled name
FLIPS across lookups — an allowed public-range address on the first (validation) lookup, an
internal blocked-range address on every subsequent (connect-time) lookup — while the legitimate
name is stable. Every query and its answer are recorded and readable over a small control HTTP
API, so the two-different-answers behaviour is observable; per-episode state is resettable so each
scenario starts from fresh state.

Hermetic by construction: only the two fictional demo names resolve. Every other name returns
NXDOMAIN; there is no recursion and no upstream, so there is no real DNS.
"""

from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

from dnslib import QTYPE, RCODE, RR, A
from dnslib.server import BaseResolver, DNSServer
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse

from dnsrebindjack.fixtures import data

# Zero TTL for the attacker name so a resolver-side flip is never masked by client caching; a
# short TTL for the stable legitimate name.
ATTACKER_TTL: Final = 0
STABLE_TTL: Final = 30

# The attacker name's A-answer sequence, indexed by how many A queries preceded this one: the
# first answer is allowed (it passes the egress check), every later answer is the internal
# address (the rebind).
ATTACKER_SEQUENCE: Final = (data.ALLOWED_FIRST_IP, data.INTERNAL_IP)


def attacker_answer(a_query_count: int) -> str:
    """The attacker name's A answer given how many A queries preceded this one."""
    index = min(a_query_count, len(ATTACKER_SEQUENCE) - 1)
    return ATTACKER_SEQUENCE[index]


def _normalize(name: str) -> str:
    return name.rstrip(".").lower()


class ResolverState:
    """Thread-safe flip counter and an observable query log."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._attacker_a_count = 0
        self._log: list[dict[str, object]] = []

    def is_known(self, name: str) -> bool:
        return _normalize(name) in (data.ATTACKER_NAME, data.LEGIT_NAME)

    def answer_for(self, name: str, *, is_a_query: bool) -> str | None:
        """Return the A address for ``name``, advancing the flip for the attacker name.

        Only A queries advance the flip; AAAA and other query types never do, and names we do not
        serve always return ``None``.
        """
        key = _normalize(name)
        if key == data.ATTACKER_NAME:
            if not is_a_query:
                return None
            with self._lock:
                count = self._attacker_a_count
                self._attacker_a_count += 1
            return attacker_answer(count)
        if key == data.LEGIT_NAME:
            return data.UPSTREAM_IP if is_a_query else None
        return None

    def record(self, *, name: str, qtype: str, answer: str | None) -> None:
        key = _normalize(name)
        with self._lock:
            seq = len(self._log)
            self._log.append({"seq": seq, "name": key, "qtype": qtype, "answer": answer})
        # Also emit to the container log so the flip is legible without the control API.
        print(f"[resolver] q#{seq} {qtype} {key} -> {answer}", flush=True)

    def log(self) -> list[dict[str, object]]:
        with self._lock:
            return [dict(entry) for entry in self._log]

    def reset(self) -> None:
        with self._lock:
            self._attacker_a_count = 0
            self._log.clear()


class FlipResolver(BaseResolver):
    """Answers A/AAAA for the two demo names; NXDOMAIN for everything else."""

    def __init__(self, state: ResolverState) -> None:
        self.state = state

    def resolve(self, request: Any, handler: Any) -> Any:
        reply = request.reply()
        qname = str(request.q.qname)
        qtype_name = QTYPE[request.q.qtype]
        is_a = request.q.qtype == QTYPE.A
        answer: str | None = None
        if self.state.is_known(qname):
            answer = self.state.answer_for(qname, is_a_query=is_a)
            if answer is not None:
                ttl = ATTACKER_TTL if _normalize(qname) == data.ATTACKER_NAME else STABLE_TTL
                reply.add_answer(
                    RR(rname=request.q.qname, rtype=QTYPE.A, rclass=1, ttl=ttl, rdata=A(answer))
                )
            # A known name with a non-A query (e.g. AAAA) gets an empty NOERROR: no IPv6 here.
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        self.state.record(name=qname, qtype=qtype_name, answer=answer)
        return reply


STATE: Final = ResolverState()
_servers: list[Any] = []


def start_dns_servers(
    state: ResolverState, *, port: int = 53, address: str = "0.0.0.0"
) -> list[Any]:
    """Start UDP + TCP DNS servers for ``state`` in background threads and return them."""
    resolver = FlipResolver(state)
    servers = [
        DNSServer(resolver, port=port, address=address, tcp=False),
        DNSServer(resolver, port=port, address=address, tcp=True),
    ]
    for server in servers:
        server.start_thread()
    return servers


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    _servers.extend(start_dns_servers(STATE))
    try:
        yield
    finally:
        for server in _servers:
            server.stop()
        _servers.clear()


app = FastAPI(
    title="dnsrebindjack controllable resolver", lifespan=lifespan, redirect_slashes=False
)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/log")
def get_log() -> JSONResponse:
    """Return every DNS query the resolver has answered since the last reset (observability)."""
    return JSONResponse({"queries": STATE.log()})


@app.post("/reset", response_class=PlainTextResponse)
def reset() -> str:
    """Reset the flip counter and query log so the next scenario starts from fresh state."""
    STATE.reset()
    return "reset"
