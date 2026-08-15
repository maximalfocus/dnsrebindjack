# dnsrebindjack

A small, **container-only, wholly-simulated** educational demo of **DNS rebinding** — a
time-of-check to time-of-use (TOCTOU, [CWE-367](https://cwe.mitre.org/data/definitions/367.html))
gap in hostname→IP resolution that defeats a Server-Side Request Forgery egress control
([CWE-918](https://cwe.mitre.org/data/definitions/918.html), OWASP A10:2021 / API7:2023). The
address a security check approves and the address the connection actually reaches are two
different resolutions of the same name, and the attacker controls what changes in between.

> **Local-only educational material.** This project ships **no working exploit**, contacts **no
> real system**, uses **no real DNS**, and performs **no network access outside its own internal
> container network**. Every user, tenant, token, hostname, and address is fictional and drawn
> from reserved documentation ranges (RFC 2606 `.example`, RFC 5737 `203.0.113.0/24`,
> RFC 1918 private space). The intentionally-vulnerable variants are gated behind two deliberate
> opt-in actions and are never the default.

## What this demo teaches

You watch a hostname pass a correct-looking server-side security check and then, on the very next
lookup, resolve somewhere the check was supposed to block — and you see both why the obvious
defense fails and the one fix that works. No source reading required: the demo's own HTTP API,
audit log, and the internal service's inbound signal show you everything.

1. **DNS rebinding is a TOCTOU flaw.** The danger is not any single DNS answer but the *gap*
   between the answer a security check saw and the answer the connection actually used.
2. **Validating the resolved IP is not enough** if the code then lets the HTTP client resolve the
   name again at connect time. More checks and caching don't close the gap while a second
   resolution remains.
3. **The fix is resolution pinning:** resolve once, validate that single address, and connect to
   that exact pinned address — never consult the name a second time.

## The scenario

A fictional webhook-integrations product lets an authenticated tenant register an outbound
webhook URL. The server performs a **reachability probe** — a server-side `GET` to the registered
URL — to confirm the endpoint is live. Everything runs on an internal, egress-less container
network, and the app resolves names **only** through the demo's own controllable authoritative
resolver.

Two destinations exist:

| Name | DNS behaviour | Address | Role |
|---|---|---|---|
| `hooks.partner.example` | stable | `203.0.113.20` (allowed) | legitimate partner endpoint |
| `probe.attacker.example` | **flips** | `203.0.113.10` → `10.10.0.9` | attacker-controlled endpoint |

The attacker's name answers with an **allowed** public-range address (`203.0.113.10`) on the
first (validation) lookup, and with an **internal** blocked-range address (`10.10.0.9`) on every
later (connect-time) lookup. The egress policy under test rejects loopback, link-local, and
private addresses and allows the public documentation range. `10.10.0.9` is the **internal-only
service**: reachable only inside the demo network, never published to the host, serving a
synthetic internal fleet-config document that carries an obvious `INTERNAL-ONLY` marker.

## Terminology

- **DNS rebinding** — an attack in which a hostname resolves to different addresses across
  lookups, so a name that passed a security check points somewhere else when the connection is
  actually opened.
- **TOCTOU (time-of-check to time-of-use, CWE-367)** — the class of flaw where the state checked
  and the state used differ. Here the check validates one resolution; the connection uses another.
- **SSRF egress control (CWE-918)** — the server-side defense that decides which destinations a
  fetch may reach. This demo's control validates each resolved address against an allow/block
  policy (reject loopback, link-local, private; allow the public documentation range).
- **Resolution pinning** — resolving a hostname exactly once, validating that single address, and
  connecting to that exact address while preserving the original `Host` header/SNI. The name is
  never consulted a second time.
- **TTL (time to live)** — how long a DNS answer may be cached. A short/zero TTL means the flip
  can happen between two lookups with no caching masking it.

## Requirements

- **Docker** (with Docker Compose v2+). Nothing else — no Python, no dependencies, no network
  access: every language, dependency, test, and linter runs inside containers on the demo's own
  internal network.

## One command: run the whole comparison

```sh
bash scripts/demo.sh
```

This builds the image, brings up **all three variants** against fresh state, runs the
deterministic three-variant comparison, tears everything down, and reports elapsed time. It
completes in well under five minutes. The per-variant verdicts (egress check result, both DNS
answers observed, where the fetch landed, whether internal content was disclosed) look like this:

```
[secure] attacker probe: probe.attacker.example
  egress check : 203.0.113.10 (allowed)
  dns answers  : 203.0.113.10
  landed on    : (none)
  internal     : not contacted
  disclosure   : no

[vulnerable] attacker probe: probe.attacker.example
  egress check : 203.0.113.10 (allowed)
  dns answers  : 203.0.113.10 -> 10.10.0.9
  landed on    : 10.10.0.9
  internal     : contacted (1)
  disclosure   : YES - INTERNAL-ONLY returned

[half-fixed] attacker probe: probe.attacker.example
  egress check : 203.0.113.10 (allowed)
  dns answers  : 203.0.113.10 -> 10.10.0.9
  landed on    : 10.10.0.9
  internal     : contacted (1)
  disclosure   : YES - INTERNAL-ONLY returned
```

…and the legitimate `hooks.partner.example` probe succeeds on every variant. The comparison
exits non-zero if any expected outcome is not observed.

## Variant by variant

All commands below assume you are in the repository root. Every variant's app port is
**loopback-only** (`127.0.0.1`). The demo tenant is `acme-widgets` with the conspicuously
fictional token `demo-token-acme-FICTIONAL`.

### 1. Secure variant (default) — pin the vetted address

The secure service is the unprofiled default. Start it and probe the attacker name:

```sh
docker compose up -d secure

# register the attacker-controlled target
curl -s -X POST http://127.0.0.1:8080/targets \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL" \
  -H "Content-Type: application/json" \
  -d '{"name":"attacker","url":"http://probe.attacker.example/internal/fleet-config"}'
```

The response includes the target `id`; probe it:

```sh
curl -s -X POST http://127.0.0.1:8080/targets/<id>/probe \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL"
```

**Expected outcome:** the app resolves the name once → `203.0.113.10` → the egress check passes →
the app connects to **that exact pinned address** and never re-resolves. The probe returns the
generic `unreachable` result (nothing actually serves `203.0.113.10`), the internal service's
inbound signal stays at **zero contacts**, and the audit event records the validated address with
no internal content and no token:

```sh
curl -s http://127.0.0.1:8080/audit -H "Authorization: Bearer demo-token-acme-FICTIONAL"
```

Tear down when done: `docker compose down --volumes`.
### 2. Vulnerable variant — check, then fetch by hostname

This is the `credjack`-style control applied the obvious way: resolve → validate the address →
then hand the **hostname** to the HTTP client, which resolves it again at connect time. It is
never the default — starting it requires **two deliberate actions**: the dedicated Compose
profile **and** `ALLOW_VULNERABLE_DEMO=true` (either alone is insufficient; the app fails closed
on startup).

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable up -d vulnerable

curl -s -X POST http://127.0.0.1:8081/targets \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL" \
  -H "Content-Type: application/json" \
  -d '{"name":"attacker","url":"http://probe.attacker.example/internal/fleet-config"}'

curl -s -X POST http://127.0.0.1:8081/targets/<id>/probe \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL"
```

**Expected outcome:** the egress check passes on the first answer (`203.0.113.10`, allowed), then
the HTTP client's connect-time resolution gets the flipped record (`10.10.0.9`) — the probe lands
on the internal service and **returns the `INTERNAL-ONLY` marker**. The resolver log shows the
two different answers; the internal service's inbound signal counts **one contact**.

Tear down: `docker compose --profile vulnerable down --volumes`.

### 3. Half-fixed variant — a guard that still fails

A plausible anti-rebinding patch: cache the first answer for the request's duration and
**re-validate it immediately before connecting** (the guard, recorded as `cached-recheck` in the
audit event) — but still let the HTTP client resolve the name when it opens the socket. The guard
re-checks the *same already-approved* address, so it adds no protection; the flip still wins at
connect time. Same two opt-in actions required:

```sh
ALLOW_VULNERABLE_DEMO=true docker compose --profile half-fixed up -d half-fixed

curl -s -X POST http://127.0.0.1:8082/targets \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL" \
  -H "Content-Type: application/json" \
  -d '{"name":"attacker","url":"http://probe.attacker.example/internal/fleet-config"}'

curl -s -X POST http://127.0.0.1:8082/targets/<id>/probe \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL"
```

**Expected outcome:** identical to the vulnerable variant — the `INTERNAL-ONLY` marker is still
disclosed — but the audit event visibly shows the extra guard:

```sh
curl -s http://127.0.0.1:8082/audit -H "Authorization: Bearer demo-token-acme-FICTIONAL"
```

```json
{ "...": "...", "validated_ip": "203.0.113.10", "connected_ip": "10.10.0.9",
  "guard": "cached-recheck", "...": "..." }
```

Tear down: `docker compose --profile half-fixed down --volumes`.

### 4. Legitimate path — pinning does not break normal use

On every variant, the legitimate partner probe succeeds:

```sh
curl -s -X POST http://127.0.0.1:8080/targets \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL" \
  -H "Content-Type: application/json" \
  -d '{"name":"partner","url":"http://hooks.partner.example/deliver"}'

curl -s -X POST http://127.0.0.1:8080/targets/<id>/probe \
  -H "Authorization: Bearer demo-token-acme-FICTIONAL"
```

`hooks.partner.example` resolves once to `203.0.113.20`, passes the egress check, and the pinned
fetch returns the benign partner payload (`{"status": "ok", ...}`). The same works on the
vulnerable and half-fixed variants (`:8081` / `:8082`).

## The lesson

**Pin the vetted address; do not re-resolve; more checks are not the fix.**

- Resolve the hostname **once**, validate **that single address**, and connect to **that exact
  address**, preserving the original `Host` header/SNI. The name is never consulted a second time,
  so the flipped record is harmless.
- A second check does not help if it re-validates an address the connection will not use. The
  half-fixed variant's guard re-checks the cached first answer — the same address the egress
  check already approved — and then lets the HTTP client resolve the name again when it opens the
  socket. That connect-time resolution is the one the guard never pinned, and it is the one that
  matters.
- Caching the first answer does not help either: it only makes the guard's re-check faster, and
  the connection still performs its own fresh resolution.
- The generic, oracle-free failure result is deliberate: the caller cannot distinguish "blocked"
  from "unreachable", so a blocked probe leaks nothing about the internal network.

## How this demo stays safe

- **Hermetic network.** Everything runs on internal Docker networks with no route to the real
  internet; the verification suite asserts there is no public egress and no real DNS.
- **No real DNS.** The app resolves names only through the demo's own authoritative resolver;
  unknown names return `NXDOMAIN`.
- **Two-action opt-in gating.** The vulnerable and half-fixed variants start only with the
  dedicated Compose profile **and** `ALLOW_VULNERABLE_DEMO=true`; the secure variant is the
  default; app ports are loopback-only; the resolver, internal service, and upstream are never
  published to the host.
- **Wholly fictional data.** Tenants, tokens, hostnames, and addresses come from reserved
  documentation ranges; the internal payload declares its fictional nature in its own contents.
- **No working exploit.** Nothing here can be pointed at a real system: there is no real network
  path and no real DNS to consult.

## Verification

The host needs only Docker. One command builds the image, brings up the hermetic in-network
topology, and runs the full `ruff` + `mypy` + `pytest` gate — including the real-boundary
per-variant checks, the opt-in startup gates, and the scripted comparison — inside containers:

```sh
bash scripts/verify.sh
```
