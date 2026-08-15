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

## What it shows

A fictional webhook-integrations product performs a server-side reachability **probe** — a `GET`
to a tenant-registered URL. A demo-owned **controllable authoritative resolver** answers the
attacker's name with an *allowed* public address on the validation lookup and an *internal*
blocked address on the connect-time lookup. The completed walkthrough (later slices) contrasts a
**vulnerable**, a **half-fixed**, and a **secure** variant to teach the one fix that works:
*resolve once, validate that single address, connect to that exact pinned address, and never
re-resolve.*

## Verification boundary

The host needs only Docker. One command builds the image, brings up the hermetic in-network
topology, and runs the full `ruff` + `mypy` + `pytest` gate inside a container:

```sh
bash scripts/verify.sh
```

This repository is being built issue-by-issue; this README is expanded into a full walkthrough in
a later slice.
