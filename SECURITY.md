# Security policy

`dnsrebindjack` is **educational material**. It exists to teach one specific flaw — DNS rebinding, a
time-of-check to time-of-use gap in hostname resolution that defeats an SSRF egress control — by
letting you watch it happen and then watch the fix hold. Please read this before filing a report.

## The vulnerable behaviour is intentional

This repository deliberately ships insecure code. The following are **teaching artifacts, not
defects**, and reports about them will be closed as working-as-intended:

- **The `vulnerable` variant** (`src/dnsrebindjack/app/vulnerable.py`) — validates a resolved address
  and then fetches by hostname, so the HTTP client re-resolves at connect time and the flipped record
  wins. This bypass is the entire lesson.
- **The `half-fixed` variant** (`src/dnsrebindjack/app/halffixed.py`) — adds a plausible
  anti-rebinding guard that still fails. Demonstrating that "more checks" is not the fix is the point.
- **The controllable authoritative resolver** (`src/dnsrebindjack/fixtures/resolver.py`) — returns
  two different answers for the same name on purpose.
- **The internal-only fixture service and its `INTERNAL-ONLY` payload** — a synthetic target that
  exists to be reached in the failing variants. It is fictional and grants access to nothing.
- **Demo tenant tokens** such as `demo-token-acme-FICTIONAL` — invented placeholders, not credentials.

Both failing variants are **never the default** and cannot start without two deliberate actions: a
dedicated Docker Compose profile **and** `ALLOW_VULNERABLE_DEMO=true`. Either action alone fails
closed. The secure, resolution-pinning variant is the default service.

## Boundaries of this project

- **Local-only.** Everything runs on internal, egress-less Docker networks with no route to the real
  internet and no real DNS. The demo contacts no real system.
- **Not hosted.** There is no deployed instance, public endpoint, or demo site.
- **Not a published package or image.** Nothing here is distributed to PyPI, a container registry, or
  any other index.
- **Not for production.** No part of this code is intended for, or supported in, production use.
- **Wholly fictional data.** Every tenant, token, hostname, address, and payload is invented and drawn
  from reserved documentation ranges (RFC 2606 `.example`, RFC 5737 and RFC 3849 documentation
  addresses, RFC 1918 private space).

## Reporting a genuine vulnerability

An **unintended** vulnerability is one outside the list above — for example, a way to start a failing
variant without both opt-in actions, a way for the demo to reach a real host or perform real DNS or
network egress, a real credential or personal data committed to the repository, or a flaw in the
secure variant's pinning that is not part of the taught lesson.

Please report those **privately**, not in a public issue:

- Use GitHub's private vulnerability reporting on this repository:
  **Security → Report a vulnerability**
  (<https://github.com/maximalfocus/dnsrebindjack/security/advisories/new>).

Include what you observed, the commands or requests that produced it, and why you believe it is
outside the intentional teaching scope. Because this is an unfunded educational project with no
deployed surface, there is no formal SLA or bug-bounty; reports are reviewed on a best-effort basis
and credited in the advisory unless you prefer otherwise.

## Please do not

- Point any part of this project at a system you do not own. There is no real network path here, and
  adding one is outside the project's scope and its licence's warranty disclaimer.
- Report the intentional variants, the flipping resolver, or the fictional fixture data as
  vulnerabilities.
