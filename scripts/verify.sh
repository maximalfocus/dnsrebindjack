#!/usr/bin/env bash
# The single documented host workflow: build the image, bring up the hermetic in-network
# fixture topology (the demo resolver, the internal-only service, and the benign upstream),
# run the full ruff + mypy + pytest gate inside a container that uses the demo resolver as its
# only DNS, then tear it down. The host needs only Docker + Docker Compose.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose build

cleanup() {
  docker compose --profile vulnerable --profile half-fixed down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

set +e
docker compose run --rm verify
rc=$?
set -e
[ "$rc" -eq 0 ] || exit "$rc"

docker compose down --volumes --remove-orphans

# Profile alone is insufficient: without the explicit acknowledgement the app must fail closed.
# The variable is pinned explicitly so a leaky parent environment can never satisfy the gate.
set +e
ALLOW_VULNERABLE_DEMO=false docker compose --profile vulnerable run --rm --no-deps vulnerable
gate_rc=$?
set -e
if [ "$gate_rc" -eq 0 ]; then
  echo "vulnerable service started without ALLOW_VULNERABLE_DEMO=true" >&2
  exit 1
fi

docker compose --profile vulnerable down --volumes --remove-orphans

# Environment acknowledgement alone is insufficient: without the vulnerable profile the
# service must not exist in the compose project at all. (docker compose run would auto-activate
# the named service's profile, so presence is asserted on the project definition instead.)
if docker compose config --services 2>/dev/null | grep -qx 'vulnerable'; then
  echo "vulnerable service is present without the vulnerable profile" >&2
  exit 1
fi

# With both deliberate actions, exercise the real vulnerable boundary.
ALLOW_VULNERABLE_DEMO=true docker compose --profile vulnerable run --rm verify-vulnerable

docker compose --profile vulnerable down --volumes --remove-orphans

# Half-fixed variant: same two opt-in actions, same fail-closed gates.
set +e
ALLOW_VULNERABLE_DEMO=false docker compose --profile half-fixed run --rm --no-deps half-fixed
gate_half_rc=$?
set -e
if [ "$gate_half_rc" -eq 0 ]; then
  echo "half-fixed service started without ALLOW_VULNERABLE_DEMO=true" >&2
  exit 1
fi

if docker compose config --services 2>/dev/null | grep -qx 'half-fixed'; then
  echo "half-fixed service is present without the half-fixed profile" >&2
  exit 1
fi

ALLOW_VULNERABLE_DEMO=true docker compose --profile half-fixed run --rm verify-half-fixed

cleanup
