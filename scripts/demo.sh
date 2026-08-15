#!/usr/bin/env bash
# The single host command for the walkthrough (FR-014): build the image, bring up all three
# variants against fresh state on the internal egress-less network, run the deterministic
# three-variant comparison (FR-012), tear down, and report elapsed time. The host needs only
# Docker; every language, dependency, test, and linter runs inside containers.
#
# The two deliberate opt-in actions are supplied here explicitly: the vulnerable and half-fixed
# services are profile-gated AND receive ALLOW_VULNERABLE_DEMO=true for this command only.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose build

cleanup() {
  docker compose --profile demo --profile vulnerable --profile half-fixed down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

start=$(date +%s)
ALLOW_VULNERABLE_DEMO=true docker compose --profile demo --profile vulnerable --profile half-fixed run --rm runner
elapsed=$(( $(date +%s) - start ))
echo "demo comparison completed in ${elapsed}s"
