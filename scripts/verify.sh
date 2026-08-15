#!/usr/bin/env bash
# The single documented host workflow: build the image, bring up the hermetic in-network
# fixture topology (the demo resolver, the internal-only service, and the benign upstream),
# run the full ruff + mypy + pytest gate inside a container that uses the demo resolver as its
# only DNS, then tear it down. The host needs only Docker + Docker Compose.
set -euo pipefail

cd "$(dirname "$0")/.."

docker compose build

set +e
docker compose run --rm verify
rc=$?
set -e

docker compose down --volumes --remove-orphans

exit "$rc"
