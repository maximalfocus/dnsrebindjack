#!/usr/bin/env sh
# In-container verification gate: static checks then the test suite.
# Invoked by the `verify` compose service (which depends on the fixtures being healthy and
# uses the demo resolver as its only DNS).
set -e

echo "== ruff check =="
ruff check .

echo "== ruff format --check =="
ruff format --check .

echo "== mypy =="
mypy

echo "== pytest =="
pytest

echo "== gate passed =="
