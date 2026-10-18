#!/usr/bin/env bash
# Set up the dev environment. Safe to run again: it only creates .venv when missing.
#   PYTHON=/path/to/python3.12 scripts/bootstrap.sh    # to use a different interpreter
set -euo pipefail

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-/opt/homebrew/bin/python3.12}"

if [ ! -x .venv/bin/python ]; then
    "$PYTHON" -m venv .venv
fi

.venv/bin/python -m pip install --quiet -e . -r requirements-dev.txt

echo "ready: source .venv/bin/activate"
