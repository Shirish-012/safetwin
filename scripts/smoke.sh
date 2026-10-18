#!/usr/bin/env bash
# The README's quickstart, from a fresh install: build the wheel, install it into a new virtual environment in
# a temporary folder, then run the commands of the quickstart block of README.md there (between the
# `quickstart:start` and `quickstart:end` markers), and say how long it all took.
#
#   scripts/smoke.sh                  needs the network for the dependencies (or a warm pip cache)
#   PYTHON=python3.13 scripts/smoke.sh
#
# The install line of the block (pip, pipx or uv tool install) is skipped: the wheel built here stands in
# for it. Every other line runs as written, in one bash with `set -euo pipefail`, so the README can't drift
# from what works. CI runs this script (.github/workflows/ci.yml, job "package").

set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
cd "$script_dir/.."

PYTHON="${PYTHON:-python3.12}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
started=$(date +%s)

# The block, without its fences and its install line. awk does it all: grep would fail on an empty block.
quickstart="$(awk '/<!-- quickstart:start -->/ { inside = 1; next }
    /<!-- quickstart:end -->/ { inside = 0 }
    inside && !/^```/ && !/^(pip|pipx|uv tool) install / { print }' README.md)"
if [ -z "$quickstart" ]; then
    echo "smoke.sh: README.md has no quickstart block" >&2
    exit 2
fi

echo "==> build the wheel"
"$PYTHON" -m pip wheel --quiet --no-deps --wheel-dir "$work/dist" .
echo "==> install it into a new virtual environment"
"$PYTHON" -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --quiet --disable-pip-version-check "$work"/dist/safetwin-*.whl
installed=$(date +%s)

echo "==> the quickstart of README.md"
mkdir "$work/home"
(
    cd "$work/home"
    export PATH="$work/venv/bin:$PATH"
    unset SAFETWIN_KEY
    bash -euo pipefail -c "$quickstart"
)
finished=$(date +%s)
echo "smoke.sh: ok: install $((installed - started)) s, quickstart $((finished - installed)) s"
