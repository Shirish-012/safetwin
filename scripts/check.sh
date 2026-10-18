#!/usr/bin/env bash
# Run every local check, in the order CI runs them, and stop at the first one that fails.
#
#   scripts/check.sh                  the checks
#   scripts/check.sh --python-only    the same checks (kept for CI and habit: every check is a Python check)
#   scripts/check.sh --perf           also run the performance checks, last (they are slow)
#   scripts/check.sh --help           print these notes
#
# --perf can be added to either. The script works from any directory: it moves to the repository root first.
#
# The checks, in this order (they need .venv: run scripts/bootstrap.sh first):
#   ruff check .
#   ruff format --check .
#   mypy src
#   python -m safetwin.spec.schema --check       (the committed JSON Schema is current)
#   pytest -q
# Performance checks (--perf):
#   pytest -q -m perf -s                         (a plain pytest run leaves out the tests marked perf)
# If no test is marked perf, pytest exits with 5 and so does this script: an empty gate is not a pass.
#
# Each step prints a header first. When a step fails the script stops and its last line names the step.
# Exit status: 0 when every check passed; the failing tool's own status (1 for most) when a check failed;
# 2 for a bad option, or when .venv is missing.
#
# CI (.github/workflows/ci.yml) runs this script. Job "python" is --python-only, and job "perf" (started by
# hand only) is --python-only --perf.

set -euo pipefail

# Start from the repository root, wherever the script was called from. CDPATH is cleared so that `cd` can
# neither be redirected nor print a path when the caller has it set.
script_dir="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
script="$script_dir/$(basename -- "$0")"
cd "$script_dir/.."

die() {
    echo "check.sh: $*" >&2
    exit 2
}

usage() {
    # The notes at the top of this file: everything from line 2 up to the first line that is not a comment.
    awk 'NR > 1 { if (!/^#/) exit; sub(/^# ?/, ""); print }' "$script"
}

run_perf=0
for arg in "$@"; do
    case "$arg" in
        --python-only) ;;
        --perf) run_perf=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) die "unknown option: $arg (see --help)" ;;
    esac
done

# Fail before the first step, not in the middle of a long run, when a tool is missing.
if [ ! -x .venv/bin/python ]; then
    die ".venv not found: run scripts/bootstrap.sh first"
fi

# The step that is running now. The EXIT trap names it when the script ends with an error.
current_step=""

on_exit() {
    local status=$?
    if [ "$status" -ne 0 ] && [ -n "$current_step" ]; then
        printf '\ncheck.sh: FAILED in step "%s" (exit status %s)\n' "$current_step" "$status" >&2
    fi
}
trap on_exit EXIT

# step TITLE COMMAND [ARGUMENT...]: print a header, then run the command. If it fails, set -e stops the script.
step() {
    current_step="$1"
    shift
    printf '\n==> %s\n    $ %s\n' "$current_step" "$*"
    "$@"
}

step "ruff check" .venv/bin/ruff check .
step "ruff format --check" .venv/bin/ruff format --check .
step "mypy" .venv/bin/mypy src
step "the committed JSON Schema is current" .venv/bin/python -m safetwin.spec.schema --check
step "pytest" .venv/bin/pytest -q

if [ "$run_perf" -eq 1 ]; then
    step "perf: tests marked perf" .venv/bin/pytest -q -m perf -s
fi

printf '\nAll checks passed.\n'
