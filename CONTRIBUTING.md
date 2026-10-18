# Contributing to safetwin

safetwin 1.0.0 is the final release and isn't actively developed, so pull requests may not be reviewed.
You're welcome to fork it under the MIT license; the rules below are what kept it safe, and are worth
keeping in a fork. safetwin handles other people's personal data, so a few rules matter more here than in
most projects. They are short.

## Set up

```bash
scripts/bootstrap.sh            # .venv with the package (editable), the CLI and the dev tools
scripts/check.sh                # ruff, ruff format, mypy (strict), the JSON Schema, pytest
scripts/check.sh --perf         # also the performance gates (slow)
scripts/smoke.sh                # the README's quickstart, from a fresh install of the wheel
```

You need Python 3.12 and macOS or Linux. CI runs the same scripts (`.github/workflows/ci.yml`).

## The rules

1. **No data value leaves the data.** Messages, logs, exceptions, reports, comments in generated code and
   test output name tables, columns, methods and counts, never a value. A library error can quote a value,
   so the CLI shows only its type. The leak tests (`tests/leak/`) plant a canary value and look for it
   everywhere afterwards; a change that touches what is written or printed needs a leak test.
2. **No key leaves its reference.** The key is read from `env://` or `file://` when a run starts and lives
   in memory only. Never log it, put it in a repr, a pipeline, a report or an exported script.
3. **The engine and the exported script compute the same bytes.** What they must agree on lives in
   `src/safetwin/masking/portable.py`, which the exporter copies word for word. A change to a method goes
   there, and `tests/masking/test_export.py` must stay green. Changing the canonical bytes of a type changes
   every pseudonym made from it: that is a new derivation version, not a fix. `tests/masking/test_golden.py`
   pins the outputs; never edit its values to make a change pass ([Stability](docs/security.md#stability)).
4. **Measured claims only.** A number goes into the README or the docs only when a test in the repository
   produces it, and the README names the test.
5. **Every column named.** Nothing may copy a column the policy doesn't name.

## Making a change

- Open an issue first for anything bigger than a fix, so we can agree on the approach.
- Keep a change small and focused, with tests: unit tests next to the code's area under `tests/`, and a
  property test (Hypothesis) for anything that holds for all inputs.
- Update the docs in `docs/` in the same change when behavior changes. Write them in plain English, short
  sentences, no marketing words.
- `scripts/check.sh` must pass. CI also builds the package, runs the quickstart, the container image and
  the GitHub Action.
- Commit messages: a short summary line, then what changed and why.

## Reporting bugs

Use the bug report form. **Never paste real data, sample values or keys** into an issue: describe the
column types and shapes instead, or make a small made-up file that shows the problem (`safetwin demo` writes
one you can start from). Security problems go through [SECURITY.md](SECURITY.md), not the issue tracker.

By contributing you agree that your contributions are licensed under the [MIT](LICENSE) license.
