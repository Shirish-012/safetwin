# Internals

How safetwin is built and tested, and why it is the way it is. For contributors.

## Architecture

How safetwin is put together: what runs where, how a policy becomes a running job, and why the pieces
are split the way they are. The decisions behind it are in [decisions](internals.md#decisions).

### The big picture

```
           ┌──────────────────────── your machine (or a CI runner / container) ─────────────────────────┐
           │                                                                                              │
  you ──▶  │  safetwin CLI ──────────────── in-process ────────────────┐                                 │
           │   scan · mask · export · key · runs                         ▼                                 │
           │                                               ┌───────────────────────┐                      │
           │                                               │  policy compiler       │  masking.yaml →     │
           │                                               │  + data plane          │  pipeline → run     │
           │                                               │  (Polars · DuckDB ·    │                      │
  browser ─┼─▶ safetwin ui ─▶ engine (control API) ──────▶│   Arrow)               │ ──▶ safe twin       │
           │   127.0.0.1, token     │   stage workers ────▶└───────────────────────┘     + report        │
           │                        │   (one process per stage)                                          │
           │                        └──▶ run history (SQLite, optional)                                   │
           └──────────────────────────────────────────────────────────────────────────────────────────────┘
                     ▲ reads                                                              │ writes
              source: CSV / Parquet / Excel folder, or Postgres             target: the same, or a new Postgres schema
```

There are two ways to run a job, and both use the same data plane:

| Mode | Used by | How it runs |
|------|---------|-------------|
| **In-process** | `safetwin mask`, `safetwin scan`, CI, Docker, exported tasks | The CLI loads the policy, compiles it and runs every stage in its own process. No server, no background process. This is the main path |
| **Engine** | `safetwin ui` | A background engine serves the browser UI through a local API and runs each stage in a separate worker process, with live progress events |

### Components

#### Policy compiler
It reads `masking.yaml` ([The policy and its methods](guide.md#the-policy-and-its-methods)) and turns it into the internal **pipeline** format, a
small DAG of steps (source → masking steps → sink, one stage per table). It also:
- validates the policy: every column named, methods valid for the column's type, relationships
  between matching domains, a key reference present;
- derives per-method subkeys from the key ([Keys](security.md#keys));
- orders tables so a subset's parents are selected before their children ([Relationships and subsetting](guide.md#relationships-and-subsetting)).

The same compiled pipeline feeds the engine and the exporter, which keeps the exported code honest
([Export to a Polars script](guide.md#export-to-a-polars-script)).

#### Data plane
It runs a stage. It was built and measured before the 2026-10-03 reset, and is reused as it is:

- **Fused path (default):** the whole stage becomes one Polars streaming query. Masking methods run
  inside the query, as Polars expressions where possible and as per-batch functions for HMAC-based
  ones. A small counter after each step gives per-step row counts.
  - Measured: **1.03×** the time of a hand-written Polars script on a 153 MB CSV.
  - On a 4 GB CSV, memory growth stayed under **300 MB**.
- **Batch path:** readers → bounded queues → steps → writer, passing Arrow record batches. It is used
  when a step can't run inside a Polars query.
- **DuckDB steps:** SQL filters and sorts run in a locked-down, in-memory DuckDB:
  - no extensions are installed or loaded;
  - no file or network access;
  - settings are locked;
  - **no spill to disk**: a step that needs more memory than its share stops with a clear message.
- **Commit writer:** output goes to a temporary name in the target and is renamed into place only when
  complete, then a manifest lists every file with size and SHA-256. A failed or cancelled stage leaves
  nothing behind, not even a temporary file.
- **Memory watchdog:** samples the stage's memory (on macOS, the physical footprint) every 100 ms. It
  pauses the source at 90% of the share and stops the stage at 100%.

#### Scanner and report writer
- **`scan`** reads a sample of each table, profiles it and runs the detectors
  ([Detection (safetwin scan)](guide.md#detection-safetwin-scan)). It writes a draft
  policy containing reasons, never values.
- **After `mask`**, the report writer:
  - runs the residual scan on the output;
  - checks uniqueness and relationship integrity;
  - writes `report.json` and `report.html` next to the twin.

#### Exporter
It turns the compiled pipeline into readable code ([Export to a Polars script](guide.md#export-to-a-polars-script)): a Polars script (DuckDB SQL
and Airflow or Dagster tasks were never built). Everything that must match the engine byte for byte (key
derivation, canonical bytes, HMAC, pseudonym formats, fake values, date shifts, the generalize and
redact expressions, subset selection) lives in one module, `safetwin/masking/portable.py`, that the
engine imports and the exporter copies into the script word for word. Anything it can't reproduce
exactly is refused, never approximated.

#### Engine (for `safetwin ui`)
A background process, started by `safetwin ui` (or `safetwin engine start`). It never loads the data
libraries itself.

- **Control API:** FastAPI on `127.0.0.1` with a random port. The security model is in
  [The local servers](security.md#the-local-servers).
  - Every request needs a 256-bit token, in a header.
  - Requests with a wrong `Host` (DNS rebinding) or an unknown web `Origin` are refused.
  - The WebSocket must send the token first.
- **Connection file:** the port and token, in a 0600 file inside a 0700 app folder. The CLI and the
  UI find the engine through it.
- **Stage workers:**
  - Each stage runs in its own single-use process with a private temporary folder, which is deleted
    when it ends.
  - They take versioned JSON-lines messages on stdin/stdout, capped at 1 MiB. No data ever crosses
    the pipe.
  - At most 2 run at once; more runs queue.
  - A crashed or killed worker fails its stage cleanly. If the engine itself is killed, its workers
    clean up and exit by themselves.
- **Events:** run and stage progress go to the UI over the WebSocket.
- **Measured:** about 60 MB RSS and 0.2% of one core when idle; ready 0.2 s after launch.

#### Run history (optional)
A local SQLite database records past runs, for `safetwin runs list/show` and the UI:
- states and times;
- per-step row counts;
- output files with their SHA-256;
- error codes (never messages).

It is a convenience. The report written next to the output is the real evidence. The control plane
talks to it with Python's built-in `sqlite3`. Schema migrations and pruning (90 days by default) run
in a short-lived helper process, so the engine stays light.

### Life of a `safetwin mask` run

```
 load masking.yaml ─▶ validate ─▶ resolve key ref ─▶ read source schemas ─▶ check every column is named
        │                                                                          │ unknown column → stop
        ▼                                                                          ▼
 compile to pipeline (one stage per table, ordered for subsetting) ─▶ select subset rows (if any)
        │
        ▼
 for each stage: source ─▶ masking steps ─▶ commit writer (temp name → rename → manifest)
        │                    ▲ the watchdog pauses or stops on memory
        ▼
 residual scan + uniqueness + relationship checks ─▶ report.json / report.html ─▶ exit status
```

The exit status is 0 only if every stage committed, every relationship has 0 orphans, every unique
column is still unique, and the residual scan found nothing in a masked column.

### Process model

| Process | Started by | Can do | Never does |
|---------|-----------|--------|------------|
| `safetwin` CLI | You, CI, a container | Read the source, write the target, read the key reference | Listen on the network |
| Engine (control plane) | `safetwin ui` / `engine start` | Serve the local API, start workers, keep run history | Load Polars, PyArrow, DuckDB or SQLAlchemy; touch data |
| Stage worker | The engine, one per stage | Read the source and write the target for its stage | Outlive its stage, or its engine by more than a short grace period |
| Maintenance helper | The engine, at start and once a day | Migrate and prune run history | Read source or target data |

Nothing needs administrator rights.

### Tech stack

| Layer | Choice | Why |
|-------|--------|-----|
| Language | Python 3.12 | One language for engine and CLI; the data libraries do the heavy lifting in native code |
| Data | Polars, PyArrow, DuckDB | Columnar, multithreaded, zero-copy Arrow between them |
| Crypto | `hmac`/`hashlib` (stdlib), pyca `cryptography` (AES-SIV for `encrypt`) | Standard, vetted primitives only |
| Postgres (M4) | ADBC Postgres driver → Arrow | Columnar reads with no row-by-row Python |
| API | FastAPI + Uvicorn (control plane only) | Typed, small, local |
| Metadata | SQLite with stdlib `sqlite3` (Alembic migrations in the helper) | Light control plane |
| UI | React, TypeScript, Vite, React Flow | The schema graph and policy editor ([The page and the commands](guide.md#the-page-and-the-commands)) |
| Packaging | `uv tool install` / `pipx install`, a Docker image, a GitHub Action | How data engineers install tools; no desktop signing |

### Repository layout

```
src/safetwin/               # one package, installed as `safetwin`
  spec/                     # policy and pipeline models, validation, JSON Schema
  dataplane/                # fused / batch / DuckDB paths, commit writer, manifest, watchdog
  executor/                 # stage workers, queue, run store
  api/                      # control API, events, connection file
  metadata/                 # SQLite schema, migrations, maintenance helper
  cli/                      # the `safetwin` command
apps/web/                   # the browser UI (built in M5)
schemas/                    # generated JSON Schema
examples/                   # example policies and synthetic datasets
tests/                      # unit, property, equivalence and leak tests
docs/                       # these documents
```

## Testing

A tool that promises "safe" has to prove it. These are the kinds of tests and checks, what each one
guarantees, and where they run. One command runs them all: `scripts/check.sh` (add `--perf` for the
benchmarks). CI runs the same command.

### Test kinds

| Kind | What it proves | Where |
|------|----------------|-------|
| **Unit** | Each method, detector, validator and policy rule on small, hand-written inputs | `tests/masking/`, `tests/detect/`, `tests/spec/`, `tests/test_keys.py` |
| **Property** (Hypothesis) | The invariants below hold for random tables: nulls, empty strings, Unicode, extreme dates, duplicates | `tests/masking/test_properties.py` |
| **Determinism** | Same key, policy and input give the same twin across runs and processes; a different key changes every keyed value | `tests/masking/test_mask_run.py` |
| **Integrity** | After masking and subsetting: 0 orphans per relationship, unique columns still unique, row counts as reported | `tests/masking/test_mask_run.py`, `tests/masking/test_subset.py` |
| **Residual scan** | The example policies leave 0 detector findings in masked columns | `tests/masking/`, `examples/shop/` |
| **Export equivalence** | The exported script reproduces the engine's rows in order, for the example policies, a table with every method, and random tables ([Equivalence is tested](guide.md#equivalence-is-tested)) | `tests/masking/test_export.py` |
| **Encryption algorithms** | FF1 gives NIST's six AES-128/AES-256 samples and round-trips in batches; AES-GCM hides repeats and refuses a changed token; relationships need one deterministic algorithm; mask → unmask → rekey with every algorithm, the report's fingerprint refusing another key; the exported script encrypts as the engine does; passphrase keys | `tests/masking/test_algorithms.py` |
| **Pinned outputs** | Every method's values, the access key, encrypted tokens and subset roots for a fixed key never change ([Stability](security.md#stability)) | `tests/masking/test_golden.py` |
| **Postgres and Excel** | Scan, check and mask from Postgres to files and to a schema (keys added back, `--replace`, refusals, no URL in messages), Excel in and out, the staging folder removed after success and failure; on Postgres 16 from the `pgserver` wheel, or on the server `SAFETWIN_TEST_PG_URL` names (its schemas `public` and `safe_copy` are replaced) | `tests/masking/test_staging.py` |
| **The page** | `safetwin ui`'s guard, mask and unmask, the method picker, preview, progress, history and Excel, through its API | `tests/ui/` |
| **Leak (zero retention)** | No canary from the input appears anywhere safetwin could write, on success and on every failure path ([Zero retention](security.md#zero-retention)) | `tests/leak/` |
| **API security** | Every check of the local API, against a real engine process ([The local servers](security.md#the-local-servers)) | `tests/api/` |
| **Process lifecycle** | Workers, the maintenance helper and the engine clean up after crashes, kills and interrupts | `tests/executor/`, `tests/cli/` |
| **Quickstart** | The README's quickstart works as written from a fresh install of the wheel | `scripts/smoke.sh` (CI job "package") |
| **Performance** | Measured numbers stay true ([Performance gates](#performance-gates)) | `-m perf` |
| **Lint and types** | ruff, ruff format, mypy (strict) | `scripts/check.sh` |
| **Schema drift** | The committed JSON Schema matches the models | `scripts/check.sh` |

### Invariants (property-tested)

For every method, and for random input:

1. **Nulls stay null**, except `fake` with `consistent: false`.
2. **Types stay the same**, except where a method changes them on purpose (`redact` gives text).
3. **Row counts are unchanged** without a subset.
4. **Joins survive:** two columns with the same domain map equal inputs to equal outputs and unequal
   inputs to unequal outputs (collisions are detected, and fail the run).
5. **Determinism:** same key, domain and input give the same output; another key gives another output.
6. **Date shift keeps intervals** between dates of the same entity.
7. **Generalization only coarsens:** the output is the bucket that contains the input.
8. **No raw value survives** in a column whose class isn't `kept`.

### Performance gates

Benchmarks run with `scripts/check.sh --perf`. A number goes into the README only if one of these
tests produces it.

| Gate | Current measurement (Apple M4) |
|------|-------------------------------|
| Fused stage vs a hand-written Polars script (153 MB CSV) | 1.03× (gate: within 2×) |
| Idle engine memory | about 60 MB RSS (gate: under 80 MB) |
| Pseudonymization speed, distinct values | About 1.7M integers/s and 1.0M strings/s per core (gates: 1.0M and 0.8M) |
| Run history overhead per run | About 1 ms, no measurable slowdown |
| Large input (opt-in, `SAFETWIN_BIG_GB`) | 4 GB CSV: 10.5 s, memory growth at most 282 MB |

### Example datasets

`examples/` holds small, fully synthetic datasets with planted personal data (emails, phones, card
numbers that pass Luhn, birth dates, free-text notes) and known relationships. Every milestone's
"done when" check runs on them. They're also the demo in the README. No real personal data is ever
committed: the generators are in the repo, and the CI leak tests would flag a stray canary.

### Review

Every change goes through a written review before it's merged. The reviewer checks it against the
design docs, looks for bypasses and races, and answers PASS or FAIL. A change merges only after a
PASS and a green `scripts/check.sh`.

## Decisions

The decisions that shape safetwin, newest first, with the reason for each. A decision changes only by
adding a new entry that replaces it.

| # | Date | Decision | Why | Status |
|---|------|----------|-----|--------|
| 22 | 2026-10-18 | **Cloud drives through their synced folders**, not their APIs: *Save to a folder* copies the masked zip into a folder that Google Drive, Dropbox, OneDrive or iCloud keeps in sync; with none, the page says to download and upload at drive.google.com | No OAuth app, Google verification or stored tokens in a tool whose promise is that nothing leaves the computer; works with every drive that has a desktop app | Active |
| 21 | 2026-10-18 | **`encrypt` gets `aes-gcm` and `ff1`, and keys can come from a passphrase.** FF1 is written on pyca `cryptography`'s AES in `portable.py` (checked against NIST's samples) rather than taken from a package; FF3-1 and per-value RSA are left out. A passphrase key uses scrypt with a fixed salt | People want values that keep their format (cards, phones) and values that hide repeats, and standard formats others can decrypt; the exported script must need nothing more than `cryptography`. The fixed salt makes a passphrase reproducible anywhere, at the cost of shared guessing: hence scrypt and a 12-character minimum. Replaces the 0.1 note that FF1 waited for a maintained library | Active |
| 20 | 2026-10-18 | **Postgres and Excel are staged through Parquet:** a source is copied to Parquet in a private 0700 folder (removed when the run ends) and masked by the unchanged engine; a target gets the twin only after every check passed (Postgres: one transaction into a new schema, keys added at the end) | One engine path for every source, so every check, the report and the leak tests stay as they are; a failed run never touches the target. The cost is a copy on local disk, inside a private folder | Active |
| 19 | 2026-10-17 | **A first `safetwin ui` now:** one page served by its own small FastAPI app on 127.0.0.1 (token in the URL fragment, then an HttpOnly SameSite=Strict cookie, plus a custom header on changes), running the CLI's code on files added in the page | The owner wants to add files and choose per file without the terminal; the fuller editor of M5 can still come | Active; brings part of M5 forward from #16 |
| 18 | 2026-10-17 | **A reversible method, `encrypt`:** deterministic AES-256-SIV (RFC 5297, pyca `cryptography`) under an access key derived from the masking key; chosen per column, or per file in the UI. A relationship between a reversible and a one-way table stays one-way on both sides | The owner wants people they trust to read values back; deterministic keeps joins; the access key reads only encrypted columns, never pseudonyms; a vetted library, not our own cipher | Active |
| 17 | 2026-10-15 | **Release through tags:** a tag `v<version>` publishes to PyPI by trusted publishing (no stored token) and pushes the image to the GitHub Container Registry; a composite GitHub Action installs from PyPI | Nothing secret to leak, one step for a release, and the README's quickstart runs on every release's wheel first | Active |
| 16 | 2026-10-15 | **Trimmed MVP:** export to Polars only; Postgres (M4), the browser UI (M5), and SQL, Airflow and Dagster exports wait until someone asks | Ship something usable sooner and spend the effort where users ask for it; the Polars script already runs in any orchestrator | Active |
| 15 | 2026-10-15 | **One portable core** (`masking/portable.py`) that the engine imports and the exporter copies word for word | The engine and the exported script can't drift: the bytes behind a pseudonym come from one place | Active |
| 14 | 2026-10-03 | **Run history is optional.** Keep the SQLite run history (built in T5c) for `safetwin runs` and the UI, but don't expand it; `report.json` next to the output is the evidence | The report travels with the twin and needs no database; history is a convenience | Active |
| 13 | 2026-10-03 | **Name: safetwin** ("a safe twin of your production data") | Says what it makes; free on PyPI. "safespark" was rejected because "Spark" reads as Apache Spark to data engineers, and the ASF discourages names that suggest a link | Active |
| 12 | 2026-10-03 | **Ship as a pip/uv-installable CLI with a browser UI** served by the engine on localhost. No desktop app, no Tauri, no Apple signing | It's how data engineers install tools (dbt, Dagster, marimo); the secure local API already exists; it removes the Rust and signing work | Active; replaces #4 |
| 11 | 2026-10-03 | **Sources: CSV/Parquet first, then Postgres** through ADBC, tested on a pip-installed Postgres | Files work with nothing to install; Postgres is where schemas, keys and subsetting matter most | Active |
| 10 | 2026-10-03 | **Open-source product first**, not a quick portfolio demo | The owner's choice: adoption and real users over speed to a showcase | Active |
| 9 | 2026-10-03 | **Direction reset: safe copies of production data with code export.** Cut packet capture, streaming and IoT, the scheduler and triggers, USB detection, Google Drive, IAM and team mode, the desktop shell, and the student and hobbyist personas | The old scope had no user with a painful problem and was five products for one person. This one maps to real data engineering work and reuses the engine | Active; replaces the 2026-09-29 vision |
| 8 | 2026-10-03 | **Every column must be named in the policy;** an unknown column fails the run | A column added to production later must never slip through unmasked | Active |
| 7 | 2026-10-03 | **Keys:** HMAC-SHA-256 with per-method, per-domain subkeys from HKDF, a `v1` version tag in the derivation, and only references in files | Joins survive (same domain, same output); domains are separated; algorithm changes can't silently change outputs; keys never leak through files | Active |
| 6 | 2026-10-02 | **The control plane stays light:** it never imports Polars, PyArrow, DuckDB, SQLAlchemy or Alembic. Run history uses stdlib `sqlite3`; migrations and pruning run in a helper process | It keeps the idle engine at about 60 MB (SQLAlchemy alone pushed it to 80–90 MB). An import-blocker test enforces it | Active |
| 5 | 2026-10-02 | **Single-use stage workers**, each with a private 0700 temp folder, at most 2 at a time, versioned JSON-lines protocol with no data on the pipe | Crash isolation; no shared temp files between runs; a stuck stage can be killed | Active |
| 4 | 2026-10-01 | Local control API security: a token in a header, exact `Host`, the app's `Origin` only, a token-first WebSocket, a 0600 connection file | The Jupyter-style model for a loopback API that a browser talks to | Active; the "desktop shell" part is replaced by #12 |
| 3 | 2026-10-01 | **No spill to disk** in DuckDB; a step that runs out of memory stops with a clear message | DuckDB's built-in temp-file encryption is insecure (GHSA-vmp8-hg63-v2hp), and its secure one downloads an extension at run time | Active |
| 2 | 2026-09-29 | **Fused Polars path by default**; batch path and DuckDB for what Polars can't do inside a query | Measured 1.03× a hand-written Polars script, against about 5.5× for batch-by-batch | Active |
| 1 | 2026-09-29 | **Python engine** (not Rust) | Built solo by a Python developer; Polars, DuckDB and Arrow do the heavy work in native code | Active |


## Status

1.0.0 is the final release: complete, tested on macOS and in a Linux container, and no further development
is planned. Its formats and outputs are listed in [Stability](security.md#stability) and pinned by
`tests/masking/test_golden.py` and `tests/masking/test_algorithms.py`.

Ideas that were considered but never built:

- MySQL, SQLite, S3 and other object stores as sources or targets.
- Exports to DuckDB SQL, Airflow or Dagster (the Polars script runs inside any of them as a Python task).
- A `where:` filter for subsets, instead of a fraction.
- Data-contract checks on the twin, and k-anonymity estimates for quasi-identifiers.
- More `fake` kinds and locales, and keys from the macOS keychain.
- A fuller editor in the page (a schema graph, editing the YAML).
