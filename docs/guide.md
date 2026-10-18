# Using safetwin

How to mask data with safetwin: the page, the commands, where data comes from and goes, the policy file and its methods, what the report proves, and the exported script. Keys and encryption: [security.md](security.md).

## The page and the commands

safetwin is **code first**. The policy file is the source of truth, the CLI does everything, and the
browser UI is an optional editor for the same file. Nothing the UI does is impossible from the CLI.

### Commands

```
safetwin ui [--no-browser]                       the page in your browser: mask, unmask, history, keys
safetwin demo DIR [--csv]                        a made-up shop with planted personal data, in DIR/data
safetwin scan SOURCE [-o masking.yaml]           profile the files and draft a policy (reasons, never values)
              [--reversible [--algorithm aes-siv|aes-gcm|auto]]   draft every masked column encrypted
              [--postgres env://URL --schema S]  scan a Postgres schema instead of a folder
safetwin check masking.yaml                      every column named, every method fits its column
safetwin mask masking.yaml [--out DIR]           the safe twin, report.json and report.html
              [--strict] [--replace] [--memory-limit SIZE] [--json]
safetwin unmask FILES --key REF --out DIR        read encrypted columns back (or --policy masking.yaml)
safetwin rekey FILES --out DIR --from REF --to REF   re-encrypt reversible files under a new access key
safetwin export masking.yaml --to polars -o FILE the same job as a standalone Polars script
safetwin key new --file PATH                     a new random 32-byte key (mode 0600)
safetwin key from-passphrase --file PATH         the key of a passphrase: the same words, the same key
safetwin key access masking.yaml --file PATH     the access key, for the people who may read reversible columns
safetwin key fingerprint masking.yaml            the fingerprint of the key a policy refers to (never the key)
```

`safetwin runs` and `safetwin engine` (the run history and the background engine) exist but are hidden
from `--help`.

How the commands behave:
- **Exit codes:** `0` success; `1` the job failed (one `ERROR` line saying what and where); `2` bad
  usage; `130` interrupted (nothing half-written).
- **Output:** progress on stderr, a summary on stdout. Never a data value, a key or a token, in any
  output or error message.
- **Machine-readable:** `--json` on `check` and `mask` prints JSON for scripts and
  CI.

A first session looks like this:

```console
$ safetwin key new --file ~/.config/safetwin/shop.key
key written to /Users/me/.config/safetwin/shop.key (mode 0600); fingerprint 9f2c4e1a7b3d5c60
use it with:  key: file://~/.config/safetwin/shop.key

$ safetwin scan ./prod_dump -o masking.yaml
scanned 2 tables, 14 columns (10,000-row sample each)
  customers.email       → fake email        (name matches "email"; 98% valid emails)
  customers.birth_date  → generalize year   (name matches "birth"; plausible birth dates)
  customers.city        → keep              (low cardinality: possible quasi-identifier)
  orders.card_number    → redact last 4     (92% pass Luhn)
  …
draft policy written to masking.yaml: review every line before running

$ safetwin mask masking.yaml --out ./safe
customers  120,000 → 120,000 rows   0.4 s
orders     980,000 → 980,000 rows   1.9 s
relationships: 1 checked, 0 orphans · unique columns: 2 checked, all unique · residual scan: 0 findings
report: safe/report.html
```

### The page (`safetwin ui`)

**A simple page, since 0.1** (`safetwin/ui/`), four tabs:

- *Mask*: add CSV, Parquet or Excel files (upload progress for big ones). For each file choose reversible or
  one-way; for each column pick a method from the ones its type takes (the scan's suggestion is preselected;
  a column linking two files takes the suggested method or is kept, and both sides must agree). *What
  happens* shows the outcome, including links that stay one-way. *Preview* masks the first 5 rows of every
  file with these choices (the mask step on a sample: nothing else is written). *Mask files* runs the job
  with live progress (rows masked, then the checks) and gives a zip of the masked files (CSV, Parquet or
  Excel) with the report and the policy.
- *Unmask*: add reversible files (CSV, Parquet or Excel) and an access key, download the readable files.
- *History*: the reports of earlier runs, kept in `ui-history/` next to the page's key (mode 0700, the
  newest 200): file names, choices, row counts and status, never a value or a masked file. Each can be
  opened or deleted.
- *Keys*: the masking key the page uses: this computer's key file (the default), a new random key (shown
  once, to save as a file), your own key (a key file or 64 hex characters) or a passphrase. It stays in
  memory and reaches each run through its environment. Below it, the access key's fingerprint and a
  download.
- For a *reversible* file, *Encrypt with* sets every column at once: *Recommended* (phone and card numbers
  keep their format with ff1, the rest standard), *Standard everywhere* (aes-siv) or *Random where
  possible* (aes-gcm; columns that link files stay standard so they still join). Each column can still be
  changed on its own: *encrypted, standard*, *encrypted, keeps the format* (ff1: digits, or letters and
  digits) or *encrypted, random*, as well as kept, emptied or removed. The algorithm belongs to the column,
  not to the key: one key serves them all, and the Keys tab lists what it drives.
- *Unmask* never asks for the algorithm: a value's prefix tells standard (`st1.`) from random (`sg1.`), and
  the report.json from the same zip names the columns that kept their format. The result shows, for each
  column, what was found.
- *Save to a folder* (after masking) copies the zip into a folder of this computer: the page lists the
  folders that Google Drive, Dropbox, OneDrive or iCloud keep in sync, so the zip goes to the cloud from
  there without signing in to anything. With no such folder, it says to download the zip and drag it into
  drive.google.com, or to install Google Drive for desktop.

It runs the same code as the CLI, listens on 127.0.0.1 only, and needs the token it opened the browser with
(traded for an HttpOnly, SameSite=Strict cookie; changes also need an `X-Safetwin` header). Reports are
served with a sandboxing Content-Security-Policy. 

## Sources and targets

Where safetwin reads production data, and where it writes the safe twin.

### What's supported

| Kind | Source | Target | Since |
|------|--------|--------|-------|
| Folder of **Parquet** files | ✔ | ✔ (default) | 0.1 |
| Folder of **CSV** files | ✔ | ✔ | 0.1 |
| **Postgres** | ✔ (read-only) | ✔ (a separate schema) | 1.0 |
| Folder of **Excel** workbooks (`.xlsx`) | ✔ (a table per sheet) | ✔ (a workbook per table) | 1.0 |
| SQLite, MySQL, S3 and other object stores | not supported | not supported | — |

### Files

```yaml
source: { folder: ./prod_dump, format: parquet }
target: { folder: ./safe, format: parquet, compression: zstd }
```

- **Tables:** by default each file is a table, named after its file stem (`customers.parquet` →
  `customers`). For partitioned data, map names to globs:
  `tables: { orders: "orders/**/*.parquet" }`.
- **CSV:** a header row is required. Values are read as text unless the policy or the scan gives a
  type, so a scanned ID column like `00042` keeps its leading zeros. Delimiter, quote character and
  encoding are settable (UTF-8 by default).
- **Output layout:** one folder per table, with files named after the run, plus a manifest:
  ```
  safe/customers/part-00000-r1a2b3c4d.parquet
  safe/customers/_manifest/run=…_r1a2b3c4d.json      # every file with size and SHA-256
  safe/report.json · safe/report.html
  ```
- **Manifest:** each output dataset gets a manifest, written last, which makes the commit visible. It
  lists every file with its row count, size and SHA-256, so anyone can check the twin without safetwin.
  The format is under "Manifest" below.
- **Atomic writes:** every file is written to a hidden temporary name and renamed into place only when
  complete. A failed or interrupted run leaves no partial file. A run never overwrites an existing file:
  a new run id gives new names.
- **Types are kept** unless a method changes them on purpose (for example `redact` turns a card number
  into text).

#### Manifest

The engine writes it as JSON, with its fields in this order:

```json
{
  "dataset": "customers",
  "run_id": "r1a2b3c4d",
  "pipeline": "shop-to-staging@v3",
  "committed_at": "2026-10-03T09:14:07Z",
  "schema": [{"name": "id", "type": "int64"}, {"name": "email", "type": "string"}],
  "files": [
    {"path": "part-00000-r1a2b3c4d.parquet", "rows": 120000, "bytes": 1048576,
     "sha256": "9f2c…", "compression": "zstd"}
  ],
  "totals": {"rows": 120000, "bytes": 1048576},
  "classification": {"id": "pseudonymized", "email": "pseudonymized"},
  "lineage": {"inputs": ["file://prod_dump/customers.parquet"], "operators": ["pseudonymize", "fake"]}
}
```

It holds names, counts, sizes and hashes only, never a data value.

### Postgres and Excel

The engine reads and writes folders of files (decision #20). A Postgres or Excel **source** is first copied,
table by table, to Parquet files in a private staging folder (mode 0700, in the system's per-user temporary
folder); the run masks those, and the folder is removed when the run ends, failed or interrupted included. A
folder left by a crash is removed by a later run once it's a day old. A Postgres or Excel **target** gets the
twin from such a folder only after every check has passed, so a failed run writes nothing there.

#### Postgres

```yaml
source:
  postgres: env://PROD_REPLICA_URL       # a connection URL held in an env var or a 0600 file, never inline
  schema: public                         # the tables are the ones spec.tables names
target:
  folder: ./safe-report                  # the report goes here
  postgres: env://STAGING_URL
  schema: safe_copy                      # created if missing; never the source schema
```

`safetwin scan --postgres env://PROD_REPLICA_URL --schema public -o masking.yaml` drafts the policy: a
sample of each table (its first 10,000 rows, or 1% when that is more) is profiled, and the database's
**single-column foreign keys become the policy's relationships**, so subsetting and the orphan checks work
with nothing declared by hand. Foreign keys of several columns are left out, with a note. Tables whose names
aren't lower-case letters, digits and `_` are skipped, with a note.

- **Reads** go through the ADBC Postgres driver straight into Arrow (no row-by-row Python), in a session set
  read-only (`SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`). A read-only role on a replica is
  still the advice. Types the driver can't give as Arrow (`json`, `uuid`, intervals, arrays of those) are
  read as text; `numeric(p, s)` with p ≤ 38 comes back as a decimal.
- **The target can be files** (any folder target: Parquet, CSV, Excel) **or a schema.** Into a schema, the
  twin is loaded in **one transaction**: the schema is created if needed, the tables are created and filled,
  then the source's primary keys, unique constraints and foreign keys are added for the columns the twin
  still has. A table that exists already stops the run unless you give `--replace` (then it is dropped and
  made again, still in that one transaction). The report (`report.json`, `report.html`) goes to the
  target's folder and names where the twin went.
- **Messages and the report name `host:port/database` only:** never the user, the password or the URL's
  options. A failed connection says `cannot connect to Postgres at db:5432/app (OperationalError)`.
- **Export:** `safetwin export` refuses a Postgres policy for now; the script reads and writes files.
- **Tests** run against Postgres 16 from the `pgserver` wheel (a dev requirement): no Docker.

#### Excel

```yaml
source: { folder: ./workbooks, format: xlsx }
target: { folder: ./safe, format: xlsx }
```

- **Reading** (fastexcel / calamine): every `.xlsx` file of the folder is read; a workbook with one sheet is
  one table named after the file, one with several gives `<file>_<sheet>` per sheet. Excel's lock files
  (`~$…`) are skipped. Types are what the cells hold: numbers, dates, text.
- **Writing** (xlsxwriter): one workbook per table, with a sheet of the table's name, written under a
  temporary name and renamed into place. Excel keeps numbers as doubles, so integers beyond 2^53 are
  written as text (exact); decimals and bytes are written as text too, and time zones as UTC.
- `safetwin unmask` and `safetwin rekey` read and write `.xlsx` files as well.

### Credentials

- A source or target that needs a password uses a reference (`env://`, or `file://` with mode 0600),
  exactly like the masking key ([Keys](security.md#keys)).
- `safetwin check` and the validator refuse a policy with an inline password or token.
- Connection URLs never appear in logs, the report, run history or error messages; only the host and
  database name do, with credentials stripped.

## The policy and its methods

What happens to each column, and how the key behind it works. Detection, subsetting and the report
are in [Detection, subsetting and the report](guide.md#detection-subsetting-and-the-report); export is in [Export to a Polars script](guide.md#export-to-a-polars-script).

### The policy file

A policy is a YAML file, kept in git, with `kind: MaskingPolicy`. `safetwin scan` writes a first draft;
a person reviews it.

```yaml
apiVersion: safetwin/v1
kind: MaskingPolicy
metadata:
  name: shop-to-staging
spec:
  source:  { folder: ./prod_dump, format: parquet }    # one table per file (the file stem), or a `tables:` map of globs
  target:  { folder: ./safe, format: parquet }          # `safetwin mask --out` overrides it
  key: env://SAFETWIN_KEY                                # env:// or file:// (must be 0600): never the key itself
  unknown_columns: fail                                 # a column the policy doesn't name stops the run
  tables:
    customers:
      id:          { method: pseudonymize, domain: customer }
      email:       { method: fake, kind: email }
      full_name:   { method: fake, kind: name }
      birth_date:  { method: generalize, to: year }
      postcode:    { method: generalize, keep_chars: 3 }
      phone:       null
      notes:       drop
      city:        keep
      created_at:  { method: date_shift, entity: id }
    orders:
      id:          keep
      customer_id: { method: pseudonymize, domain: customer }
      card_number: { method: redact, keep_last: 4 }
      placed_at:   { method: date_shift, entity: customer_id }
      total:       keep
  relationships:
    - orders.customer_id -> customers.id
  subset:                                               # optional
    root: customers
    fraction: 0.10
    include_children: true
```

The rules:

- **Every column must be named.** `keep` is an explicit choice. A source column that the policy
  doesn't name fails the run (`unknown_columns: fail`, the default), so a column added to production
  later can't slip through unmasked. The other settings are `null` and `drop`.
- **The policy compiles to the internal pipeline format** ([Policy compiler](internals.md#policy-compiler)): one stage per table,
  source → masking steps → sink. The engine runs it, and `safetwin export` turns it into code. Validation
  covers unknown tables and columns, methods that don't fit a column's type, relationships between
  incompatible domains, and a missing key.

### Methods

| Method | Parameters | Output | Same input → same output? | Report class |
|--------|-----------|--------|---------------------------|--------------|
| `keep` | — | Unchanged | — | **kept** |
| `pseudonymize` | `domain` (default `<table>.<column>`), `format`: `auto` · `hex` · `int` · `uuid`, `prefix` | Same type: int stays int64, UUID stays UUID, text becomes `prefix + base32` | Yes, per key and domain | **pseudonymized** |
| `fake` | `kind`: name · first_name · last_name · email · phone · street · city · company · text…, `locale`, `consistent` (default true) | Realistic text of that kind | Yes when `consistent`; random per row otherwise | **pseudonymized** when consistent, **removed** otherwise |
| `generalize` | dates: `to: year·month·week·day`; numbers: `bucket: 10` or `bins: [...]`; text: `keep_chars: 3`; IPs: `/24` (IPv4), `/48` (IPv6) | Same type, coarser value (dates truncated, a number becomes its bucket's lower bound) | Yes (no key needed) | **generalized** |
| `date_shift` | `entity` (column), `max_days` (default 30) | The same type, shifted by an offset fixed per entity | Yes, per key and entity | **pseudonymized** |
| `redact` | `keep_last` / `keep_first`, `char` (default `*`), or `with: "[REDACTED]"` | Text | Yes | **removed** (full) or **partially redacted** |
| `null` | — | Nulls | — | **removed** |
| `drop` | — | Column removed | — | **removed** |
| `encrypt` | `algorithm`: `aes-siv` (default) · `aes-gcm` · `ff1`; for `ff1`: `alphabet` (`digits`, default, or `alphanumeric`) and `domain` | `aes-siv`: text `st1.<base64url>`; `aes-gcm`: text `sg1.<base64url>`; `ff1`: the same text with its digits (or letters and digits) encrypted, same length and separators. All readable again with the access key (`safetwin unmask`) | `aes-siv`, `ff1`: yes, per key (and `ff1` domain), in every column. `aes-gcm`: no, a fresh nonce per value | **encrypted** |

Details that matter:

- **Nulls stay null** under every method except `fake` with `consistent: false`. An empty string is
  a value like any other.
- **Domains make joins work.** Two columns with the same domain and key give identical pseudonyms:
  `orders.customer_id` and `customers.id` above. Different domains give unrelated pseudonyms, even for
  equal inputs.
- **Integer pseudonyms are 63-bit.** For n distinct values, the chance of a collision is about
  n² / 2⁶⁴: roughly 5 in 10,000 at 100 million values. The engine checks uniqueness on columns that
  were unique in the input (primary keys, and anything a relationship points to). If two inputs
  collide, the run stops and suggests `format: hex` or `format: uuid`, which are 128-bit and
  practically collision-free.
- **`date_shift` keeps intervals within an entity.** All dates of one customer move by the same
  offset, so "ordered 3 days after sign-up" stays true. The offset is drawn uniformly from
  [−max_days, +max_days] and is never 0 days.
- **`encrypt` is the reversible method.** Whoever holds the access key (or the masking key) reads the
  values back, with their types, with `safetwin unmask` or the page's Unmask tab. Three algorithms, for
  three needs:

  | Algorithm | Equal values | Hides length | Authenticated | Joins | Use it for |
  |-----------|--------------|--------------|---------------|-------|------------|
  | `aes-siv` (default) | equal outputs | to 16 bytes | yes | yes | keys, IDs, anything that must still join or stay unique |
  | `aes-gcm` | different outputs | to 16 bytes | yes | no | free text, emails: nothing shows which rows share a value; any AES-GCM library decrypts it |
  | `ff1` | equal outputs (per `domain`) | no: same length | no | yes (same alphabet and domain) | card, phone, account and ID numbers that must keep their format for the systems that read them |

  `ff1` needs a text column. Only the characters of its alphabet are encrypted (digits, or `0-9A-Za-z`), so
  with `digits` the letters of a value stay readable: use it on numbers, not on emails or names (the
  residual scan still looks for emails in a `digits` column, and fails the run if it finds any). NIST asks
  for at least 1,000,000 possible values, so a value with fewer than 6 digits (4 letters or digits) is
  emptied, and the report counts them. FF1 isn't authenticated: a wrong key gives wrong values, not an
  error, so the report records the access key's fingerprint and `unmask` refuses another key.
  Both sides of a relationship must be encrypted the same way (`aes-siv`, or `ff1` with one alphabet and
  domain), or both pseudonymized with one domain. Datetimes come back to the microsecond, in UTC if they had
  a zone; a decimal comes back normalized (`1.10` as `1.1`).
- **Consistent `fake` values are linkable**, so they count as pseudonymized. Anyone with the key can
  compute the fake value for a guessed input and look for it in the output. `consistent: false` gives
  random values per row; that breaks the link, and also breaks consistency.

### Pseudonymized is not anonymized

Under GDPR, data that can be re-identified with extra information that someone holds (here, the
key) is still personal data. So:

| Report class | Meaning |
|--------------|---------|
| **kept** | The original values, copied as they were |
| **encrypted** | Reversible on purpose: anyone with the access key reads the values. Personal data for as long as the access key exists, and as safe as the access key is kept |
| **pseudonymized** | Replaced, but linkable and reversible by brute force for anyone who holds the key. Still personal data while the key exists. Destroying the key turns it into practically anonymous data, but only if nothing else in the row identifies the person |
| **generalized** | Made coarser. Lowers the risk, but rare combinations (postcode prefix + birth year + gender) can still single people out |
| **removed** | Nulled, dropped, fully redacted, or random (non-consistent) fake values |

The report lists every column's class, and flags **quasi-identifiers**: kept or generalized columns
with few distinct values that, together, could single out a row. Masking lowers re-identification
risk; it doesn't remove it. The docs and the report say so.

## Detection, subsetting and the report

How `safetwin scan` suggests methods, how a smaller twin keeps every relationship valid, and what the
report proves. The methods themselves are in [The policy and its methods](guide.md#the-policy-and-its-methods).

### Detection (`safetwin scan`)

`safetwin scan` reads a sample of each table: up to 10,000 rows or 1%, whichever is larger. For every
column it reports type, null share, distinct-count estimate and length range, **never the values
themselves**. It suggests a method from three kinds of signal:

| Signal | Examples |
|--------|----------|
| **Column name** | `email`, `mail`, `phone`, `mobile`, `first_name`, `name`, `address`, `street`, `zip`, `postcode`, `dob`, `birth`, `ssn`, `national_id`, `passport`, `iban`, `card`, `ip`, `lat`/`lon`, `user_agent` |
| **Value validators** | email syntax; phone numbers; card numbers with a Luhn check; IBAN mod-97; IPv4/IPv6; UUIDs; plausible birth dates |
| **Shape** | Unique and non-null (a key: pseudonymize); free text (drop or redact); few distinct values (a possible quasi-identifier) |

The draft policy gives every column a method and a comment with the reasons, for example
`# name matches "email", 98% of the sample are valid emails`. It never contains a sample value.
**Detection only suggests;** the person reviewing the policy decides.

How a method is chosen (first match wins; the full rules are in `safetwin/masking/scan.py`):
- the name or at least half the values say what the column holds: email → `fake email`, card or IBAN →
  `redact keep_last: 4`, IP → `generalize ip`, birth date → `generalize to: year`, postcode →
  `generalize keep_chars: 3`, and so on;
- `<thing>_id` with a table `<thing>` or `<thing>s` that has an `id`: a relationship, both sides
  pseudonymized in the domain `<thing>`; another unique `id`-like column: `pseudonymize`;
- a date in a table with an entity: `date_shift` by that entity (in a CSV source, dates are text and are
  kept, with a note);
- free text, or anything a detector found in a column that would be kept: `drop`;
- the rest: `keep`, with a note when few distinct values make it a possible quasi-identifier.

A method that doesn't fit the column's type becomes `null`, so the draft always passes `safetwin check`.
`safetwin scan DIR -o masking.yaml` never replaces a file without `--force`.

### Relationships and subsetting

- **Relationships** come from the policy: `orders.customer_id -> customers.id`. Postgres foreign keys
  are read automatically. The two sides of a relationship must share a
  pseudonymization domain, or both must be kept.
- **Subsetting** picks root rows, then completes the closure:
  1. **Root selection is stable.** A row is in if `HMAC(key, "safetwin/v1/subset/<root>", key value)`,
     read as a 64-bit number, falls under `fraction` × 2^64, so re-runs and growing data pick the same
     rows. The key column is `subset.key`, or by default the root's one column that relationships point at.
  2. **Parents are always pulled in,** recursively, so every foreign key still points at a row that
     exists.
  3. **Children of rows reached from the root** are pulled in when `include_children: true` (the
     default), recursively. Children of rows pulled in only as parents are not, or one shared parent (a
     product, a country) would bring in its whole child table. Cycles and self-references are handled by
     iterating until nothing changes.
  4. **Tables with no relationship path to the root** are copied whole.

  The selection is computed before the stages run, from the key columns only. It is held in memory as a
  row filter per table, never written to the pipeline, a log or the report. The report's `subset` section
  gives the settings and the number of root rows picked.
- **Integrity:** after masking, every relationship is checked for orphans, and the report lists the
  count per relationship. It must be 0.

### The report

Every `safetwin mask` run writes `report.json` and a static `report.html` (no scripts) next to the output.
It contains **names, counts, hashes and settings, never data values**. `report.html` opens with the status,
any errors, and a row of totals (tables, rows in and out, columns masked, orphans, uniqueness, residual
findings), then one section per table; it follows the system's light or dark mode and fits a phone screen.

`report.json` looks like this:

```json
{
  "report_version": 1,
  "run_id": "r1a2b3c4d",
  "policy": { "name": "shop-to-staging", "sha256": "…" },
  "key_fingerprint": "9f2c4e1a7b3d5c60",
  "access_fingerprint": null,
  "engine_version": "1.0.0",
  "started_at": "…", "ended_at": "…",
  "tables": {
    "customers": {
      "rows_in": 120000, "rows_out": 12000,
      "columns": {
        "email": { "method": "fake", "class": "pseudonymized", "params": { "kind": "email" } },
        "city":  { "method": "keep", "class": "kept", "quasi_identifier": true }
      }
    }
  },
  "relationships": [ { "from": "orders.customer_id", "to": "customers.id", "orphans": 0 } ],
  "uniqueness": [ { "column": "customers.id", "unique_in": true, "unique_out": true } ],
  "residual_scan": { "findings": [ { "table": "customers", "column": "city", "detector": "email", "count": 0 } ] },
  "files": [ { "path": "safe/customers/part-00000-r1a2b3c4d.parquet", "bytes": 1048576, "sha256": "…" } ],
  "warnings": []
}
```

- **The residual scan** runs the detectors above on the *output*:
  - A finding in a column that was masked means something is wrong, and the run fails.
  - A finding in a `keep` column is a warning ("a kept column contains email addresses").
    `--strict` turns warnings into failures.
  - Methods with a fixed output shape (fake email and phone, hex and UUID pseudonyms, generalized IPs) are
    checked against that shape instead: every value must match it, or the run fails with an
    `outside_output_space` finding. The detectors don't run there, because the method's own output would set
    them off (a fake email is an email, and a UUID can pass the card check).
- **Uniqueness:** a pseudonymized column, a fake email column or a relationship target that was unique in
  the input must stay unique; a collision fails the run.
- **The target folder** must be empty. `--replace` replaces the twin already there, and only once the new
  one has passed every check. A failed run leaves the earlier twin as it was and writes
  `failed-report.json`. The report pair is renamed into place last, so a `report.json` means the whole run
  finished.
- **The exit status** is non-zero when integrity, uniqueness or the residual scan fails.
- **Run history** (optional) keeps the run, the files and their checksums
  ([Run history (optional)](internals.md#run-history-optional)), so a report can be checked against what was
  actually written.

## Export to a Polars script

`safetwin export` turns a policy into readable code you can run without safetwin: in CI, in a
container, or inside your orchestrator. This is how a policy designed on a laptop runs near the data
([Using safetwin](guide.md)).

```bash
safetwin export masking.yaml --to polars   -o mask_shop.py        # a standalone Polars script
safetwin export masking.yaml --to sql      -o mask_shop.sql       # DuckDB SQL (+ a small Python UDF for HMAC)
safetwin export masking.yaml --to airflow  -o dags/mask_shop.py   # an Airflow DAG with one task
safetwin export masking.yaml --to dagster  -o assets/mask_shop.py # a Dagster asset
```

**Status:** `--to polars` is the only target (`sql`, `airflow` and `dagster` were never built); the
Polars script runs inside any orchestrator as a plain Python task.

### What gets exported

The exporter works from the **compiled pipeline** ([Policy compiler](internals.md#policy-compiler)),
not from the YAML text, so the engine and the exported code start from exactly the same plan:
- the same table order;
- the same subset selection;
- the same derivation strings (`safetwin/v1/<method>/<domain>`).

| Target | Output | Depends on |
|--------|--------|------------|
| `polars` | One Python file: read → mask → write per table, then the integrity checks, with a `main()` | Polars and the standard library (`hmac`, `hashlib`); `cryptography` only if HKDF isn't inlined |
| `sql` | A DuckDB SQL script. `generalize`, `redact`, `null`, `drop` and `keep` are plain SQL. HMAC-based methods (`pseudonymize`, consistent `fake`, `date_shift`, subset selection) call a Python UDF that the script's small launcher registers, because DuckDB has no built-in HMAC | DuckDB and Python |
| `airflow` | The Polars job as one `@task` in a DAG. The key comes from an Airflow connection or variable named in the export | Airflow plus the `polars` export |
| `dagster` | The Polars job as one asset, with the key from a Dagster resource or env var | Dagster plus the `polars` export |

The exported code reads the key from the same kind of reference as the policy (`env://` or `file://`).
It never contains the key.

#### The Polars script

```bash
safetwin export masking.yaml --to polars -o mask_shop.py     # reads the source's schemas, never a row or the key
SAFETWIN_KEY=... python mask_shop.py [--source DIR] [--target DIR] [--replace]
```

- **Built from the same code.** The script is the word lists, the portable core
  (`safetwin/masking/portable.py`: key derivation, canonical bytes, HMAC, pseudonym formats, fake values,
  date shifts, the generalize and redact expressions, subset selection) and a small runner
  (`safetwin/export/runner.py`), copied word for word, then one function per table and the job. The
  engine imports the same portable core, so the bytes that make a pseudonym come from one place.
- **It checks what it can.** It refuses a source whose columns or types differ from the export's (export
  again), checks every relationship (0 orphans) and every column that must stay unique, and only then
  renames its files into place: `<target>/<table>.parquet` (or `.csv`). A failure or Ctrl-C leaves
  nothing. The residual scan and `report.json` stay with `safetwin mask`, whose report is the evidence.
- **Folders** are written relative to the script's folder (absolute when the script goes to stdout).

### Readable by design

The goal is code a reviewer would accept in a pull request, not a dump:

- **Short functions:** one function per table, one line per column, with a comment giving the report
  class. This is the exported shop:
  ```python
  def mask_customers(frame: pl.LazyFrame, keys: Keys) -> pl.LazyFrame:
      """customers: 9 column(s) in, 8 out, in the source's order."""
      return frame.select(
          pseudonymize("id", keys.mac("pseudonymize", "customer"), "int"),  # pseudonymized
          fake("full_name", "name", keys.mac("fake", "customers.full_name")),  # pseudonymized
          fake("email", "email", keys.mac("fake", "customers.email")),  # pseudonymized
          nulled("phone"),  # removed
          truncate("birth_date", "year"),  # generalized
          keep_chars("postcode", 3),  # generalized
          pl.col("city"),  # kept
          # "notes": dropped (removed)
          date_shift(
              "created_at", "id", keys.mac("date_shift", "customer"), 30, pl.Datetime("us", None)
          ),  # pseudonymized
      )
  ```
- **Shared helpers** above the tables: the word lists, the portable core and the runner, each function
  with a docstring.
- **Pinned:** a header names the safetwin version, the policy's SHA-256 and the derivation version
  (`v1`), so a reviewer knows what produced the file.
- **Formatted:** run through `ruff format` before it's written, when ruff is installed (the code is valid
  either way).

### Equivalence is tested

An exported job is only useful if it does exactly what the engine does. So CI does this for every
example policy and every target (`tests/masking/test_export.py`: the example shop as Parquet, as CSV
and as a subset, and a table that uses every method and many types):

1. Run `safetwin mask` → the engine's twin.
2. Run the exported code on the same input with the same key → the export's twin.
3. Assert the two have the same tables, schemas and rows **in the same order**. Content is compared,
   not bytes: Parquet writers add their own metadata.
4. Run the integrity checks of the exported code itself, and confirm they agree with the report.

Property tests (Hypothesis) add random tables with nulls, empty strings, Unicode, extreme dates and
duplicate keys, and assert equivalence for every method.

### Limits

- **Unsupported methods are refused.** If a method can't be reproduced exactly in a target (for
  example a future method that needs an external service), the export refuses it with a message
  naming the column. It never writes an approximation.
- **Export doesn't add features.** The exported code does what the policy says and nothing else. No
  scheduling, retries or alerting: that's the orchestrator's job.
- **Changes don't flow back.** Edits to exported code don't update the policy. The policy stays the
  source of truth; re-export after changing it.
