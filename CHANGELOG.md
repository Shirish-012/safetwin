# Changelog

All notable changes to safetwin. 1.0.0 is the final release: no further development is planned.

## 1.0.0 — 2026-10-19 (final release)

Everything planned after 0.1, in one version. Nothing a 0.1 twin holds changes: the same key and policy
give the same values (now pinned by a test).

- **Postgres** (`safetwin scan --postgres env://URL --schema S`, and `postgres:` sources and targets): read
  through ADBC in a read-only session; the database's foreign keys become the relationships; the twin goes
  to files or into a new schema, in one transaction, with primary keys, unique constraints and foreign keys
  added back after every check passed. `--replace` replaces the tables of an earlier twin. Messages and the
  report name `host:port/database`, never the URL.
- **Excel** (`format: xlsx`) in and out: a table per sheet, a workbook per table; integers beyond 2^53 are
  written as text so Excel can't round them. `unmask` and `rekey` read and write `.xlsx`.
- **`safetwin rekey`**: re-encrypts reversible files under a new access key (key rotation).
- **Pinned outputs**: `tests/masking/test_golden.py` fixes every method's values, the access key, encrypted
  tokens and subset roots for a fixed key; [Stability](docs/security.md#stability) lists the formats and outputs that are fixed.
- **`safetwin ui`**: Excel files in and out; a method per column (the ones its type takes); a preview of the
  first masked rows; upload and masking progress; a History tab of earlier reports (no values); a link
  between files must be masked or kept on both sides. Narrow screens stack each column's outcome under its
  method.
- A policy that holds a database URL itself, rather than a reference to it, is refused by `check`
  (`url_reference`), without the URL in the message.
- Fixed: on Linux, a prune of the run history could delete the database's `-wal` and `-shm` files while the
  engine still wrote to them (opening the database file to make it private dropped SQLite's lock on it), so
  later history went missing. An existing database file is no longer opened.
- Linux: the whole test suite now runs in a Linux container too (Debian, Python 3.12), with the Postgres
  tests on the official Postgres 16 image (`SAFETWIN_TEST_PG_URL`). `pgserver` is installed only where it
  has wheels (macOS, x86-64 Linux).
- The README says how to install from this repository (`pip install .`, or from GitHub with
  `pip install git+https://…`) and where the masked data goes; the GitHub Action installs the copy of
  safetwin it comes from unless `package` says otherwise. The page says "this computer", not "this Mac".
- The page has a new look: frosted glass over a soft blue field (a deep-navy one in dark mode), larger
  numbers, and a progress bar of pills that fill up.
- **More ciphers for `encrypt`:** `algorithm: aes-gcm` (a random nonce per value: repeats can't be seen;
  no joins) and `algorithm: ff1` (NIST SP 800-38G format-preserving encryption: digits, or letters and
  digits, are encrypted and everything else stays, so a card number keeps its shape). FF1 is checked
  against NIST's samples; values too short for it are emptied and counted. The report records the access
  key's fingerprint, and `unmask` reads the ff1 columns from `report.json` and refuses another key. `rekey`
  keeps each column's algorithm. docs/security.md shows how to decrypt each format with standard libraries.
- **Keys from a passphrase:** `safetwin key from-passphrase` (scrypt; the same words give the same key).
- **The page:** a Keys tab (this computer's key, a new key, your own key, or a passphrase; kept in memory);
  reversible files offer the three ciphers per column (phones and cards default to keeping their format);
  *Save to a folder* puts the zip in a Google Drive, Dropbox, OneDrive or iCloud folder that is synced, and
  says what to do when there is none; Unmask takes the report.json too.
- **One cipher for a whole file:** `safetwin scan --reversible --algorithm aes-siv|aes-gcm|auto`, and
  *Encrypt with* on each reversible file in the page (any column can still differ). `unmask` reports which
  cipher it found for each column; nothing is chosen by hand. The Keys tab lists what the key drives.
- New dependencies: `adbc-driver-postgresql`, `fastexcel`, `xlsxwriter`; `pgserver` for the tests.

## 0.1.0 — 2026-10-17 (shared as a zip)

The first public version: safe twins of folders of CSV and Parquet files.

- `safetwin scan` profiles every table from a sample and drafts a masking policy, with the reasons and the
  profile as comments, never a value.
- `safetwin check` and `safetwin mask`: the methods `keep`, `pseudonymize` (int, hex, uuid), `fake`
  (consistent or random), `generalize`, `date_shift`, `redact`, `null` and `drop`; keys by reference
  (`env://`, `file://`) with HKDF-SHA-256 subkeys; `report.json` and `report.html` with privacy classes,
  quasi-identifiers, foreign-key integrity, uniqueness, a residual scan and the SHA-256 of every file. A
  failed check leaves no twin; `--replace` swaps a twin only after the new one passes.
- Subsetting: a fraction of a root table, picked by a keyed hash (the same rows on every run), with every
  row the selection points at and their children: 0 orphans.
- `safetwin export --to polars`: the same job as a standalone Polars script that writes exactly the same
  twin.
- `encrypt`, the reversible method (AES-256-SIV from pyca `cryptography`, a new dependency): `safetwin key
  access` writes the access key for the people who may read encrypted columns, `safetwin unmask` reads them
  back with their types, and `safetwin scan --reversible` drafts it for every column to mask. Reports class
  these columns *encrypted*.
- `safetwin ui`: a page in the browser, served from 127.0.0.1, to add files, choose reversible or one-way
  per file and the columns to mask, download the masked files and the report, read reversible files back,
  and download the access key.
- `safetwin demo`, `safetwin key new`, a container image and a GitHub Action.
