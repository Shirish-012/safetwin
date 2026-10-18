# Keys, encryption and security

How keys and encryption work, how safetwin keeps data from leaking, and which formats and outputs are fixed.

## Keys and encryption

### Keys

- **What a key is:** 32 random bytes. `safetwin key new` creates one and prints how to store it (an
  environment variable for CI, or a 0600 file). The policy only holds a reference (`env://` or
  `file://`; `keychain://` is refused as not supported yet), the same references used for database credentials ([Credentials](guide.md#credentials)).
  A `file://` key that others can read is refused.
- **Derivation:** each use gets its own subkey:
  `HKDF-SHA-256(key, info = "safetwin/v1/<method>/<domain>")`. The version tag `v1` means a future change of
  algorithm can't silently change existing outputs.
  - **Pseudonymize:** `HMAC-SHA-256(subkey, canonical bytes of the value)`, cut to 63 bits (int),
    122 bits (UUIDv8) or 128 bits (text).
  - **Consistent fake:** that HMAC seeds a deterministic pick from the generator's word lists.
  - **Date shift:** the HMAC of the entity value gives the offset.
- **Canonical bytes:** a one-byte type tag plus fixed-format bytes, so `"42"` and `42` don't collide by
  accident: integers as 8-byte big-endian; text (String, Categorical, Enum) as UTF-8; dates as days since
  1970; datetimes as microseconds since 1970 in UTC (the same instant gives the same pseudonym in every time
  zone); decimals as normalized text (`1.10` = `1.1`); floats as IEEE 754 with one `-0.0` and one NaN. The
  exact formats are in `safetwin/masking/hmacs.py`. They are fixed: changing one would change every
  pseudonym. Two columns match only if their values have the same type tag.
- **Access key (for `encrypt`):** `HKDF-SHA-256(key, info = "safetwin/v1/access/v1")`, 32 bytes. The
  AES-256-SIV key (RFC 5297, from pyca `cryptography`) is
  `HKDF(access key, "safetwin/v1/aes-siv/1") || HKDF(access key, "safetwin/v1/aes-siv/2")`, and what it
  encrypts is the canonical bytes below (a datetime with a zone gets the tag `z`), padded ISO/IEC 7816-4
  style to a multiple of 16 bytes. `safetwin key access` writes the access key for the people who may
  read encrypted columns: it reads those and nothing else, and the masking key can't be found from it.
- **The other ciphers of `encrypt`:** AES-256-GCM with the key `HKDF(access key, "safetwin/v1/aes-gcm")`,
  a random 96-bit nonce per value and no associated data; the token is `sg1.` + base64url(nonce ‖
  ciphertext ‖ tag) of the same padded plaintext. FF1 (NIST SP 800-38G) with AES-256 and the key
  `HKDF(access key, "safetwin/v1/ff1")`, radix 10 (`digits`) or 62 (`0-9A-Za-z`), the tweak being the
  `domain` in UTF-8 (empty by default). The implementation (`portable.FF1`) is checked against NIST's six
  AES-128 and AES-256 samples.
- **A key from a passphrase:** `safetwin key from-passphrase` (or the page's Keys tab) makes the key with
  scrypt (N = 2¹⁷, r = 8, p = 1, 128 MiB) of the passphrase's UTF-8 bytes (NFKC) and the fixed salt
  `safetwin/v1/passphrase`. The same passphrase gives the same key on every computer, which is the point:
  type it again instead of copying a file. The cost of the fixed salt is that a guess costs an attacker the
  same for every user, so a passphrase must be long (at least 12 characters; four or more random words).
  A random key file is stronger.
- **Fingerprint:** reports and run history show `HMAC-SHA-256(key, "safetwin/v1/fingerprint")`, cut to 8
  bytes. That is enough to tell which key was used, and useless for recovering it.
- **Rotation:** a new key changes every pseudonym, fake value and date shift. Plan rotations like a
  re-seed of test data.
- **Speed:** the prototype measured about 1.3M HMAC-SHA-256 values/s per core. Columns with many
  repeats are dictionary-encoded first, so each distinct value is hashed once.

Algorithms that are deliberately not used: plain unkeyed hashes of personal data (reversible by
brute force for small value spaces), MD5 and SHA-1, FF3/FF3-1 (NIST is withdrawing it), and RSA per value
(slow, and outputs hundreds of bytes long). FF1 is built on pyca `cryptography`'s AES in
`masking/portable.py` rather than taken from a package, so the exported script needs nothing more
(decision #21).

#### Decrypting outside safetwin

Every encrypted value can be read with standard libraries and the access key alone. The plaintext of
`aes-siv` and `aes-gcm` is a one-byte type tag (`s` text, `i` integer, `d` date, …: the canonical bytes
above) and the value, then `0x80` and zeros up to 16 bytes. In Python, with pyca `cryptography`:

```python
import base64, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESSIV

def hkdf(key: bytes, info: bytes) -> bytes:  # HKDF-SHA-256, no salt, 32 bytes
    return hmac.digest(hmac.digest(bytes(32), key, "sha256"), info + b"\x01", "sha256")

access = bytes.fromhex(open("safetwin-access-key.txt").read().strip())

def plain(token: str) -> bytes:
    raw = base64.urlsafe_b64decode(token[4:] + "=" * (-len(token[4:]) % 4))
    if token.startswith("sg1."):
        padded = AESGCM(hkdf(access, b"safetwin/v1/aes-gcm")).decrypt(raw[:12], raw[12:], None)
    else:  # st1.
        key = hkdf(access, b"safetwin/v1/aes-siv/1") + hkdf(access, b"safetwin/v1/aes-siv/2")
        padded = AESSIV(key).decrypt(raw, None)
    return padded[: padded.rindex(b"\x80")]  # tag + value: b"s" + UTF-8 for text

print(plain("sg1....")[1:].decode())  # a text value
```

For `ff1`, any FF1 implementation (Java, Go, Python…) decrypts with the AES-256 key
`hkdf(access, b"safetwin/v1/ff1")`, radix 10 over the value's digits in order (or radix 62 over
`0-9A-Za-z`), and the column's `domain` as the tweak; the other characters were never changed.

## Security and privacy

safetwin's whole job is to read raw personal data, so its security model is about one thing: the raw
data goes into the masking steps and nowhere else. This document lists what is protected, from whom,
and how, including what safetwin can't protect against.

### Threat model

#### What we protect

| Asset | Why it matters |
|-------|----------------|
| **Raw source data** | Personal data; the reason the tool exists |
| **The masking key** | With it, pseudonyms can be tested against guesses, and date shifts undone |
| **The safe twin** | Pseudonymized columns are still personal data while the key exists ([Pseudonymized is not anonymized](guide.md#pseudonymized-is-not-anonymized)) |
| **Database credentials** | Access to production |
| **The engine's session token** | Control of the local engine |

#### From whom, and how

| Threat | Control |
|--------|---------|
| Raw values left behind in temp files, caches, logs, crash output or the app's own files | [Zero retention](#zero-retention), tested by canary leak tests in CI |
| Raw values shown to people who shouldn't see them | The page's preview shows the output as masked (a kept column shows its values: you chose to keep them), in the answer only, never written ([The page (safetwin ui)](guide.md#the-page-safetwin-ui)) |
| The key leaking through the policy, the report, logs or exported code | Keys are references only; only fingerprints are shown; a `file://` key readable by others is refused ([Keys](security.md#keys)) |
| A web page or another local user driving the engine | The local API's token, Host and Origin checks ([The local servers](#the-local-servers)) |
| A malicious or careless policy file (shared through git) | Policies are data, never code ([Policy files are data, not code](#policy-files-are-data-not-code)) |
| Detection missing a personal-data column | Every column needs an explicit method; unknown columns stop the run; residual scan on the output ([Detection, subsetting and the report](guide.md#detection-subsetting-and-the-report)) |
| Re-identification from what's kept | Classes and quasi-identifier flags in the report; generalization methods; honest docs |
| Writing to production by mistake | Postgres sources are opened read-only; the target must be a different schema or database ([Postgres and Excel](guide.md#postgres-and-excel)) |
| Vulnerable dependencies | A small, pinned dependency set; `pip-audit` in CI |

#### What safetwin can't protect against
- **Malware running as you.** It can read the same files and memory you can.
- **Whoever holds the key.** They can re-link pseudonyms; that's what a key is. Keep it in CI secrets
  or a password manager, and rotate it when people leave.
- **The operating system.** It may write memory to swap, and a crash dump may contain data. Python
  can't pin or wipe memory: strings and bytes are immutable and may be copied. Keys are kept in as few
  places and for as short a time as possible. We say so rather than promise `mlock`-style guarantees.

### Zero retention

safetwin keeps **metadata only**: names, counts, sizes, hashes, settings, error codes. It never keeps
data values.

| Place | Rule |
|-------|------|
| Policy file | Methods and reasons. `scan` never writes a sample value |
| Report | Names, counts, classes, hashes, the key fingerprint. Never a value |
| Logs and error messages | Class names and safetwin's own messages only. Library error text can quote data, so it's never shown |
| Run history (SQLite) | States, times, counts, file paths and checksums, error *codes*. A policy text that looks like it contains a secret isn't stored |
| Temporary files | DuckDB never spills to disk (its file encryption is either insecure or needs a downloaded extension). Each stage worker gets its own 0700 temp folder for `TMPDIR` and `POLARS_TEMP_DIR`, deleted when the worker ends |
| Partial output | Written under temporary names and renamed only when complete; failures and interrupts remove them |
| Staging (Postgres, Excel) | The source's tables copied to Parquet in a 0700 folder of the system's per-user temp folder, removed when the run ends, failed or interrupted included; one left by a crash is removed by a later run after a day. The twin is staged the same way before it is delivered |
| `safetwin ui` | The files you add, and what is made of them, live in a 0700 temp folder removed when you clear a job and when the page stops. The preview is in the answer only. The History tab keeps reports only (`ui-history/` next to the page's key, 0700): names, counts, choices, never a value or a masked file. A key chosen in the page (new, pasted, or from a passphrase) stays in the server's memory: a run gets it in its environment, never in a file, and a new key's hex is in the one answer that made it, for you to save. *Save to a folder* copies only the masked zip, and warns when it holds reversible columns |

**How it's checked:** the tests in `tests/leak/` put unique canary strings in the input data, then run:
- every command;
- every failure path (out of memory, a type error, Ctrl-C, a killed worker, a killed engine);
- the engine and its API.

Then they search every file in the app folder, the home folder, the temp folders and the system temp
and cache folders, plus all console output, API answers and event messages, as UTF-8 and UTF-16.
Self-tests prove the scanner finds a planted canary. Any hit fails CI.

### The local servers

#### The page (`safetwin ui`)

A small FastAPI app of its own (decision #19), on `127.0.0.1` only, on a port the system picks. Tested in
`tests/ui/` and `tests/leak/`.

- **Token:** 256 bits, in the address's fragment (which browsers never send); the page trades it once at
  `POST /api/login` for an HttpOnly, SameSite=Strict cookie, compared in constant time on every API call.
- **Changes need a header:** every call but a GET needs `X-Safetwin: 1`, which another site's form or image
  can't send, so a page elsewhere can't drive it.
- **Host:** must be exactly `127.0.0.1:<port>` or `localhost:<port>` (DNS rebinding).
- **No message holds a value:** an unexpected error answers with its class name only; library errors are
  never passed on. Reports are served with a sandboxing Content-Security-Policy, the page with
  `script-src 'self'`.
- **Files:** names are checked (letters, digits, `. _ - ( )`, a `.csv`, `.parquet` or `.xlsx` ending), and
  every job lives in its own folder of the workspace.

#### The engine API

The background engine (`safetwin engine`, hidden from `--help`) listens on
`127.0.0.1` only, on a random port. Every check below has a test.

- **Token:** a 256-bit token on every request, in an `Authorization` header, compared in constant time.
  It is never accepted from a cookie or a query string.
- **Host:** must be exactly `127.0.0.1:<port>` or `localhost:<port>`. This blocks DNS rebinding.
- **Origin and CORS:** any `Origin` must be the UI's own. CORS allows exactly that origin, and a
  token-less preflight request never reaches a route.
- **WebSocket:** Host and Origin are checked before the connection is accepted. The token must be the
  first message, within 2 s. Sockets that haven't authenticated yet can't crowd out the UI.
- **Limits:** 1 MiB request bodies; head and body timeouts; a connection limit tied to the file
  descriptor limit.
- **Fixed error bodies:** validation errors list where and what, never the input. No access log.
  FastAPI's built-in telemetry is off.
- **Connection file:** the port and token, in a 0600 file inside a 0700 app folder.
  - The CLI refuses the file if another user owns it, if it's readable by others, or if it's a link
    or a FIFO.
  - An app folder chosen through the environment variable is refused, never silently changed, if
    other users can access it.

### Policy files are data, not code

Policies get shared through git, so safetwin treats them as untrusted input:

- **YAML:** loaded with a safe loader: no tags that build objects, no aliases, no duplicate keys.
  Error messages never repeat values from the file.
- **Expressions** (in `where:` filters): an allow-list tokenizer with fixed keywords, functions and
  types, ASCII only. Polars' own SQL expressions can run sub-queries that read files, so they're never
  passed through unchecked.
- **DuckDB** runs locked down: no extensions installed or loaded, no file or network access, settings
  locked, and SQL limited to a single `SELECT`.
- **Inline secrets:** a value that looks like a key or token is rejected, with a hint to use a
  reference.
- **No code execution:** a policy can't run a script, import a module or call the network.

### Cryptography

| Use | Algorithm | Library |
|-----|-----------|---------|
| Pseudonyms, consistent fake values, date shifts, subset selection | HMAC-SHA-256 with per-method, per-domain subkeys from HKDF-SHA-256 | stdlib `hmac`, `hashlib`; pyca `cryptography` |
| Reversible tokens (`encrypt`, opt-in) | AES-256-SIV (RFC 5297), deterministic, under the access key (the default) | pyca `cryptography` |
| Reversible, hiding repeats (`encrypt`, `aes-gcm`) | AES-256-GCM, a random 96-bit nonce per value | pyca `cryptography` |
| Reversible, format-preserving (`encrypt`, `ff1`) | FF1 (NIST SP 800-38G) with AES-256; not authenticated, so the report records the access key's fingerprint and `unmask` refuses another key | `masking/portable.py` on pyca `cryptography`'s AES, checked against NIST's samples |
| A key from a passphrase | scrypt, N = 2¹⁷, r = 8, p = 1, a fixed salt (the same passphrase, the same key, anywhere), at least 12 characters | stdlib `hashlib` |
| File integrity | SHA-256 in manifests and reports | stdlib `hashlib` |
| Randomness (keys, tokens) | OS CSPRNG | stdlib `secrets` |

**Never used:** unkeyed hashes of personal data (reversible by brute force), MD5 or SHA-1 for
security, ECB, FF3/FF3-1. FF1 format-preserving encryption only if a maintained library passes the
NIST test vectors.

## Stability

A safe twin is only useful if the next run joins with the last one: a pseudonym in last month's staging
copy must be the same pseudonym today, and a reversible file masked today must still open next year.
1.0.0 is the final release, so its outputs won't change; this section lists what they are, so that anyone
who forks safetwin knows what not to break. No release has ever changed an output.

### The promise

**Within a major version, the same key, the same policy and the same input give the same twin**, byte for
byte in its values, on every platform and with the exported script as well as with `safetwin mask`. That
covers pseudonyms, fake values, date shifts, generalizations, redactions and encrypted tokens, and the rows
a subset picks.

A test pins it: `tests/masking/test_golden.py` masks a fixed table with a fixed key (`a1` × 32, fingerprint
`ea8427e75815808d`) and compares every method's output, the access key, encrypted tokens and the root rows
a subset picks with values written into the test; `tests/masking/test_algorithms.py` does the same for FF1,
an AES-GCM token and the key of a passphrase.

One exception, on purpose: `encrypt` with `aes-gcm` draws a fresh nonce for every value, so its outputs
differ on every run. What they decrypt to is the same. A change that
moves any of them fails the build; it can only ship in a new major version, with a changelog entry that
says what changed.

### What is fixed

| What | Fixed as | If a fork must change it |
|------|-----------|-------------------------|
| The policy format | `apiVersion: safetwin/v1`: every field and its meaning | New optional fields may be added. A removed field or a changed meaning needs `safetwin/v2`, and 1.x keeps reading `v1` |
| Key derivation | HKDF-SHA-256 subkeys with the info `safetwin/v1/<method>/<domain>`; the access key with `safetwin/v1/access/v1`; the canonical bytes of each type (with their type tags) | A new derivation gets a new version tag (`v2`) beside the old one, never in place of it |
| Method outputs | The pinned values of `test_golden.py`: pseudonyms (`int`, `hex`, `uuid`), fakes, date shifts, generalizations, redactions | Only in a new major version |
| Encrypted tokens | `st1.` + base64url of AES-256-SIV (RFC 5297), `sg1.` + base64url of nonce ‖ AES-256-GCM, over the canonical bytes padded to 16 bytes; their keys `HKDF(access, "safetwin/v1/aes-siv/1"‖"…/2")` and `HKDF(access, "safetwin/v1/aes-gcm")` | A new format gets a new prefix (`st2.`); `unmask` keeps reading the old ones |
| FF1 | AES-256 with `HKDF(access, "safetwin/v1/ff1")`; the alphabets (`0-9`, `0-9A-Za-z`), their minimum lengths (6, 4), the domain as the tweak | Only in a new major version |
| Keys from a passphrase | scrypt N = 2¹⁷, r = 8, p = 1, NFKC UTF-8, the salt `safetwin/v1/passphrase` | A new derivation gets a new name beside the old one |
| Subset selection | The keyed hash that picks root rows, and the closure over parents and children | Only in a new major version |
| `report.json` | Its fields and their meaning, and the column classes (*kept*, *encrypted*, *pseudonymized*, *generalized*, *partially_redacted*, *removed*) | Fields may be added; none is removed or changes meaning |
| The CLI | The commands and options `safetwin --help` lists; exit status 0 (done), 1 (a failed run, check or error), 2 (a usage error) | Options may be added; a removal is announced one minor version ahead with a warning |
| The exported script | It writes the same twin as `safetwin mask` of the same version; it copies `masking/portable.py` word for word, so the promise of section 1 covers it | As the engine |

### Not frozen

- **What `scan` suggests.** Detection gets better; a new version may suggest another method for a column.
  The policy you reviewed is what runs, so this never changes an existing twin.
- **The look of `report.html` and of the `safetwin ui` page**, and the wording of messages.
- **Python imports.** `safetwin.*` modules are internal; the CLI, the policy format and the exported script
  are the interface.
- **The run history** of `safetwin ui` (`ui-history/`) and of `safetwin runs`: a convenience, not evidence
  (decision #14).

### Where it runs

| | Status in 1.0.0 |
|---|---|
| macOS (Apple silicon), Python 3.12 | Tested: every check, the performance gates, the fresh-install quickstart |
| Linux | Tested in a Linux container (Debian, Python 3.12, arm64): the whole test suite, the Postgres tests on the official Postgres 16 image, and the container image's quickstart with an Excel round trip. |
| Windows | Not supported |
| Postgres | 16 tested (embedded, `pgserver`); the queries use only `information_schema` and `pg_catalog` features older versions have too |
| Excel | `.xlsx` (read by calamine, written by xlsxwriter); not `.xls` or `.xlsb` |
