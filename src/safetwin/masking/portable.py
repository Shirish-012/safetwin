"""The portable core of masking: everything that the exported code must do exactly as the engine does.

The engine uses it (`hmacs`, `methods`, `subset`, `run`), and `safetwin export --to polars` copies the code
below the marker line into the exported script word for word, after that script's own imports and the word
lists (`wordlists.py`, also copied). So the code below the marker uses only the standard library, Polars and
the word lists' names, and the engine and an exported script compute the same bytes from the same code:

- the key: HKDF-SHA-256 subkeys and the fingerprint (`safetwin.keys` does the same for the engine, and
  the tests check that the two agree), and reading a key reference with the same checks;
- the canonical bytes of values, and HMAC-SHA-256;
- the pseudonym formats, the fake values, the date-shift offsets, IP networks;
- the expressions of `generalize` and `redact`;
- the subset selection, and the orphan check of a relationship.
"""

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import stat
import struct
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import polars as pl

from .wordlists import (
    AREA_CODES,
    CITIES,
    COMPANY_KINDS,
    COMPANY_SUFFIXES,
    COMPANY_WORDS,
    EMAIL_DOMAINS,
    GIVEN_NAMES,
    LOREM,
    STREET_SUFFIXES,
    STREETS,
    SURNAMES,
)

# --- exported below this line -------------------------------------------------------------------------------

DERIVATION = "safetwin/v1"  # the version tag of every subkey: a change of algorithm gets a new one
_HEX_KEY = re.compile(r"[0-9a-fA-F]{64}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# --- the key (docs/security.md) ----------------------------------------------------------------------------


class KeyProblem(Exception):
    """A key reference that can't be used. The message names the reference, never the key."""


def hkdf_sha256(key: bytes, info: bytes) -> bytes:
    """HKDF-SHA-256 (RFC 5869) without a salt, 32 bytes out: one HMAC to extract, one to expand."""
    prk = hmac.digest(bytes(32), key, "sha256")
    return hmac.digest(prk, info + b"\x01", "sha256")


def read_key(reference: str, environ: Mapping[str, str] | None = None) -> bytes:
    """The 32-byte key that `reference` points at:

    - `env://NAME`: the environment variable NAME holds 64 hexadecimal characters;
    - `file://PATH`: a regular file of this user that no one else can read or change, holding 64
      hexadecimal characters and an optional newline.
    """
    env = os.environ if environ is None else environ
    if reference.startswith("env://"):
        name = reference.removeprefix("env://")
        if not _ENV_NAME.fullmatch(name):
            raise KeyProblem("an env:// key reference names an environment variable: env://NAME")
        text = env.get(name, "").strip()
        if not text:
            raise KeyProblem(f"the environment variable {name} (key: env://{name}) is not set")
        if not _HEX_KEY.fullmatch(text):
            raise KeyProblem(f"the environment variable {name} does not hold 64 hexadecimal characters")
        return bytes.fromhex(text)
    if reference.startswith("file://"):
        path = Path(reference.removeprefix("file://")).expanduser()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
        except OSError as err:
            raise KeyProblem(f"cannot open the key file {path} ({type(err).__name__})") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise KeyProblem(
                    f"the key file {path} must be a regular file of yours that no one else can read or "
                    f"change: run chmod 600 {path}"
                )
            data = os.read(fd, 200).decode("ascii", errors="replace")
        finally:
            os.close(fd)
        body = data[:-1] if data.endswith("\n") else data
        if not _HEX_KEY.fullmatch(body):
            raise KeyProblem(f"the key file {path} does not hold 64 hexadecimal characters")
        return bytes.fromhex(body)
    raise KeyProblem("the key must be a reference, env://NAME or file://PATH, never the key itself")


class Mac:
    """HMAC-SHA-256 with one key (RFC 2104), its inner and outer states computed once and copied per
    message: the same bytes as `hmac.digest`, faster. Its repr shows nothing of the key."""

    __slots__ = ("_inner", "_outer")

    def __init__(self, key: bytes) -> None:
        if len(key) > 64:
            key = hashlib.sha256(key).digest()
        padded = key.ljust(64, b"\0")
        self._inner = hashlib.sha256(bytes(b ^ 0x36 for b in padded))
        self._outer = hashlib.sha256(bytes(b ^ 0x5C for b in padded))

    def digest(self, message: bytes) -> bytes:
        inner = self._inner.copy()
        inner.update(message)
        outer = self._outer.copy()
        outer.update(inner.digest())
        return outer.digest()

    def digests(self, messages: Iterable[bytes]) -> list[bytes]:
        inner_copy, outer_copy = self._inner.copy, self._outer.copy
        out = []
        for message in messages:
            inner = inner_copy()
            inner.update(message)
            outer = outer_copy()
            outer.update(inner.digest())
            out.append(outer.digest())
        return out

    def __repr__(self) -> str:
        return "Mac(<hidden>)"


class Keys:
    """The masking key in memory, and its subkeys: `HKDF-SHA-256(key, info="safetwin/v1/<method>/<domain>")`
    per use. Its repr shows the fingerprint only, `HMAC-SHA-256(key, "safetwin/v1/fingerprint")` cut to 8
    bytes."""

    __slots__ = ("_key", "_macs", "_sealer", "fingerprint")

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise KeyProblem("a key is 32 bytes (64 hexadecimal characters)")
        self._key = key
        self._macs: dict[tuple[str, str], Mac] = {}
        self._sealer: Sealer | None = None
        self.fingerprint = hmac.digest(key, f"{DERIVATION}/fingerprint".encode(), "sha256")[:8].hex()

    def mac(self, method: str, domain: str) -> Mac:
        if (method, domain) not in self._macs:
            subkey = hkdf_sha256(self._key, f"{DERIVATION}/{method}/{domain}".encode())
            self._macs[(method, domain)] = Mac(subkey)
        return self._macs[(method, domain)]

    def sealer(self) -> "Sealer":
        """The `Sealer` of the `encrypt` method, from this key's access key."""
        if self._sealer is None:
            self._sealer = Sealer(access_key(self._key))
        return self._sealer

    def __repr__(self) -> str:
        return f"Keys(fingerprint={self.fingerprint})"


def access_key(key: bytes) -> bytes:
    """The access key of a masking key: `HKDF-SHA-256(key, "safetwin/v1/access/v1")`. It reads the columns
    that `encrypt` masked and nothing else: from it, the masking key (and so the pseudonyms) can't be
    found."""
    return hkdf_sha256(key, f"{DERIVATION}/access/v1".encode())


# --- canonical bytes ----------------------------------------------------------------------------------------

_INT64_MIN, _INT64_MAX = -(1 << 63), (1 << 63) - 1
_EPOCH_DAY = date(1970, 1, 1).toordinal()
_EPOCH = datetime(1970, 1, 1)
_NAN = bytes.fromhex("7ff8000000000000")


def is_text(dtype: pl.DataType) -> bool:
    """String, Categorical or Enum: text as far as the methods are concerned."""
    return dtype == pl.String or isinstance(dtype, pl.Categorical | pl.Enum)


def as_text(series: pl.Series) -> pl.Series:
    """A Categorical or Enum column as String (every method works on their text); others as they are."""
    return series.cast(pl.String) if is_text(series.dtype) and series.dtype != pl.String else series


def _datetime_bytes(v: datetime) -> bytes:
    if v.tzinfo is not None:
        v = v.astimezone(UTC).replace(tzinfo=None)
    delta = v - _EPOCH
    micros = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    return b"t" + micros.to_bytes(8, "big", signed=True)


def _time_bytes(v: time) -> bytes:
    micros = ((v.hour * 60 + v.minute) * 60 + v.second) * 1_000_000 + v.microsecond
    return b"T" + micros.to_bytes(8, "big", signed=True)


def _float_bytes(v: float) -> bytes:
    if v != v:  # NaN
        return b"f" + _NAN
    return b"f" + struct.pack(">d", v + 0.0)  # -0.0 + 0.0 is 0.0


def _decimal_bytes(v: Decimal) -> bytes:
    return b"n" + ("0" if v == 0 else format(v.normalize(), "f")).encode("ascii")


def canonical(values: Sequence[Any], dtype: pl.DataType) -> list[bytes]:
    """The canonical bytes of non-null `values` of a column of type `dtype`: a one-byte type tag, then the
    value in a fixed format, so `"42"` and `42` never collide by accident. The formats are fixed: changing
    one would change every pseudonym made from that type.

    - `i` integer in the int64 range: 8 bytes, big-endian two's complement;
    - `u` unsigned integer above the int64 range: 8 bytes, big-endian unsigned;
    - `s` text (String, Categorical, Enum): UTF-8;
    - `x` binary: the bytes themselves;
    - `d` date: 4 bytes, big-endian signed, days since 1970-01-01;
    - `t` datetime: 8 bytes, big-endian signed, microseconds since 1970-01-01T00:00 UTC. A value with a
      time zone is converted to UTC first, so the same instant gives the same bytes in every zone; a naive
      value is taken as it is. Nanoseconds are truncated to the microsecond (floor);
    - `T` time: 8 bytes, big-endian signed, microseconds since midnight;
    - `b` boolean: one byte, 1 or 0;
    - `f` float: 8 bytes, IEEE 754 binary64 big-endian; `-0.0` is written as `0.0`, every NaN as
      `7ff8000000000000`;
    - `n` decimal: ASCII text with no exponent and no trailing zeros (`1.10` is `1.1`, `10.0` is `10`), and
      `-0` is `0`;
    - `o` anything else: the value's `str()` in UTF-8 (not stable: avoid keyed methods on such columns).
    """
    if dtype.is_integer():
        return [
            b"i" + v.to_bytes(8, "big", signed=True)
            if _INT64_MIN <= v <= _INT64_MAX
            else b"u" + v.to_bytes(8, "big", signed=False)
            for v in values
        ]
    if is_text(dtype):
        return [b"s" + v.encode("utf-8") for v in values]
    if dtype == pl.Binary:
        return [b"x" + bytes(v) for v in values]
    if dtype == pl.Date:
        return [b"d" + (v.toordinal() - _EPOCH_DAY).to_bytes(4, "big", signed=True) for v in values]
    if isinstance(dtype, pl.Datetime):
        return [_datetime_bytes(v) for v in values]
    if dtype == pl.Time:
        return [_time_bytes(v) for v in values]
    if dtype == pl.Boolean:
        return [b"b\x01" if v else b"b\x00" for v in values]
    if dtype.is_float():
        return [_float_bytes(float(v)) for v in values]
    if isinstance(dtype, pl.Decimal):
        return [_decimal_bytes(Decimal(v)) for v in values]
    return [b"o" + str(v).encode("utf-8") for v in values]


def per_distinct(
    series: pl.Series, compute: Callable[[list[Any]], list[Any] | pl.Series], dtype: pl.DataType
) -> pl.Series:
    """`compute` once per distinct non-null value of `series`, mapped back onto it. Nulls stay null."""
    distinct = series.drop_nulls().unique()
    if distinct.len() == 0:
        return pl.Series(series.name, [None] * series.len(), dtype=dtype)
    computed = compute(distinct.to_list())
    outputs = computed.cast(dtype) if isinstance(computed, pl.Series) else pl.Series(computed, dtype=dtype)
    return series.replace_strict(distinct, outputs, return_dtype=dtype).alias(series.name)


def keyed(series: pl.Series, mac: Mac, make: Callable[[bytes], Any], dtype: pl.DataType) -> pl.Series:
    """`make(HMAC of the canonical bytes)` for every distinct non-null value of `series`."""
    series = as_text(series)
    source = series.dtype
    return per_distinct(
        series, lambda values: [make(h) for h in mac.digests(canonical(values, source))], dtype
    )


# --- pseudonymize -------------------------------------------------------------------------------------------

BASE32 = "abcdefghijklmnopqrstuvwxyz234567"  # RFC 4648 base32, lower case


def int_pseudonym(h: bytes) -> int:
    """The top 63 bits of the first 8 bytes of the HMAC, big-endian: never negative."""
    return int.from_bytes(h[:8], "big") >> 1


def hex_pseudonym(h: bytes, prefix: str = "") -> str:
    """`prefix` and the unpadded lower-case base32 of the first 16 bytes of the HMAC (26 characters)."""
    return prefix + base64.b32encode(h[:16]).decode("ascii").rstrip("=").lower()


def uuid_pseudonym(h: bytes) -> bytes:
    """The first 16 bytes of the HMAC as a UUID of version 8 (variant 10)."""
    b = bytearray(h[:16])
    b[6] = (b[6] & 0x0F) | 0x80
    b[8] = (b[8] & 0x3F) | 0x80
    return bytes(b)


def pseudonymize_series(series: pl.Series, mac: Mac, fmt: str, prefix: str = "") -> pl.Series:
    """`fmt` is int, hex or uuid (a UUID column of binary type gets bytes, any other its text)."""
    if fmt == "int":
        return keyed(series, mac, int_pseudonym, pl.Int64())
    if fmt == "hex":
        return keyed(series, mac, lambda h: hex_pseudonym(h, prefix), pl.String())
    if series.dtype == pl.Binary:
        return keyed(series, mac, uuid_pseudonym, pl.Binary())
    return keyed(series, mac, lambda h: str(uuid.UUID(bytes=uuid_pseudonym(h))), pl.String())


# --- fake ---------------------------------------------------------------------------------------------------


def _pick(words: Sequence[Any], h: bytes, i: int) -> Any:
    return words[int.from_bytes(h[2 * i : 2 * i + 2], "big") % len(words)]


def fake_value(h: bytes, kind: str) -> str:
    """A fake value of `kind`, picked deterministically from the 32 bytes `h`."""
    first, last = _pick(GIVEN_NAMES, h, 0), _pick(SURNAMES, h, 1)
    match kind:
        case "name":
            return f"{first} {last}"
        case "first_name":
            return str(first)
        case "last_name":
            return str(last)
        case "email":  # 30 more bits in the local part, so a unique column stays unique at scale
            tag = int.from_bytes(h[12:16], "big") >> 2
            suffix = "".join(BASE32[(tag >> (25 - 5 * i)) & 31] for i in range(6))
            return f"{first.lower()}.{last.lower()}.{suffix}@{EMAIL_DOMAINS[h[5] % 3]}"
        case "phone":
            return f"+1 {_pick(AREA_CODES, h, 3)} 555-01{h[8] % 100:02d}"
        case "street":
            number = 1 + int.from_bytes(h[9:11], "big") % 9999
            return f"{number} {_pick(STREETS, h, 6)} {_pick(STREET_SUFFIXES, h, 7)}"
        case "city":
            return str(_pick(CITIES, h, 8))
        case "company":
            word, kind_word = _pick(COMPANY_WORDS, h, 9), _pick(COMPANY_KINDS, h, 10)
            return f"{word} {kind_word} {_pick(COMPANY_SUFFIXES, h, 11)}"
    more = h + hashlib.sha256(h).digest()  # text: 6 to 12 words
    count = 6 + more[24] % 7
    words = [LOREM[int.from_bytes(more[26 + 2 * i : 28 + 2 * i], "big") % len(LOREM)] for i in range(count)]
    return " ".join(words).capitalize() + "."


def fake_series(series: pl.Series, kind: str, mac: Mac | None) -> pl.Series:
    """Consistent (`mac` given): one fake value per distinct input, nulls stay null. Random (`mac` None): a
    fresh value for every row, nulls included."""
    if mac is not None:
        return keyed(series, mac, lambda h: fake_value(h, kind), pl.String())
    raw = secrets.token_bytes(32 * series.len())
    out = [fake_value(raw[i : i + 32], kind) for i in range(0, len(raw), 32)]
    return pl.Series(series.name, out, dtype=pl.String)


# --- generalize, redact -------------------------------------------------------------------------------------

TRUNCATE = {"year": "1y", "month": "1mo", "week": "1w", "day": "1d"}


def bucket_expr(x: pl.Expr, bucket: float, integer: bool) -> pl.Expr:
    """The lower bound of the bucket of width `bucket` that holds the value."""
    return (x // bucket) * bucket if integer else (x / bucket).floor() * bucket


def bins_expr(x: pl.Expr, bins: Sequence[float]) -> pl.Expr:
    """The lower bound of the bin that holds the value; a value below the first bin gets the first bin."""
    chain: Any = pl.when(x >= bins[-1]).then(pl.lit(bins[-1]))
    for b in reversed(bins[:-1]):
        chain = chain.when(x >= b).then(pl.lit(b))
    return pl.when(x.is_null()).then(None).otherwise(chain.otherwise(pl.lit(bins[0])))


def ip_network(text: str) -> str | None:
    """The /24 (IPv4) or /48 (IPv6) network of an address, None if it isn't one."""
    try:
        address = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False).network_address)


def ip_networks(series: pl.Series) -> pl.Series:
    return per_distinct(as_text(series), lambda values: [ip_network(v) for v in values], pl.String())


def redact_expr(
    x: pl.Expr,
    *,
    keep_last: int | None = None,
    keep_first: int | None = None,
    char: str = "*",
    with_: str | None = None,
) -> pl.Expr:
    """Text out. A value no longer than what is kept is masked whole: keeping it would show all of it."""
    x = x.cast(pl.String)
    if with_ is not None:
        return pl.when(x.is_not_null()).then(pl.lit(with_)).otherwise(None)
    n = x.str.len_chars()
    whole = pl.lit("", dtype=pl.String).str.pad_start(n, char)
    if keep_last is not None:
        keep = keep_last
        partial = x.str.slice(-keep, keep).str.pad_start(n, char) if keep else whole
    else:
        keep = keep_first or 0
        partial = x.str.slice(0, keep).str.pad_end(n, char) if keep else whole
    return pl.when(x.is_null()).then(None).when(n <= keep).then(whole).otherwise(partial)


# --- date_shift ---------------------------------------------------------------------------------------------


def shift_days(h: bytes, max_days: int) -> int:
    """An offset uniform in [-max_days, +max_days] without 0, from an HMAC."""
    r = int.from_bytes(h[:8], "big") % (2 * max_days)
    return r - max_days if r < max_days else r - max_days + 1


def date_offsets(entity: pl.Series, mac: Mac, max_days: int) -> pl.Series:
    """The shift in days of every row, from its entity's value (null for a null entity)."""
    return keyed(entity, mac, lambda h: shift_days(h, max_days), pl.Int64())


def shift_dates(dates: pl.Series, offsets: pl.Series) -> pl.Series:
    frame = pl.DataFrame({"d": dates, "o": offsets})
    shifted = (pl.col("d") + pl.duration(days=pl.col("o"))).cast(dates.dtype)
    return frame.select(shifted.alias(dates.name)).to_series()


# --- encrypt: the reversible method -------------------------------------------------------------------------

SEALED = "st1."  # the prefix of every value encrypted with AES-SIV: safetwin, format 1
SEALED_PATTERN = r"^st1\.[A-Za-z0-9_-]{43,}$"  # at least 32 bytes: the 16-byte SIV and one 16-byte block
SEALED_RANDOM = "sg1."  # the prefix of every value encrypted with AES-GCM
SEALED_RANDOM_PATTERN = r"^sg1\.[A-Za-z0-9_-]{59,}$"  # at least 44 bytes: nonce, one block and the tag
ALGORITHMS = ("aes-siv", "aes-gcm", "ff1")
# FF1's alphabets, and the fewest characters of the alphabet a value must have: NIST SP 800-38G asks for
# radix ** minlen >= 1,000,000, so a shorter value is not encrypted (it is emptied, and the report says so).
FF1_ALPHABETS = {
    "digits": "0123456789",
    "alphanumeric": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
}
FF1_MIN = {"digits": 6, "alphanumeric": 4}


class SealProblem(Exception):
    """Values that can't be decrypted: the wrong key, or a changed file. The message holds no value."""


class Sealer:
    """The ciphers of the `encrypt` method, with keys made from the access key by HKDF-SHA-256. Its repr
    shows the access key's fingerprint only.

    - `aes-siv` (the default; `seal`): AES-256-SIV (RFC 5297) with the 64-byte key
      `HKDF(access, "safetwin/v1/aes-siv/1") || HKDF(access, "safetwin/v1/aes-siv/2")`. Deterministic: equal
      values give equal ciphertexts (in every column and table), so relationships and unique columns
      survive, and anyone can see which values are equal.
    - `aes-gcm` (`seal_random`): AES-256-GCM with the key `HKDF(access, "safetwin/v1/aes-gcm")` and a random
      96-bit nonce per value, so equal values give different ciphertexts: nothing shows which are equal, and
      such a column can't join. Any AES-GCM library decrypts it (docs/guide.md).
    - `ff1` (`ff1`): FF1 format-preserving encryption (NIST SP 800-38G) with AES-256 and the key
      `HKDF(access, "safetwin/v1/ff1")`: a value keeps its length and every character outside the alphabet.

    AES-SIV and AES-GCM are authenticated (a changed value fails to decrypt rather than giving a wrong one),
    and their plaintext is padded to a multiple of 16 bytes, so a ciphertext shows the length of its value
    only to within 16 bytes. FF1 is neither: it keeps the length, and any value of the format decrypts."""

    __slots__ = ("_access", "_ff1", "_gcm", "_siv", "fingerprint")

    def __init__(self, access: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESSIV  # only an `encrypt` needs it

        if len(access) != 32:
            raise KeyProblem("an access key is 32 bytes (64 hexadecimal characters)")
        one = hkdf_sha256(access, f"{DERIVATION}/aes-siv/1".encode())
        two = hkdf_sha256(access, f"{DERIVATION}/aes-siv/2".encode())
        self._siv = AESSIV(one + two)
        self._access = access
        self._gcm: Any = None
        self._ff1: FF1 | None = None
        self.fingerprint = hmac.digest(access, f"{DERIVATION}/fingerprint".encode(), "sha256")[:8].hex()

    def seal(self, plain: bytes) -> str:
        sealed = self._siv.encrypt(_pad(plain), None)
        return SEALED + base64.urlsafe_b64encode(sealed).decode("ascii").rstrip("=")

    def seal_random(self, plain: bytes) -> str:
        nonce = os.urandom(12)
        sealed = nonce + self._aes_gcm().encrypt(nonce, _pad(plain), None)
        return SEALED_RANDOM + base64.urlsafe_b64encode(sealed).decode("ascii").rstrip("=")

    def open(self, token: str) -> bytes | None:
        """The plaintext of `token` (AES-SIV or AES-GCM), or None if it isn't one this key made (or it was
        changed)."""
        from cryptography.exceptions import InvalidTag

        prefix = token[: len(SEALED)]
        if prefix not in (SEALED, SEALED_RANDOM):
            return None
        body = token[len(prefix) :]
        try:
            sealed = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            if prefix == SEALED:
                padded = self._siv.decrypt(sealed, None)
            else:
                padded = self._aes_gcm().decrypt(sealed[:12], sealed[12:], None)
        except (InvalidTag, ValueError):
            return None
        end = padded.rfind(b"\x80")
        if end < 0 or any(padded[end + 1 :]):
            return None
        return padded[:end]

    def ff1(self) -> "FF1":
        if self._ff1 is None:
            self._ff1 = FF1(hkdf_sha256(self._access, f"{DERIVATION}/ff1".encode()))
        return self._ff1

    def _aes_gcm(self) -> Any:
        if self._gcm is None:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            self._gcm = AESGCM(hkdf_sha256(self._access, f"{DERIVATION}/aes-gcm".encode()))
        return self._gcm

    def __repr__(self) -> str:
        return f"Sealer(fingerprint={self.fingerprint})"


def _pad(plain: bytes) -> bytes:
    """ISO/IEC 7816-4 padding to a multiple of 16 bytes: 0x80, then zeros."""
    return plain + b"\x80" + bytes(-(len(plain) + 1) % 16)


class FF1:
    """FF1 (NIST SP 800-38G, section 6.2) with AES-256, for many numeral strings at once: the strings of one
    length share the first block of every PRF, so each step of each round is one call of the block cipher
    for the whole group, not one per string."""

    __slots__ = ("_cipher",)

    def __init__(self, key: bytes) -> None:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        # ECB here is the block cipher itself, one block per string: FF1 chains the blocks (a CBC-MAC).
        self._cipher = Cipher(algorithms.AES(key), modes.ECB())

    def encrypt(self, strings: Sequence[Sequence[int]], radix: int, tweak: bytes) -> list[list[int]]:
        return self._run(strings, radix, tweak, decrypt=False)

    def decrypt(self, strings: Sequence[Sequence[int]], radix: int, tweak: bytes) -> list[list[int]]:
        return self._run(strings, radix, tweak, decrypt=True)

    def _blocks(self, data: bytes) -> bytes:
        encryptor = self._cipher.encryptor()
        return bytes(encryptor.update(data) + encryptor.finalize())

    def _run(
        self, strings: Sequence[Sequence[int]], radix: int, tweak: bytes, *, decrypt: bool
    ) -> list[list[int]]:
        out: list[list[int]] = [[] for _ in strings]
        groups: dict[int, list[int]] = {}
        for i, numerals in enumerate(strings):
            groups.setdefault(len(numerals), []).append(i)
        for n, members in groups.items():
            done = self._group([strings[i] for i in members], n, radix, tweak, decrypt)
            for i, numerals in zip(members, done, strict=True):
                out[i] = numerals
        return out

    def _group(
        self, strings: Sequence[Sequence[int]], n: int, radix: int, tweak: bytes, decrypt: bool
    ) -> list[list[int]]:
        if n < 2:
            raise ValueError("FF1 needs at least 2 numerals")
        u, v, t = n // 2, n - n // 2, len(tweak)
        b = ((radix**v - 1).bit_length() + 7) // 8  # ceil(ceil(v * log2(radix)) / 8)
        d = 4 * ((b + 3) // 4) + 4
        p = bytes([1, 2, 1]) + radix.to_bytes(3, "big") + bytes([10, u % 256]) + n.to_bytes(4, "big")
        p += t.to_bytes(4, "big")
        head = self._blocks(p)  # the CBC-MAC after P: the same for every string of this length and tweak
        zeros = bytes((-t - b - 1) % 16)
        a = [_num(s[:u], radix) for s in strings]
        bb = [_num(s[u:], radix) for s in strings]
        for i in range(9, -1, -1) if decrypt else range(10):
            q = [tweak + zeros + bytes([i]) + x.to_bytes(b, "big") for x in (a if decrypt else bb)]
            y = self._prf(head, q, d)
            m = radix ** (u if i % 2 == 0 else v)
            if decrypt:
                a, bb = [(x - yy) % m for x, yy in zip(bb, y, strict=True)], a
            else:
                a, bb = bb, [(x + yy) % m for x, yy in zip(a, y, strict=True)]
        return [_str(x, u, radix) + _str(z, v, radix) for x, z in zip(a, bb, strict=True)]

    def _prf(self, head: bytes, qs: list[bytes], d: int) -> list[int]:
        """`NUM(S)` of every Q: R = PRF(P || Q) (a CBC-MAC that starts from `head`), then S, `d` bytes of
        R || CIPH(R xor [1]) || CIPH(R xor [2]) ..."""
        state = [head] * len(qs)
        for j in range(0, len(qs[0]), 16):
            state = _split(
                self._blocks(b"".join(_xor(s, q[j : j + 16]) for s, q in zip(state, qs, strict=True)))
            )
        s = list(state)
        for j in range(1, (d + 15) // 16):
            more = _split(self._blocks(b"".join(_xor(r, j.to_bytes(16, "big")) for r in state)))
            s = [x + y for x, y in zip(s, more, strict=True)]
        return [int.from_bytes(x[:d], "big") for x in s]


def _xor(a: bytes, b: bytes) -> bytes:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(16, "big")


def _split(data: bytes) -> list[bytes]:
    return [data[i : i + 16] for i in range(0, len(data), 16)]


def _num(numerals: Sequence[int], radix: int) -> int:
    value = 0
    for x in numerals:
        value = value * radix + x
    return value


def _str(value: int, length: int, radix: int) -> list[int]:
    out = [0] * length
    for i in range(length - 1, -1, -1):
        value, out[i] = divmod(value, radix)
    return out


def ff1_texts(
    values: Sequence[str], cipher: FF1, alphabet: str, tweak: bytes, *, decrypt: bool = False
) -> list[str | None]:
    """Each text with the characters of `alphabet` encrypted (or decrypted) by FF1 as one numeral string,
    every other character in its place. None for a text with fewer than `FF1_MIN[alphabet]` of them."""
    chars = FF1_ALPHABETS[alphabet]
    index = {c: i for i, c in enumerate(chars)}
    places = [[i for i, c in enumerate(v) if c in index] for v in values]
    ok = [k for k, where in enumerate(places) if len(where) >= FF1_MIN[alphabet]]
    run = cipher.decrypt if decrypt else cipher.encrypt
    done = run([[index[values[k][i]] for i in places[k]] for k in ok], len(chars), tweak)
    out: list[str | None] = [None] * len(values)
    for k, numerals in zip(ok, done, strict=True):
        text = list(values[k])
        for i, x in zip(places[k], numerals, strict=True):
            text[i] = chars[x]
        out[k] = "".join(text)
    return out


def plain_bytes(values: Sequence[Any], dtype: pl.DataType) -> list[bytes]:
    """What `encrypt` encrypts: the canonical bytes of the values, except that a datetime with a time zone
    gets the tag `z` (UTC microseconds), so that decryption gives it back with its zone (as UTC)."""
    if isinstance(dtype, pl.Datetime) and dtype.time_zone is not None:
        return [b"z" + _datetime_bytes(v)[1:] for v in values]
    return canonical(values, dtype)


def plain_value(plain: bytes) -> tuple[str, Any]:
    """The tag and the value of `plain_bytes`. Raises `ValueError` on bytes it didn't make."""
    tag, body = chr(plain[0]), plain[1:]
    match tag:
        case "i":
            return tag, int.from_bytes(body, "big", signed=True)
        case "u":
            return tag, int.from_bytes(body, "big", signed=False)
        case "s":
            return tag, body.decode("utf-8")
        case "x":
            return tag, bytes(body)
        case "d":
            return tag, date.fromordinal(int.from_bytes(body, "big", signed=True) + _EPOCH_DAY)
        case "t" | "z":
            micros = int.from_bytes(body, "big", signed=True)
            value = _EPOCH + timedelta(microseconds=micros)
            return tag, value.replace(tzinfo=UTC) if tag == "z" else value
        case "T":
            micros = int.from_bytes(body, "big", signed=True)
            return tag, (datetime.min + timedelta(microseconds=micros)).time()
        case "b":
            return tag, body == b"\x01"
        case "f":
            return tag, struct.unpack(">d", body)[0]
        case "n":
            return tag, Decimal(body.decode("ascii"))
    raise ValueError(f"no value has the tag {tag!r}")


# The column type of the values of each tag, when a column is decrypted (`i` and `u`: whatever holds them).
PLAIN_DTYPES: dict[str, Any] = {
    "s": pl.String(),
    "x": pl.Binary(),
    "d": pl.Date(),
    "t": pl.Datetime("us"),
    "z": pl.Datetime("us", "UTC"),
    "T": pl.Time(),
    "b": pl.Boolean(),
    "f": pl.Float64(),
}


def encrypt_series(
    series: pl.Series,
    sealer: Sealer,
    algorithm: str = "aes-siv",
    alphabet: str = "digits",
    domain: str | None = None,
) -> pl.Series:
    """The column encrypted, as text; nulls stay null. `aes-siv` and `ff1` encrypt every distinct value once
    (`ff1`: a text column, the `domain` as its tweak; a value too short for it becomes null); `aes-gcm`
    encrypts every value with a nonce of its own."""
    series = as_text(series)
    source = series.dtype
    if algorithm == "ff1":
        tweak = (domain or "").encode()
        return per_distinct(
            series, lambda values: ff1_texts(values, sealer.ff1(), alphabet, tweak), pl.String()
        )
    if algorithm == "aes-gcm":
        values = series.to_list()
        present = [i for i, v in enumerate(values) if v is not None]
        tokens: list[str | None] = [None] * len(values)
        for i, plain in zip(present, plain_bytes([values[i] for i in present], source), strict=True):
            tokens[i] = sealer.seal_random(plain)
        return pl.Series(series.name, tokens, dtype=pl.String())
    return per_distinct(
        series, lambda values: [sealer.seal(p) for p in plain_bytes(values, source)], pl.String()
    )


def is_sealed(series: pl.Series) -> bool:
    """A text column with at least one value, every one of which looks encrypted by AES-SIV or AES-GCM
    (FF1's values look like any others: `unmask` learns those columns from the report)."""
    if not is_text(series.dtype):
        return False
    values = as_text(series).drop_nulls()
    pattern = f"{SEALED_PATTERN}|{SEALED_RANDOM_PATTERN}"
    return values.len() > 0 and bool(values.str.contains(pattern).all())


def decrypt_ff1_series(
    series: pl.Series, sealer: Sealer, alphabet: str, domain: str | None = None
) -> pl.Series:
    """A column that `ff1` encrypted, back to its text. Raises `SealProblem` (with a count) when some values
    are too short to be FF1's."""
    series = as_text(series)
    tweak = (domain or "").encode()
    out = per_distinct(
        series, lambda values: ff1_texts(values, sealer.ff1(), alphabet, tweak, decrypt=True), pl.String()
    )
    short = int((out.is_null() & series.is_not_null()).sum())
    if short:
        raise SealProblem(f"{short:,} value(s) are too short to have been encrypted with ff1 ({alphabet})")
    return out


def decrypt_series(series: pl.Series, sealer: Sealer) -> pl.Series:
    """An encrypted column back to its values and type. Raises `SealProblem` (with a count, never a value)
    when some values don't decrypt with this key or don't share one type."""
    distinct = as_text(series).drop_nulls().unique().to_list()
    plains = [sealer.open(token) for token in distinct]
    failed = sum(1 for p in plains if p is None)
    if failed:
        raise SealProblem(
            f"{failed:,} distinct value(s) don't decrypt with this key (another key, or changed)"
        )
    try:
        decoded = [plain_value(p) for p in plains if p is not None]
    except (ValueError, UnicodeDecodeError, struct.error):
        raise SealProblem("some values decrypt to bytes that no safetwin value has") from None
    tags = {tag for tag, _ in decoded}
    if len(tags - {"i", "u"}) > 1 or (tags & {"i", "u"} and tags - {"i", "u"}):
        raise SealProblem(f"the values have {len(tags)} different types: a column has one")
    dtype = PLAIN_DTYPES.get(next(iter(tags))) if tags else pl.String()
    values = pl.Series([v for _, v in decoded], dtype=dtype, strict=False)
    if not distinct:
        return pl.Series(series.name, [None] * series.len(), dtype=pl.String())
    lookup = pl.Series(distinct, dtype=pl.String())
    return as_text(series).replace_strict(lookup, values, return_dtype=values.dtype).alias(series.name)


# --- subset (docs/guide.md) -----------------------------------------------------------------------------

Relationship = tuple[str, str, str, str]  # (from table, from column, to table, to column)


def picked(values: pl.Series, mac: Mac, fraction: float) -> pl.Series:
    """The distinct non-null `values` whose HMAC, read as a 64-bit number, is below `fraction` * 2^64."""
    distinct = values.drop_nulls().unique()
    if distinct.len() == 0:
        return distinct
    threshold = round(fraction * (1 << 64))
    keep = [
        int.from_bytes(h[:8], "big") < threshold
        for h in mac.digests(canonical(distinct.to_list(), distinct.dtype))
    ]
    return distinct.filter(pl.Series(keep, dtype=pl.Boolean))


def subset_columns(root: str, key: str, relationships: Sequence[Relationship]) -> dict[str, list[str]]:
    """The tables connected to `root` through relationships, with the columns the selection reads of each."""
    connected, todo = {root}, [root]
    while todo:
        table = todo.pop()
        for a, _, b, _ in relationships:
            for here, there in ((a, b), (b, a)):
                if here == table and there not in connected:
                    connected.add(there)
                    todo.append(there)
    columns: dict[str, set[str]] = {t: set() for t in connected}
    columns[root].add(key)
    for a, ac, b, bc in relationships:
        if a in connected:
            columns[a].add(ac)
            columns[b].add(bc)
    return {t: sorted(cs) for t, cs in sorted(columns.items())}


def _values(frame: pl.DataFrame, mask: pl.Series, column: str, dtype: pl.DataType) -> pl.Series:
    """The distinct non-null values of `column` in the rows of `mask`, as `dtype`."""
    return frame.get_column(column).filter(mask).drop_nulls().unique().cast(dtype, strict=False).drop_nulls()


def subset_filters(
    frames: Mapping[str, pl.DataFrame],
    root: str,
    key: str,
    fraction: float,
    include_children: bool,
    relationships: Sequence[Relationship],
    mac: Mac,
) -> tuple[dict[str, pl.Expr], int]:
    """The row filter of every table in `frames` (the tables of `subset_columns`, with those columns), and
    the number of root rows picked.

    1. Root rows: those whose key is `picked`.
    2. Parents, always: the rows a selected row points at, so every reference still finds its row.
    3. Children, with `include_children`: the rows that point at a row reached *downward* (a root row, or a
       child of one). Rows pulled in only as parents don't bring their children, or one shared parent (a
       product, a country) would bring in the whole child table.

    Steps 2 and 3 repeat until nothing changes, so cycles and self-references end too. Every reason a row
    is in is a test of one of its columns against a set of values, so the filter of a table is the OR of
    those tests. The value sets are data: they stay in memory.
    """
    rels = [r for r in relationships if r[0] in frames]
    dtype = {(t, c): f.schema[c] for t, f in frames.items() for c in f.columns}
    roots = picked(frames[root].get_column(key), mac, fraction)
    down = {t: pl.Series([False] * f.height, dtype=pl.Boolean) for t, f in frames.items()}
    down[root] = frames[root].get_column(key).is_in(roots.implode()).fill_null(False)
    selected = dict(down)
    changed = True
    while changed:
        changed = False
        for child_t, child_c, parent_t, parent_c in rels:
            child, parent = frames[child_t], frames[parent_t]
            wanted = _values(child, selected[child_t], child_c, dtype[(parent_t, parent_c)])
            grown = selected[parent_t] | parent.get_column(parent_c).is_in(wanted.implode()).fill_null(False)
            if grown.sum() != selected[parent_t].sum():
                selected[parent_t], changed = grown, True
            if include_children:
                keys = _values(parent, down[parent_t], parent_c, dtype[(child_t, child_c)])
                hit = child.get_column(child_c).is_in(keys.implode()).fill_null(False)
                if (down[child_t] | hit).sum() != down[child_t].sum():
                    down[child_t], changed = down[child_t] | hit, True
                if (selected[child_t] | hit).sum() != selected[child_t].sum():
                    selected[child_t], changed = selected[child_t] | hit, True
    tests: dict[str, list[pl.Expr]] = {t: [] for t in frames}
    tests[root].append(pl.col(key).is_in(roots.cast(dtype[(root, key)]).implode()))
    for child_t, child_c, parent_t, parent_c in rels:
        wanted = _values(frames[child_t], selected[child_t], child_c, dtype[(parent_t, parent_c)])
        tests[parent_t].append(pl.col(parent_c).is_in(wanted.implode()))
        if include_children:
            keys = _values(frames[parent_t], down[parent_t], parent_c, dtype[(child_t, child_c)])
            tests[child_t].append(pl.col(child_c).is_in(keys.implode()))
    filters = {t: pl.any_horizontal(ts).fill_null(False) if ts else pl.lit(False) for t, ts in tests.items()}
    return filters, int(down[root].sum())


def orphans(child: pl.LazyFrame, column: str, parent: pl.LazyFrame, parent_column: str) -> int:
    """The rows of `child` whose `column` is not null and matches no `parent_column` of `parent`."""
    left = child.select(pl.col(column).alias("k")).drop_nulls()
    dtype = left.collect_schema()["k"]
    right = parent.select(pl.col(parent_column).cast(dtype, strict=False).alias("k")).drop_nulls().unique()
    return int(left.join(right, on="k", how="anti").select(pl.len()).collect(engine="streaming").item())
