"""The masking methods (docs/guide.md) on one batch of one column: a Polars Series in, a Series out.

Nulls stay null under every method except `fake` with `consistent: false`. The keyed methods
(`pseudonymize`, consistent `fake`, `date_shift`) are dictionary-encoded: the HMAC is computed once per
distinct value of the batch and mapped back with `replace_strict`. Nothing here logs or keeps a value; what a
method counts (values below the first bin, invalid IPs, dates without an entity) goes to a `MaskStats`.
"""

import re
import threading
from typing import Any, cast

import polars as pl
import pyarrow as pa

from safetwin.spec.policy import Encrypt, Fake, Generalize, Pseudonymize, Redact

from .portable import (
    SEALED_PATTERN,
    SEALED_RANDOM_PATTERN,
    TRUNCATE,
    Mac,
    Sealer,
    bins_expr,
    bucket_expr,
    canonical,
    date_offsets,
    encrypt_series,
    fake_series,
    ip_networks,
    is_text,
    per_distinct,
    pseudonymize_series,
    redact_expr,
    shift_dates,
)

# Bits of an integer pseudonym (docs/guide.md: 63). A test lowers it to force collisions; nothing else may.
INT_BITS = 63


class MaskStats:
    """Counts per column and reason (`below_first_bin`, `invalid_ip`, `null_entity`), from any thread."""

    def __init__(self) -> None:
        self._counts: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()

    def add(self, column: str, reason: str, count: int) -> None:
        if count:
            with self._lock:
                per = self._counts.setdefault(column, {})
                per[reason] = per.get(reason, 0) + count

    def snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {column: dict(reasons) for column, reasons in self._counts.items()}


def _words(digests: list[bytes], count: int) -> list[pl.Series]:
    """The first `count` big-endian 64-bit words of every digest, as UInt64 Series (one per word), computed in
    Arrow and Polars rather than value by value in Python."""
    joined = b"".join([h[: 8 * count] for h in digests])
    array = pa.Array.from_buffers(pa.binary(8), count * len(digests), [None, pa.py_buffer(joined)])
    words = (
        cast("pl.Series", pl.from_arrow(array))
        .cast(pl.Binary)
        .bin.reinterpret(dtype=pl.UInt64, endianness="big")
    )
    return [words.gather_every(count, offset=i) for i in range(count)]


_BASE32 = "abcdefghijklmnopqrstuvwxyz234567"  # RFC 4648 base32, lower case (as `portable.BASE32`)


def _base32_128(digests: list[bytes], prefix: str) -> pl.Series:
    """`prefix` + the unpadded lower-case base32 of the first 16 bytes of every digest: 26 characters, the
    130 bits of the two 64-bit words and two zero bits, five bits per character (vectorized)."""
    hi, lo = _words(digests, 2)
    h, low = pl.col("hi"), pl.col("lo")
    groups = [(h // (1 << (59 - 5 * i))) % 32 for i in range(12)]
    groups.append((h % 16) * 2 + low // (1 << 63))
    groups += [(low // (1 << (123 - 5 * i))) % 32 for i in range(13, 25)]
    groups.append((low % 8) * 4)
    chars = [pl.lit(_BASE32).str.slice(group.cast(pl.Int64), 1) for group in groups]
    frame = pl.DataFrame([hi.alias("hi"), lo.alias("lo")])
    return frame.select(pl.concat_str([pl.lit(prefix), *chars]).alias("v")).to_series()


def _evaluate(series: pl.Series, expr: pl.Expr) -> pl.Series:
    """`expr` (on `pl.col("x")`) evaluated on `series`."""
    return pl.DataFrame({"x": series}).select(expr.alias(series.name)).to_series()


# --- pseudonymize ------------------------------------------------------------------------------------------


def pseudonym_format(fmt: str, dtype: pl.DataType) -> str:
    return ("int" if dtype.is_integer() else "hex") if fmt == "auto" else fmt


def pseudonym_dtype(fmt: str, dtype: pl.DataType) -> pl.DataType:
    fmt = pseudonym_format(fmt, dtype)
    if fmt == "int":
        return pl.Int64()
    return pl.Binary() if fmt == "uuid" and dtype == pl.Binary else pl.String()


def pseudonymize(series: pl.Series, mac: Mac, fmt: str = "auto", prefix: str = "") -> pl.Series:
    dtype = series.dtype
    fmt = pseudonym_format(fmt, dtype)
    if fmt == "int":
        divisor = 1 << (64 - INT_BITS)  # the top INT_BITS bits of the first 8 bytes, big-endian

        def ints(values: list[Any]) -> pl.Series:
            (first,) = _words(mac.digests(canonical(values, dtype)), 1)
            return (first // divisor).cast(pl.Int64)

        return per_distinct(series, ints, pl.Int64())
    if fmt == "hex":

        def texts(values: list[Any]) -> pl.Series:
            return _base32_128(mac.digests(canonical(values, dtype)), prefix)

        return per_distinct(series, texts, pl.String())
    return pseudonymize_series(series, mac, "uuid")


# --- encrypt -----------------------------------------------------------------------------------------------


def encrypt(series: pl.Series, spec: Encrypt, sealer: Sealer, stats: MaskStats | None = None) -> pl.Series:
    """The column encrypted with the spec's algorithm, as text (`portable.Sealer`): reversible with the access
    key. For ff1, the values too short for it are counted (`too_short`)."""
    out = encrypt_series(series, sealer, spec.algorithm, spec.alphabet or "digits", spec.domain)
    if stats is not None and spec.algorithm == "ff1":
        stats.add(series.name, "too_short", int((out.is_null() & series.is_not_null()).sum()))
    return out


# --- fake --------------------------------------------------------------------------------------------------


def fake(series: pl.Series, kind: Fake | str, mac: Mac | None) -> pl.Series:
    """Consistent (`mac` given): one fake value per distinct input, nulls stay null. Random (`mac` None): a
    fresh value for every row, nulls included."""
    return fake_series(series, kind.kind if isinstance(kind, Fake) else kind, mac)


# --- generalize --------------------------------------------------------------------------------------------


def generalize(series: pl.Series, spec: Generalize, stats: MaskStats | None = None) -> pl.Series:
    x = pl.col("x")
    name = series.name
    if spec.to is not None:
        return series.dt.truncate(TRUNCATE[spec.to])
    if spec.bucket is not None:
        return _evaluate(series, bucket_expr(x, spec.bucket, series.dtype.is_integer())).cast(series.dtype)
    if spec.bins is not None:
        if stats is not None:
            stats.add(name, "below_first_bin", int((series < spec.bins[0]).sum() or 0))
        return _evaluate(series, bins_expr(x, spec.bins)).cast(series.dtype)
    if spec.keep_chars is not None:
        return series.str.slice(0, spec.keep_chars)
    out = ip_networks(series)
    if stats is not None:
        stats.add(name, "invalid_ip", int((out.is_null() & series.is_not_null()).sum()))
    return out


# --- date_shift --------------------------------------------------------------------------------------------


def date_shift(
    series: pl.Series, entity: pl.Series, mac: Mac, max_days: int, stats: MaskStats | None = None
) -> pl.Series:
    if stats is not None:
        stats.add(series.name, "null_entity", int((entity.is_null() & series.is_not_null()).sum()))
    return shift_dates(series, date_offsets(entity, mac, max_days))


# --- redact ------------------------------------------------------------------------------------------------


def redact(series: pl.Series, spec: Redact) -> pl.Series:
    """Text out. A value no longer than what is kept is masked whole: keeping it would show all of it."""
    expr = redact_expr(
        pl.col("x"), keep_last=spec.keep_last, keep_first=spec.keep_first, char=spec.char, with_=spec.with_
    )
    return _evaluate(series, expr)


def null(series: pl.Series) -> pl.Series:
    return pl.Series(series.name, [None] * series.len(), dtype=series.dtype)


def output_dtype(spec: Any, dtype: pl.DataType) -> pl.DataType:
    """The type of the column a method makes from a column of type `dtype`."""
    if isinstance(spec, Pseudonymize):
        return pseudonym_dtype(spec.format, dtype)
    if isinstance(spec, Encrypt | Fake | Redact):
        return pl.String()
    if isinstance(spec, Generalize) and (spec.ip or (spec.keep_chars is not None and is_text(dtype))):
        return pl.String()  # Categorical and Enum come out as String
    return dtype


# The exact shape of what some methods make. The residual scan checks that every value of such a column has it
# (a value outside it means the method let something through) instead of running the detectors, which the
# method's own output would set off: a fake email is an email, and a UUID can pass Luhn.
_FAKE_SPACE = {
    "email": r"^[a-z]+\.[a-z]+\.[a-z2-7]{6}@example\.(?:com|org|net)$",
    "phone": r"^\+1 \d{3} 555-01\d{2}$",
}
_UUID_V8 = r"^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
_NETWORK = r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}0$|^(?:::|(?:[0-9a-f]{1,4}:){1,3}:)$"


def output_space(spec: Any, dtype: pl.DataType) -> str | None:
    """The pattern every non-null output value of `spec` matches, for a text output; None when the method has
    no fixed shape (or its output is not text)."""
    if isinstance(spec, Encrypt):
        return {"aes-siv": SEALED_PATTERN, "aes-gcm": SEALED_RANDOM_PATTERN}.get(spec.algorithm)
    if isinstance(spec, Fake):
        return _FAKE_SPACE.get(spec.kind)
    if isinstance(spec, Pseudonymize):
        fmt = pseudonym_format(spec.format, dtype)
        if fmt == "hex":
            return rf"^{re.escape(spec.prefix)}[a-z2-7]{{26}}$"
        if fmt == "uuid" and dtype != pl.Binary:
            return _UUID_V8
    if isinstance(spec, Generalize) and spec.ip:
        return _NETWORK
    return None
