"""Each masking method on small, hand-written inputs (docs/guide.md)."""

import base64
import re
import uuid
from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import Any

import polars as pl
import pytest

from safetwin.masking import methods, portable
from safetwin.masking.hmacs import canonical
from safetwin.spec.policy import Fake, Generalize, Pseudonymize, Redact

from .conftest import KEY_B, mac, run_mask


def test_canonical_bytes_tag_the_type() -> None:
    assert canonical([42], pl.Int64()) == [b"i" + (42).to_bytes(8, "big", signed=True)]
    assert canonical([-1], pl.Int32()) == [b"i" + b"\xff" * 8]
    assert canonical(["42"], pl.String()) == [b"s42"]
    assert canonical([date(2024, 1, 2)], pl.Date()) == [b"d" + (19724).to_bytes(4, "big", signed=True)]
    assert canonical([date(1969, 12, 31)], pl.Date()) == [b"d\xff\xff\xff\xff"]
    assert canonical([True, False], pl.Boolean()) == [b"b\x01", b"b\x00"]
    assert canonical([2**64 - 1], pl.UInt64()) == [b"u" + b"\xff" * 8]
    assert canonical(["42"], pl.String()) != canonical([42], pl.Int64())


def test_pseudonymize_int_is_the_documented_63_bit_value() -> None:
    m = mac("pseudonymize", "customer")
    out = methods.pseudonymize(pl.Series("id", [1, 2, None, 1]), m, "int")
    expected = int.from_bytes(m.digest(b"i" + (1).to_bytes(8, "big", signed=True))[:8], "big") >> 1
    assert out.dtype == pl.Int64
    assert out.to_list()[0] == expected
    assert out[0] == out[3]
    assert out[0] != out[1]
    assert out[2] is None
    assert all(0 <= v < 2**63 for v in out.drop_nulls())


def test_pseudonymize_text_is_prefix_and_unpadded_lowercase_base32_of_16_bytes() -> None:
    m = mac("pseudonymize", "t.email")
    out = methods.pseudonymize(pl.Series("e", ["a@b.co", None]), m, "hex", "c_")
    expected = "c_" + base64.b32encode(m.digest(b"sa@b.co")[:16]).decode().lower().rstrip("=")
    assert out.to_list() == [expected, None]
    assert re.fullmatch(r"c_[a-z2-7]{26}", expected)


def test_pseudonymize_auto_picks_int_for_integers_and_text_otherwise() -> None:
    m = mac("pseudonymize", "x")
    assert methods.pseudonymize(pl.Series([1]), m).dtype == pl.Int64
    assert methods.pseudonymize(pl.Series(["1"]), m).dtype == pl.String
    assert methods.pseudonymize(pl.Series([date(2024, 1, 1)]), m).dtype == pl.String


def test_pseudonymize_uuid_is_a_version_8_uuid() -> None:
    m = mac("pseudonymize", "x")
    text = methods.pseudonymize(pl.Series(["123e4567-e89b-12d3-a456-426614174000"]), m, "uuid")[0]
    parsed = uuid.UUID(text)
    assert parsed.version == 8
    assert parsed.variant == uuid.RFC_4122
    binary = methods.pseudonymize(pl.Series([b"\x01" * 16], dtype=pl.Binary), m, "uuid")
    assert binary.dtype == pl.Binary
    assert uuid.UUID(bytes=binary[0]).version == 8


def test_domains_and_keys_change_pseudonyms() -> None:
    s = pl.Series([7])
    a = methods.pseudonymize(s, mac("pseudonymize", "one"), "int")[0]
    assert a == methods.pseudonymize(s, mac("pseudonymize", "one"), "int")[0]
    assert a != methods.pseudonymize(s, mac("pseudonymize", "two"), "int")[0]
    assert a != methods.pseudonymize(s, mac("pseudonymize", "one", KEY_B), "int")[0]


@pytest.mark.parametrize(
    ("kind", "pattern"),
    [
        ("name", r"[A-Z][a-z]+ [A-Z][a-z]+"),
        ("first_name", r"[A-Z][a-z]+"),
        ("last_name", r"[A-Z][a-z]+"),
        ("email", r"[a-z]+\.[a-z]+\.[a-z2-7]{6}@example\.(com|org|net)"),
        ("phone", r"\+1 \d{3} 555-01\d\d"),
        ("street", r"\d{1,4} [A-Z][a-z]+ (St|Ave|Rd|Ln|Way|Dr|Ct|Blvd|Pl|Ter)"),
        ("city", r"[A-Z][a-z]+"),
        ("company", r"[A-Z][a-z]+ [A-Z][a-z]+ (Inc\.|LLC|Ltd\.|Co\.|Group)"),
        ("text", r"[A-Z][a-z]+( [a-z]+){5,11}\."),
    ],
)
def test_fake_kinds(kind: str, pattern: str) -> None:
    values = pl.Series([f"input {i}" for i in range(200)] + [None])
    out = methods.fake(values, kind, mac("fake", "t.c"))
    assert out[-1] is None
    assert all(re.fullmatch(pattern, value) for value in out.drop_nulls()), out.head(5).to_list()
    assert out.to_list() == methods.fake(values, kind, mac("fake", "t.c")).to_list()  # consistent
    assert out.drop_nulls().n_unique() > 1


def test_fake_that_is_not_consistent_is_random_per_row_and_fills_nulls() -> None:
    values = pl.Series(["same"] * 50 + [None])
    out = methods.fake(values, "email", None)
    assert out.null_count() == 0
    assert out.n_unique() > 1


@pytest.mark.parametrize(
    ("to", "expected"),
    [
        ("year", date(2024, 1, 1)),
        ("month", date(2024, 5, 1)),
        ("week", date(2024, 5, 13)),
        ("day", date(2024, 5, 17)),
    ],
)
def test_generalize_dates(to: str, expected: date) -> None:
    out = methods.generalize(pl.Series([date(2024, 5, 17), None]), Generalize(method="generalize", to=to))
    assert out.to_list() == [expected, None]
    assert out.dtype == pl.Date


def test_generalize_datetimes_keep_their_type() -> None:
    s = pl.Series([datetime(2024, 5, 17, 13, 5, tzinfo=UTC)])
    out = methods.generalize(s, Generalize(method="generalize", to="month"))
    assert out.dtype == s.dtype
    assert out[0] == datetime(2024, 5, 1, tzinfo=UTC)


def test_generalize_numbers() -> None:
    ints = pl.Series([-7, 0, 7, 10, None], dtype=pl.Int32)
    out = methods.generalize(ints, Generalize(method="generalize", bucket=5))
    assert out.to_list() == [-10, 0, 5, 10, None]
    assert out.dtype == pl.Int32
    floats = methods.generalize(pl.Series([2.4, -0.1]), Generalize(method="generalize", bucket=0.5))
    assert floats.to_list() == [2.0, -0.5]


def test_generalize_bins_and_values_below_the_first_bin() -> None:
    stats = methods.MaskStats()
    s = pl.Series("age", [5, 18, 30, 64, 65, 99, None])
    out = methods.generalize(s, Generalize(method="generalize", bins=[18, 30, 65]), stats)
    assert out.to_list() == [18, 18, 30, 30, 65, 65, None]
    assert stats.snapshot() == {"age": {"below_first_bin": 1}}


def test_generalize_text_and_ips() -> None:
    assert methods.generalize(
        pl.Series(["SW1A 1AA", "x", None]), Generalize(method="generalize", keep_chars=3)
    ).to_list() == [
        "SW1",
        "x",
        None,
    ]
    stats = methods.MaskStats()
    s = pl.Series("ip", ["192.0.2.77", "2001:db8:abcd:1234::1", "not an ip", None])
    out = methods.generalize(s, Generalize(method="generalize", ip=True), stats)
    assert out.to_list() == ["192.0.2.0", "2001:db8:abcd::", None, None]
    assert stats.snapshot() == {"ip": {"invalid_ip": 1}}


def test_date_shift_offsets_are_fixed_per_entity_and_never_zero() -> None:
    stats = methods.MaskStats()
    dates = pl.Series("d", [date(2024, 1, 10), date(2024, 1, 20), date(2024, 3, 1), date(2024, 1, 1), None])
    entity = pl.Series("e", [1, 1, 2, None, 3])
    out = methods.date_shift(dates, entity, mac("date_shift", "customer"), 30, stats)
    shifts = [
        (o - d).days if o is not None and d is not None else None for o, d in zip(out, dates, strict=True)
    ]
    assert shifts[0] == shifts[1]
    assert shifts[0] != 0
    assert -30 <= shifts[0] <= 30
    assert out[3] is None
    assert out[4] is None
    assert stats.snapshot() == {"d": {"null_entity": 1}}
    assert out.dtype == pl.Date


def test_shift_days_covers_the_range_without_zero() -> None:
    offsets = {portable.shift_days(i.to_bytes(8, "big"), 3) for i in range(60)}
    assert offsets == {-3, -2, -1, 1, 2, 3}


def test_date_shift_on_datetimes_with_a_time_zone() -> None:
    s = pl.Series("t", [datetime(2024, 1, 1, 12, tzinfo=UTC)])
    out = methods.date_shift(s, pl.Series([1]), mac("date_shift", "x"), 30)
    assert out.dtype == s.dtype
    assert (out[0] - s[0]).seconds == 0


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ({"keep_last": 4}, ["************1111", "****", "***", None, ""]),
        ({"keep_first": 2}, ["41**************", "12**", "ab*", None, ""]),
        ({"keep_last": 4, "char": "#"}, ["############1111", "####", "###", None, ""]),
        ({"keep_last": 0}, ["****************", "****", "***", None, ""]),
        ({"with": "[REDACTED]"}, ["[REDACTED]", "[REDACTED]", "[REDACTED]", None, "[REDACTED]"]),
    ],
)
def test_redact(spec: dict[str, object], expected: list[str | None]) -> None:
    s = pl.Series(["4111111111111111", "1234", "abc", None, ""])
    assert methods.redact(s, Redact.model_validate({"method": "redact", **spec})).to_list() == expected


def test_null_keeps_the_type() -> None:
    out = methods.null(pl.Series("x", [1, 2], dtype=pl.Int16))
    assert out.to_list() == [None, None]
    assert out.dtype == pl.Int16


def test_a_batch_keeps_its_rows_and_column_order_without_dropped_columns() -> None:
    frame = pl.DataFrame({"a": [1, 2, 3], "b": ["x", "y", "z"], "c": [1.0, 2.0, 3.0]})
    out = run_mask(frame, {"a": {"method": "pseudonymize"}, "b": "drop", "c": "null"})
    assert out.columns == ["a", "c"]
    assert out.height == 3
    assert out["c"].null_count() == 3
    empty = run_mask(frame.head(0), {"a": {"method": "pseudonymize"}, "b": "drop", "c": "keep"})
    assert empty.columns == ["a", "c"]
    assert empty.height == 0


def test_canonical_bytes_are_the_same_instant_in_every_zone() -> None:
    naive = pl.Series([datetime(2024, 3, 10, 12, 0, 0, 123456)])
    utc = naive.dt.replace_time_zone("UTC")
    expected = [b"t" + (1710072000123456).to_bytes(8, "big", signed=True)]
    assert canonical(naive.to_list(), naive.dtype) == expected
    for zone in ("Asia/Kolkata", "America/New_York", "Pacific/Chatham"):
        s = utc.dt.convert_time_zone(zone)
        assert canonical(s.to_list(), s.dtype) == expected
    ns = pl.Series([1710072000123456999]).cast(pl.Datetime("ns"))
    assert canonical(ns.to_list(), ns.dtype) == expected  # truncated to the microsecond


def test_canonical_bytes_of_numbers_and_times() -> None:
    decimals = [Decimal("1.10"), Decimal("1.1"), Decimal("-0.00"), Decimal("10.0")]
    dec = pl.Series(decimals, dtype=pl.Decimal(10, 2))
    assert canonical(dec.to_list(), dec.dtype) == [b"n1.1", b"n1.1", b"n0", b"n10"]
    assert canonical([-0.0], pl.Float64()) == canonical([0.0], pl.Float64())
    nan = b"f" + bytes.fromhex("7ff8000000000000")
    assert canonical([float("nan"), -float("nan")], pl.Float32()) == [nan, nan]
    assert canonical([1.5], pl.Float64()) == [b"f" + bytes.fromhex("3ff8000000000000")]
    assert canonical([time(0, 0, 1, 5)], pl.Time()) == [b"T" + (1_000_005).to_bytes(8, "big", signed=True)]


def test_categorical_and_enum_columns_mask_like_text(masker: Any) -> None:
    values = ["a@b.co", "c@d.org", None, "a@b.co"]
    frame = pl.DataFrame(
        {
            "s": pl.Series(values, dtype=pl.String),
            "c": pl.Series(values, dtype=pl.Categorical),
            "e": pl.Series(values, dtype=pl.Enum(["a@b.co", "c@d.org"])),
            "k": pl.Series(values, dtype=pl.Categorical),
            "g": pl.Series(values, dtype=pl.Enum(["a@b.co", "c@d.org"])),
            "r": pl.Series(values, dtype=pl.Categorical),
        }
    )
    out = masker(
        frame,
        {
            "s": {"method": "pseudonymize", "domain": "x"},
            "c": {"method": "pseudonymize", "domain": "x"},
            "e": {"method": "pseudonymize", "domain": "x"},
            "k": {"method": "generalize", "keep_chars": 3},
            "g": {"method": "redact", "keep_last": 2},
            "r": {"method": "fake", "kind": "email"},
        },
    )
    # a Categorical FK joins a String PK
    assert out["s"].to_list() == out["c"].to_list() == out["e"].to_list()
    assert out["k"].dtype == pl.String
    assert out["k"].to_list() == ["a@b", "c@d", None, "a@b"]
    assert out["g"].to_list() == ["****co", "*****rg", None, "****co"]
    assert out["r"][0] == out["r"][3]


def test_output_space_holds_every_pseudonym_and_fake() -> None:
    from safetwin.detect.exprs import residual_scan

    n = 50_000
    ids = pl.Series("v", [f"user-{i}" for i in range(n)])
    frame = pl.DataFrame(
        {
            "u": methods.pseudonymize(ids, mac("pseudonymize", "u"), "uuid"),
            "h": methods.pseudonymize(ids, mac("pseudonymize", "h"), "hex", "cus_"),
            "e": methods.fake(ids, "email", mac("fake", "e")),
            "p": methods.fake(ids, "phone", mac("fake", "p")),
        }
    )
    specs = {
        "u": Pseudonymize(method="pseudonymize", format="uuid"),
        "h": Pseudonymize(method="pseudonymize", format="hex", prefix="cus_"),
        "e": Fake(method="fake", kind="email"),
        "p": Fake(method="fake", kind="phone"),
    }
    spaces = {c: methods.output_space(spec, pl.String()) for c, spec in specs.items()}
    assert all(spaces.values())
    classes = dict.fromkeys(frame.columns, "pseudonymized")
    assert residual_scan("t", frame, classes, output_space=spaces) == []  # no card or phone false alarm
    raw = pl.DataFrame({c: ["4111 1111 1111 1111", "a@b.co", None] for c in frame.columns})
    findings = residual_scan("t", raw, classes, output_space=spaces)
    assert {(f.column, f.detector, f.count, f.level) for f in findings} == {
        (c, "outside_output_space", 2, "error") for c in frame.columns
    }


def test_generalized_ips_have_zero_host_bits() -> None:
    from safetwin.detect.exprs import residual_scan

    spec = Generalize(method="generalize", ip=True)
    out = methods.generalize(pl.Series("ip", ["10.1.2.3", "2001:db8:1:2::5", "::1", "8.8.8.8", None]), spec)
    space = methods.output_space(spec, pl.String())
    assert space is not None
    frame = pl.DataFrame({"ip": out})
    assert residual_scan("t", frame, {"ip": "generalized"}, output_space={"ip": space}) == []
    raw = pl.DataFrame({"ip": ["10.1.2.3", "2001:db8:1:2::5"]})
    (finding,) = residual_scan("t", raw, {"ip": "generalized"}, output_space={"ip": space})
    assert finding.count == 2
