"""The masking invariants of docs/internals.md, numbers 1 to 8, on random tables (Hypothesis).

Inputs include nulls, empty strings, Unicode, extreme dates and duplicates. Each property runs the
`transform.mask` batch function (`mask_frame`), exactly what the fused path runs per batch.

Invariant 8 ("no raw value survives in a column whose class isn't kept") is checked for the pseudonymized and
removed classes. A generalized column keeps a value that is already as coarse as asked (1 January stays
1 January under `to: year`): that is invariant 7, and it is checked there instead.
"""

from datetime import date, timedelta
from typing import Any

import polars as pl
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from safetwin.keys import MasterKey

from .conftest import KEY_A, run_mask

SETTINGS = settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
texts = st.one_of(st.none(), st.text(max_size=12), st.sampled_from(["", "a", "é", "日本", "a@b.co"]))
ints = st.one_of(st.none(), st.integers(-(2**63), 2**63 - 1), st.integers(-3, 3))
dates = st.one_of(st.none(), st.dates(min_value=date(1, 2, 1), max_value=date(9999, 11, 30)))
keys = st.binary(min_size=32, max_size=32).map(MasterKey)

TEXT_METHODS: list[dict[str, Any]] = [
    {"method": "pseudonymize"},
    {"method": "pseudonymize", "format": "uuid"},
    {"method": "pseudonymize", "prefix": "p_"},
    {"method": "fake", "kind": "name"},
    {"method": "fake", "kind": "email"},
    {"method": "redact", "keep_last": 2},
    {"method": "redact", "with": "[X]"},
    {"method": "generalize", "keep_chars": 2},
    {"method": "null"},
    {"method": "keep"},
]
INT_METHODS: list[dict[str, Any]] = [
    {"method": "pseudonymize"},
    {"method": "pseudonymize", "format": "hex"},
    {"method": "generalize", "bucket": 10},
    {"method": "generalize", "bins": [-5, 0, 5]},
    {"method": "null"},
    {"method": "keep"},
]
DATE_METHODS: list[dict[str, Any]] = [
    {"method": "generalize", "to": "month"},
    {"method": "generalize", "to": "week"},
    {"method": "date_shift", "entity": "e", "max_days": 30},
    {"method": "null"},
]


def frame_of(values: list[Any], dtype: pl.DataType) -> pl.DataFrame:
    return pl.DataFrame(
        {"x": pl.Series(values, dtype=dtype), "e": pl.Series(range(len(values)), dtype=pl.Int64)}
    )


def cases() -> st.SearchStrategy[tuple[pl.DataFrame, dict[str, Any]]]:
    text = st.tuples(
        st.lists(texts, max_size=30).map(lambda v: frame_of(v, pl.String())), st.sampled_from(TEXT_METHODS)
    )
    integer = st.tuples(
        st.lists(ints, max_size=30).map(lambda v: frame_of(v, pl.Int64())), st.sampled_from(INT_METHODS)
    )
    when = st.tuples(
        st.lists(dates, max_size=30).map(lambda v: frame_of(v, pl.Date())), st.sampled_from(DATE_METHODS)
    )
    return st.one_of(text, integer, when)


@given(cases())
@SETTINGS
def test_1_nulls_stay_null_2_types_stay_3_row_counts_stay(case: tuple[pl.DataFrame, dict[str, Any]]) -> None:
    frame, spec = case
    out = run_mask(frame, {"x": spec})
    assert out.height == frame.height  # 3
    x, y = frame["x"], out["x"]
    assert (y.is_null() | x.is_not_null()).all()  # 1: a null input gives a null output
    expected = {"pseudonymize": None, "fake": pl.String, "redact": pl.String}.get(spec["method"], x.dtype)
    if spec["method"] == "pseudonymize":
        fmt = spec.get("format", "auto")
        expected = pl.Int64 if fmt == "int" or (fmt == "auto" and x.dtype.is_integer()) else pl.String
    assert y.dtype == expected  # 2


@given(st.lists(texts, max_size=30))
@SETTINGS
def test_1_random_fake_is_the_one_method_that_fills_nulls(values: list[str | None]) -> None:
    out = run_mask(
        frame_of(values, pl.String()), {"x": {"method": "fake", "kind": "city", "consistent": False}}
    )
    assert out["x"].null_count() == 0
    assert out.height == len(values)


@given(
    st.lists(st.one_of(st.none(), st.text(max_size=8)), max_size=40), st.sampled_from(["hex", "uuid", "int"])
)
@SETTINGS
def test_4_joins_survive_across_columns_of_one_domain(values: list[str | None], fmt: str) -> None:
    data = pl.DataFrame({"a": values, "b": list(reversed(values))}, schema={"a": pl.String, "b": pl.String})
    if fmt == "int":
        data = data.with_columns(
            pl.col("a").str.len_bytes().cast(pl.Int64), pl.col("b").str.len_bytes().cast(pl.Int64)
        )
    spec = {"method": "pseudonymize", "domain": "shared", "format": fmt if fmt != "int" else "auto"}
    out = run_mask(data, {"a": spec, "b": spec})
    pairs = {}
    for x, y in zip(
        data["a"].to_list() + data["b"].to_list(), out["a"].to_list() + out["b"].to_list(), strict=True
    ):
        if x is not None:
            assert pairs.setdefault(x, y) == y  # equal inputs, equal outputs
    assert len(set(pairs.values())) == len(pairs)  # unequal inputs, unequal outputs


@given(st.lists(texts, min_size=1, max_size=20), keys, keys)
@SETTINGS
def test_5_determinism_per_key_and_another_key_changes_every_value(
    values: list[str | None], key: MasterKey, other: MasterKey
) -> None:
    frame = frame_of(values, pl.String())
    spec = {"x": {"method": "pseudonymize"}, "e": {"method": "pseudonymize", "format": "int"}}
    first = run_mask(frame, spec, key=key)
    assert first.equals(run_mask(frame, spec, key=key))
    if key.fingerprint != other.fingerprint:
        changed = run_mask(frame, spec, key=other)
        for column in ("x", "e"):
            for a, b in zip(first[column], changed[column], strict=True):
                assert a is None or a != b


@given(
    st.lists(
        st.tuples(st.integers(0, 5), st.dates(min_value=date(1900, 1, 1), max_value=date(2100, 1, 1))),
        max_size=40,
    ),
    st.integers(1, 400),
)
@SETTINGS
def test_6_date_shift_keeps_intervals_within_an_entity(rows: list[tuple[int, date]], max_days: int) -> None:
    frame = pl.DataFrame(
        {"e": [r[0] for r in rows], "d": [r[1] for r in rows]}, schema={"e": pl.Int64, "d": pl.Date}
    )
    out = run_mask(
        frame,
        {"e": {"method": "pseudonymize"}, "d": {"method": "date_shift", "entity": "e", "max_days": max_days}},
    )
    shift: dict[int, timedelta] = {}
    for entity, before, after in zip(frame["e"], frame["d"], out["d"], strict=True):
        offset = after - before
        assert timedelta(days=-max_days) <= offset <= timedelta(days=max_days)
        assert offset != timedelta(0)
        assert shift.setdefault(entity, offset) == offset


@given(st.lists(ints, max_size=30), st.integers(1, 1000))
@SETTINGS
def test_7_buckets_contain_their_input(values: list[int | None], bucket: int) -> None:
    values = [v if v is None else max(min(v, 2**62), -(2**62)) for v in values]
    out = run_mask(frame_of(values, pl.Int64()), {"x": {"method": "generalize", "bucket": bucket}})
    for x, y in zip(values, out["x"], strict=True):
        assert x is None or (y <= x < y + bucket and y % bucket == 0)


@given(st.lists(ints, max_size=30), st.lists(st.integers(-100, 100), min_size=1, max_size=6, unique=True))
@SETTINGS
def test_7_bins_give_the_lower_bound_of_the_containing_bin(values: list[int | None], bins: list[int]) -> None:
    bins = sorted(bins)
    out = run_mask(frame_of(values, pl.Int64()), {"x": {"method": "generalize", "bins": bins}})
    for x, y in zip(values, out["x"], strict=True):
        if x is None:
            continue
        assert y in bins
        if x >= bins[0]:
            assert y <= x
            assert all(b <= y or b > x for b in bins)
        else:
            assert y == bins[0]


@given(st.lists(dates, max_size=30), st.sampled_from(["year", "month", "week", "day"]))
@SETTINGS
def test_7_dates_are_truncated_never_moved_forward(values: list[date | None], to: str) -> None:
    out = run_mask(frame_of(values, pl.Date()), {"x": {"method": "generalize", "to": to}})
    for x, y in zip(values, out["x"], strict=True):
        if x is None:
            continue
        assert y <= x
        assert (x - y).days < {"year": 366, "month": 31, "week": 7, "day": 1}[to]
        if to == "year":
            assert (y.month, y.day, y.year) == (1, 1, x.year)
        if to == "month":
            assert (y.day, y.month, y.year) == (1, x.month, x.year)


@given(
    st.lists(
        st.text(
            alphabet=st.characters(blacklist_characters="*", blacklist_categories=("Cs",)),
            min_size=1,
            max_size=12,
        ),
        max_size=30,
    )
)
@SETTINGS
def test_7_keep_chars_is_a_prefix_and_8_no_raw_value_survives_masking(values: list[str]) -> None:
    frame = pl.DataFrame(
        {"x": values, "p": values, "u": values, "r": values, "n": values, "s": values},
        schema=dict.fromkeys("xpurns", pl.String),
    )
    out = run_mask(
        frame,
        {
            "x": {"method": "generalize", "keep_chars": 3},
            "p": {"method": "pseudonymize"},
            "u": {"method": "pseudonymize", "format": "uuid"},
            "r": {"method": "redact", "keep_last": 2},
            "n": "null",
            "s": {"method": "fake", "kind": "text"},
        },
    )
    assert all(y == x[:3] for x, y in zip(values, out["x"], strict=True))
    raw = set(values)
    for column in "purns":
        assert not raw & set(out[column].drop_nulls().to_list()), column


@given(st.lists(dates.filter(lambda d: d is not None), min_size=1, max_size=30))
@SETTINGS
def test_8_a_shifted_date_never_equals_its_input(values: list[date]) -> None:
    values = [v for v in values if date(1, 3, 1) <= v <= date(9999, 11, 1)]
    out = run_mask(frame_of(values, pl.Date()), {"x": {"method": "date_shift", "entity": "e"}}, key=KEY_A)
    assert all(a != b for a, b in zip(values, out["x"], strict=True))
