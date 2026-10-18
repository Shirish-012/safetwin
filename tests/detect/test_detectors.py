"""Detectors (docs/guide.md): the value validators, the Polars expressions (which must agree with them),
the column-name signals and the residual-scan API (counts, never values)."""

from datetime import date, datetime

import polars as pl
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safetwin.detect import validators as v
from safetwin.detect.exprs import DETECTORS, count_matches, detector_expr, residual_scan
from safetwin.detect.names import name_signals, words

TODAY = date(2026, 10, 3)


def flags(detector: str, values: list[str | None]) -> list[bool]:
    expr = detector_expr(detector, pl.col("s"), pl.String(), TODAY)  # type: ignore[arg-type]
    assert expr is not None
    return pl.DataFrame({"s": values}, schema={"s": pl.String}).select(expr).to_series().to_list()


@pytest.mark.parametrize(
    ("detector", "yes", "no"),
    [
        ("email", ["a@b.co", "note: ann.lee+x@mail.example.org!"], ["a@b", "@example.com", "plain text", ""]),
        (
            "phone",
            ["+1 415 555 0142", "(415) 555-0142", "415-555-0142", "+442079460018", "call 020 7946 0018"],
            ["12345", "2024-01-15", "4111 1111", "version 1.2.3"],
        ),
        (
            "card",
            ["4111 1111 1111 1111", "4111-1111-1111-1111", "pay 5555555555554444 now", "378282246310005"],
            ["4111 1111 1111 1112", "1234", "***************1111"],
        ),
        (
            "iban",
            ["GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"],
            ["GB82WEST12345698765433", "GB82"],
        ),
        ("ipv4", ["10.0.0.1", "from 192.0.2.17 at"], ["256.1.1.1", "1.2.3", "v10.0.0"]),
        (
            "ipv6",
            ["2001:db8::1", "fe80::1", "::1", "2001:0db8:0000:0000:0000:ff00:0042:8329"],
            ["12:30", "a:b"],
        ),
        ("uuid", ["123e4567-e89b-12d3-a456-426614174000"], ["123e4567-e89b-12d3-a456", "not-a-uuid"]),
        (
            "birth_date",
            ["1985-02-03", " 1900-01-01 "],
            ["2020-01-01", "1899-12-31", "1985-02-30", "85-02-03"],
        ),
    ],
)
def test_each_detector_on_text(detector: str, yes: list[str], no: list[str]) -> None:
    assert flags(detector, [*yes, None]) == [True] * len(yes) + [False]
    assert flags(detector, no) == [False] * len(no)


def test_birth_date_on_date_and_datetime_columns() -> None:
    frame = pl.DataFrame(
        {
            "d": [date(1985, 1, 1), date(2020, 1, 1), None],
            "t": [datetime(1950, 5, 5), datetime(2024, 1, 1), None],
        }
    )
    assert count_matches(frame, detectors=["birth_date"], today=TODAY) == {
        ("d", "birth_date"): 1,
        ("t", "birth_date"): 1,
    }


def test_text_detectors_do_not_apply_to_numbers() -> None:
    frame = pl.DataFrame({"n": [4111111111111111, 2]})
    assert count_matches(frame) == {}
    assert detector_expr("card", pl.col("n"), pl.Int64()) is None


@given(st.lists(st.integers(0, 9), min_size=13, max_size=19), st.sampled_from(["", " ", "-"]))
@settings(max_examples=200, deadline=None)
def test_luhn_in_polars_agrees_with_python(digits: list[int], separator: str) -> None:
    text = "".join(map(str, digits))
    grouped = separator.join(text[i : i + 4] for i in range(0, len(text), 4))
    assert flags("card", [grouped]) == [v.is_card(grouped)]
    assert v.is_card(grouped) == v.luhn_ok(text)


@given(
    st.sampled_from(["GB", "DE", "FR", "NL"]),
    st.integers(0, 99),
    st.text(alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=11, max_size=30),
)
@settings(max_examples=200, deadline=None)
def test_iban_mod97_in_polars_agrees_with_python(country: str, check: int, body: str) -> None:
    iban = f"{country}{check:02d}{body}"
    assert flags("iban", [iban]) == [v.iban_ok(iban)]


def test_a_valid_iban_made_by_computing_its_check_digits() -> None:
    body = "WEST12345698765432"
    rearranged = body + "GB00"
    check = 98 - int("".join(str(int(c, 36)) for c in rearranged)) % 97
    iban = f"GB{check:02d}{body}"
    assert v.iban_ok(iban)
    assert flags("iban", [iban]) == [True]


@given(st.ip_addresses())
@settings(max_examples=200, deadline=None)
def test_ip_detectors_find_every_ip_address(address: object) -> None:
    text = str(address)
    detector = "ipv4" if v.is_ipv4(text) else "ipv6"
    assert flags(detector, [text]) == [True]


def test_python_validators() -> None:
    assert v.is_email("a.b@example.com")
    assert not v.is_email("a.b@example")
    assert v.is_phone("(415) 555-0142")
    assert not v.is_phone("hello")
    assert v.is_card("4111 1111 1111 1111")
    assert not v.is_card("4111 1111 1111 1112")
    assert not v.is_card("411")
    assert v.is_ipv4("192.0.2.1")
    assert v.is_ipv6("2001:db8::1")
    assert not v.is_ipv4("2001:db8::1")
    assert v.is_uuid("123e4567-e89b-12d3-a456-426614174000")
    assert not v.is_uuid("x")
    assert v.is_birth_date(date(1980, 1, 1), TODAY)
    assert not v.is_birth_date(date(2015, 1, 1), TODAY)
    assert v.is_birth_date("1980-01-01", TODAY)
    assert not v.is_birth_date("1980-13-01", TODAY)
    assert v.birth_max(date(2024, 2, 29)) == date(2011, 2, 28)


@pytest.mark.parametrize(
    ("column", "signals"),
    [
        ("email", ["email"]),
        ("contactEmail", ["email"]),
        ("mobile_phone", ["phone"]),
        ("first_name", ["name"]),
        ("FULL-NAME", ["name"]),
        ("street_address", ["address"]),
        ("zip", ["postcode"]),
        ("postcode", ["postcode"]),
        ("dob", ["birth_date"]),
        ("birthDate", ["birth_date"]),
        ("ssn", ["national_id"]),
        ("passport_no", ["national_id"]),
        ("iban", ["iban"]),
        ("card_number", ["card"]),
        ("client_ip", ["ip"]),
        ("lat", ["geo"]),
        ("user_agent", ["user_agent"]),
        ("description", []),
        ("zipper", []),
        ("total", []),
    ],
)
def test_column_name_signals(column: str, signals: list[str]) -> None:
    assert name_signals(column) == signals


def test_words() -> None:
    assert words("customerFirstName") == ["customer", "first", "name"]
    assert words("HTTPUserAgent") == ["http", "user", "agent"]


def test_count_matches_counts_and_never_returns_values() -> None:
    frame = pl.LazyFrame({"note": ["mail ann@example.com", None, "x"], "n": [1, 2, 3]})
    counts = count_matches(frame)
    assert counts[("note", "email")] == 1
    assert set(counts) == {("note", d) for d in DETECTORS}
    assert all(isinstance(c, int) for c in counts.values())


def test_residual_scan_levels_and_expected_detectors() -> None:
    frame = pl.LazyFrame(
        {
            "kept": ["a@b.co", "c@d.org"],
            "masked": ["x@y.com", "ok"],
            "fake": ["p.q01@example.com", "r@example.org"],
        }
    )
    findings = residual_scan(
        "t",
        frame,
        {"kept": "kept", "masked": "generalized", "fake": "pseudonymized"},
        expected={"fake": ["email"]},
    )
    assert [(f.column, f.detector, f.count, f.level) for f in findings] == [
        ("kept", "email", 2, "warning"),
        ("masked", "email", 1, "error"),
    ]
    assert findings[0].as_dict() == {
        "table": "t",
        "column": "kept",
        "detector": "email",
        "count": 2,
        "level": "warning",
    }


def test_a_categorical_column_is_scanned_as_text() -> None:
    frame = pl.DataFrame({"c": pl.Series(["ann@example.com", "x", None], dtype=pl.Categorical)})
    (finding,) = residual_scan("t", frame, {"c": "kept"})
    assert (finding.detector, finding.count, finding.level) == ("email", 1, "warning")
