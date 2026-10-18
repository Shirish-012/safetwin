"""`report.html`: escaped, self-contained, and every section of `report.json` shown in words people read."""

from typing import Any

from safetwin.masking.report import render_html

INJECTED = "<img src=x onerror=alert(1)>"


def _report(**changes: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "report_version": 1,
        "run_id": "r0123abcd",
        "status": "ok",
        "policy": {"name": "shop", "sha256": "ab" * 32},
        "key_fingerprint": "0011223344556677",
        "engine_version": "0.1.0",
        "started_at": "2026-10-17T07:26:11Z",
        "ended_at": "2026-10-17T07:26:14Z",
        "subset": None,
        "tables": {
            "customers": {
                "rows_in": 12345,
                "rows_out": 1234,
                "columns": {
                    "id": {"method": "pseudonymize", "class": "pseudonymized", "params": {"domain": "c"}},
                    "card": {"method": "redact", "class": "partially_redacted", "params": {"keep_last": 4}},
                    "ip": {"method": "generalize", "class": "generalized", "params": {"ip": True}},
                    INJECTED: {"method": "keep", "class": "kept", "quasi_identifier": True},
                },
            }
        },
        "relationships": [{"from": "orders.customer_id", "to": "customers.id", "orphans": 0}],
        "uniqueness": [{"column": "customers.id", "unique_in": True, "unique_out": True}],
        "residual_scan": {"findings": []},
        "files": [{"path": "customers/part-00000.parquet", "bytes": 42256, "sha256": "cd" * 32}],
        "warnings": [],
        "errors": [],
    }
    report.update(changes)
    return report


def test_the_page_is_self_contained_and_escapes_every_name() -> None:
    html = render_html(_report())
    assert "<script" not in html.lower()
    assert "default-src 'none'" in html
    assert INJECTED not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_numbers_and_settings_read_like_words() -> None:
    html = render_html(_report())
    assert "12,345 rows in → 1,234 rows out" in html
    assert "42,256" in html
    assert "ip: yes" in html
    assert "True" not in html
    assert "partially redacted" in html
    assert "took 3 s" in html
    assert "3 of 4" in html  # columns masked
    assert "No findings" in html
    assert "Subset" not in html


def test_a_failed_run_says_so_first_and_shows_its_findings() -> None:
    finding = {"table": "customers", "column": "notes", "detector": "email", "count": 2490, "level": "error"}
    html = render_html(
        _report(
            status="failed",
            errors=["residual scan: customers.notes: 2490 value(s) look like email"],
            residual_scan={"findings": [finding]},
            relationships=[{"from": "orders.customer_id", "to": "customers.id", "orphans": 7}],
        )
    )
    assert html.index("no twin was written") < html.index("Table customers")
    assert "badge failed" in html
    assert "2,490" in html
    assert "pill bad'>7<" in html


def test_a_subset_gets_its_own_section() -> None:
    subset = {
        "root": "customers",
        "key": "id",
        "fraction": 0.1,
        "include_children": True,
        "root_rows_picked": 1234,
        "copied_whole": ["countries"],
    }
    html = render_html(_report(subset=subset))
    assert "<h2>Subset</h2>" in html
    assert "10%" in html
    assert "1,234" in html
    assert "countries" in html
