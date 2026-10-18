"""`safetwin scan` (docs/guide.md): the profile, the suggestions, the draft, and scan → mask on the
example shop."""

from pathlib import Path
from typing import Any

import polars as pl
import pytest
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.masking.scan import scan
from safetwin.spec.policy import load_policy_text, validate_policy

from .test_mask_run import KEY, _generator, report

runner = CliRunner()


@pytest.fixture(scope="module")
def shop(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert _generator().main([str(folder), "--csv"]) == 0
    return folder


def methods_of(policy_text: str) -> dict[str, dict[str, Any]]:
    policy = load_policy_text(policy_text)
    return {
        table: {c: spec.model_dump(by_alias=True, exclude_unset=True) for c, spec in columns.items()}
        for table, columns in policy.spec.tables.items()
    }


def run_scan(*args: str) -> Any:
    return runner.invoke(app, ["scan", *args])


def test_scan_then_mask_the_example_with_no_edits(shop: Path, tmp_path: Path) -> None:
    policy = tmp_path / "masking.yaml"
    scanned = run_scan(str(shop), "-o", str(policy))
    assert scanned.exit_code == 0, scanned.output
    assert "NOTE the folder has Parquet and CSV files" in scanned.stderr
    summary = "scanned customers (1,000 rows), orders (3,000 rows): 15 columns, 13 masked, 2 kept"
    assert summary in scanned.stderr
    text = policy.read_text(encoding="utf-8")
    assert methods_of(text) == {
        "customers": {
            "id": {"method": "pseudonymize", "domain": "customer"},
            "full_name": {"method": "fake", "kind": "name"},
            "email": {"method": "fake", "kind": "email"},
            "phone": {"method": "fake", "kind": "phone"},
            "birth_date": {"method": "generalize", "to": "year"},
            "postcode": {"method": "generalize", "keep_chars": 3},
            "city": {"method": "keep"},
            "notes": {"method": "drop"},
            "created_at": {"method": "date_shift", "entity": "id"},
        },
        "orders": {
            "id": {"method": "pseudonymize"},
            "customer_id": {"method": "pseudonymize", "domain": "customer"},
            "card_number": {"method": "redact", "keep_last": 4},
            "ip_address": {"method": "generalize", "ip": True},
            "placed_at": {"method": "date_shift", "entity": "customer_id"},
            "total": {"method": "keep"},
        },
    }
    assert load_policy_text(text).spec.relationships == ["orders.customer_id -> customers.id"]
    assert load_policy_text(text).spec.source.folder.startswith(".")  # relative to the policy file
    assert '# name matches "email"; 100% of the sample are valid emails' in text
    assert "few distinct values: a possible quasi-identifier" in text
    assert runner.invoke(app, ["check", str(policy)], env={"SAFETWIN_KEY": KEY}).exit_code == 0
    out = tmp_path / "safe"
    masked = runner.invoke(app, ["mask", str(policy), "--out", str(out)], env={"SAFETWIN_KEY": KEY})
    assert masked.exit_code == 0, masked.output
    r = report(out)
    assert r["status"] == "ok"
    assert r["residual_scan"]["findings"] == []
    assert r["relationships"] == [{"from": "orders.customer_id", "to": "customers.id", "orphans": 0}]
    assert all(u["unique_out"] for u in r["uniqueness"])


def test_scan_then_mask_from_csv_says_dates_as_text_cant_be_shifted(shop: Path, tmp_path: Path) -> None:
    scanned = run_scan(str(shop), "--format", "csv")
    assert scanned.exit_code == 0, scanned.output
    methods = methods_of(scanned.stdout)
    assert methods["customers"]["birth_date"] == {"method": "generalize", "keep_chars": 4}
    assert methods["orders"]["placed_at"] == {"method": "keep"}
    assert "dates as text: date_shift needs a date column" in scanned.stdout
    policy = tmp_path / "masking.yaml"
    policy.write_text(scanned.stdout, encoding="utf-8")
    out = tmp_path / "safe"
    masked = runner.invoke(app, ["mask", str(policy), "--out", str(out)], env={"SAFETWIN_KEY": KEY})
    assert masked.exit_code == 0, masked.output
    assert report(out)["residual_scan"]["findings"] == []


def test_the_draft_and_the_summary_hold_no_value(shop: Path) -> None:
    scanned = run_scan(str(shop))
    assert scanned.exit_code == 0
    values: set[str] = set()
    for name in ("customers", "orders"):
        frame = pl.read_csv(shop / f"{name}.csv", infer_schema=False)
        for column in frame.columns:
            values |= {v for v in frame[column].drop_nulls().to_list() if len(v) >= 5}
    leaked = [v for v in values if v in scanned.stdout or v in scanned.stderr]
    assert leaked == []


def test_a_big_table_is_sampled(tmp_path: Path) -> None:
    pl.DataFrame({"id": range(50_000), "email": [f"u{i}@example.com" for i in range(50_000)]}).write_parquet(
        tmp_path / "users.parquet"
    )
    result = scan(tmp_path)
    users = result.tables["users"]
    assert (users.rows, users.sampled) == (50_000, 10_000)
    assert users.suggestions["email"].method == {"method": "fake", "kind": "email"}
    assert users.suggestions["id"].method == {"method": "pseudonymize"}


def test_names_that_need_quoting_and_methods_that_must_fit_the_type(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    pl.DataFrame(
        {
            "First Name": ["Ann", "Bo"],
            "yes": ["a", "b"],
            "phone": [5550100, 5550101],  # an integer: fake phone needs text
            "user_agent": ["Mozilla/5.0", "curl/8"],
            "lat": [52.37, 48.85],
        }
    ).write_parquet(source / "Customer Data.parquet")
    result = run_scan(str(source))
    assert result.exit_code == 0, result.output
    policy = load_policy_text(result.stdout)
    assert [p for p in validate_policy(policy) if p.severity == "error"] == []
    assert policy.spec.source.tables == {"customer_data": "Customer Data.parquet"}
    methods = methods_of(result.stdout)["customer_data"]
    assert methods["First Name"] == {"method": "fake", "kind": "first_name"}
    assert methods["yes"] == {"method": "keep"}
    assert methods["phone"] == {"method": "null"}
    assert methods["user_agent"] == {"method": "null"}
    assert methods["lat"] == {"method": "generalize", "bucket": 0.1}
    assert "fake needs a text column, so null" in result.stdout
    draft = tmp_path / "masking.yaml"
    draft.write_text(result.stdout, encoding="utf-8")
    checked = runner.invoke(app, ["check", str(draft)], env={"SAFETWIN_KEY": KEY})
    assert checked.exit_code == 0, checked.output


def test_the_output_file_is_never_replaced_without_force(shop: Path, tmp_path: Path) -> None:
    policy = tmp_path / "masking.yaml"
    policy.write_text("mine\n", encoding="utf-8")
    refused = run_scan(str(shop), "-o", str(policy))
    assert refused.exit_code == 1
    assert "exists already: give --force" in refused.stderr
    assert policy.read_text(encoding="utf-8") == "mine\n"
    assert run_scan(str(shop), "-o", str(policy), "--force").exit_code == 0
    assert policy.read_text(encoding="utf-8").startswith("# Drafted by safetwin scan")


def test_bad_input_is_refused(tmp_path: Path) -> None:
    empty = run_scan(str(tmp_path))
    assert empty.exit_code == 1
    assert "has no .parquet, .csv or .xlsx file" in empty.stderr
    (tmp_path / "t.csv").write_text("a\n1\n", encoding="utf-8")
    assert run_scan(str(tmp_path), "--format", "parquet").exit_code == 1
    key = run_scan(str(tmp_path), "--key", "00" * 32)
    assert key.exit_code == 2
    assert "--key" in key.output
