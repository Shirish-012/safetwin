"""`safetwin mask`, `check` and `key` end to end, on the example shop (examples/shop): the report, the
manifests, determinism, joins and date shifts across tables, the compiled pipeline, and the failure paths."""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import polars as pl
import pytest
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.keys import MasterKey
from safetwin.masking import methods, portable
from safetwin.masking import run as mask_run
from safetwin.masking.check import discover
from safetwin.masking.compile import compile_policy
from safetwin.spec import dump_pipeline, load_pipeline_text, validate_pipeline
from safetwin.spec.policy import load_policy_file, load_policy_text, validate_policy

REPO = Path(__file__).resolve().parents[2]
POLICY = REPO / "examples" / "shop" / "masking.yaml"
SAFETWIN = Path(sys.executable).parent / "safetwin"
KEY = "c3" * 32
OTHER_KEY = "d4" * 32
runner = CliRunner()


def _generator() -> Any:
    spec = importlib.util.spec_from_file_location("shop_generate", REPO / "examples" / "shop" / "generate.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def shop(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert _generator().main([str(folder), "--csv"]) == 0
    return folder


def mask(policy: Path, source: Path, out: Path, *options: str, key: str = KEY) -> Any:
    return runner.invoke(
        app,
        ["mask", str(policy), "--source", str(source), "--out", str(out), *options],
        env={"SAFETWIN_KEY": key},
    )


def table(out: Path, name: str, fmt: str = "parquet") -> pl.DataFrame:
    (file,) = (out / name).glob(f"part-*.{fmt}")
    return pl.read_parquet(file) if fmt == "parquet" else pl.read_csv(file, infer_schema=False)


def report(out: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((out / "report.json").read_text(encoding="utf-8"))
    return data


def write_policy(tmp_path: Path, replace: dict[str, str]) -> Path:
    text = POLICY.read_text(encoding="utf-8")
    for old, new in replace.items():
        assert old in text
        text = text.replace(old, new)
    path = tmp_path / "masking.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def data_files(out: Path) -> list[str]:
    return sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file() and "report." not in p.name)


# --- success ------------------------------------------------------------------------------------------------


def test_the_example_masks_and_its_report_proves_it(shop: Path, tmp_path: Path) -> None:
    out = tmp_path / "safe"
    result = mask(POLICY, shop, out)
    assert result.exit_code == 0, result.output
    assert "residual scan: 0 findings" in result.stdout
    r = report(out)
    assert r["status"] == "ok"
    assert r["errors"] == []
    assert r["warnings"] == []
    assert list(r)[:9] == [
        "report_version", "run_id", "status", "policy", "key_fingerprint", "access_fingerprint",
        "engine_version", "started_at", "ended_at",
    ]  # fmt: skip
    assert r["key_fingerprint"] == MasterKey(bytes.fromhex(KEY)).fingerprint
    assert r["access_fingerprint"] is None  # nothing encrypted
    assert r["residual_scan"]["findings"] == []
    assert r["uniqueness"] == [
        {"column": "customers.id", "unique_in": True, "unique_out": True},
        {"column": "customers.email", "unique_in": True, "unique_out": True},
    ]
    assert r["relationships"] == [{"from": "orders.customer_id", "to": "customers.id", "orphans": 0}]
    assert r["tables"]["customers"]["rows_in"] == r["tables"]["customers"]["rows_out"] == 1000
    assert r["tables"]["orders"]["rows_out"] == 3000
    assert r["tables"]["customers"]["columns"]["city"] == {
        "method": "keep",
        "class": "kept",
        "quasi_identifier": True,
    }
    assert r["tables"]["customers"]["columns"]["email"] == {
        "method": "fake", "class": "pseudonymized", "params": {"kind": "email"}
    }  # fmt: skip
    assert r["tables"]["orders"]["columns"]["card_number"]["class"] == "partially_redacted"
    assert [f["path"] for f in r["files"]] == [
        f"customers/part-00000-{r['run_id']}.parquet",
        f"orders/part-00000-{r['run_id']}.parquet",
    ]
    for name in ("customers", "orders"):
        (manifest,) = (out / name / "_manifest").glob("*.json")
        classification = json.loads(manifest.read_text())["classification"]
        assert set(classification) == set(table(out, name).columns)
    assert (
        json.loads((out / "customers" / "_manifest").glob("*.json").__next__().read_text())["classification"][
            "phone"
        ]
        == "removed"
    )
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "<script" not in html.lower()
    assert "Content-Security-Policy" in html
    assert r["run_id"] in html


def test_nothing_from_the_input_is_in_the_report_the_policy_or_masked_columns(
    shop: Path, tmp_path: Path
) -> None:
    out = tmp_path / "safe"
    result = mask(POLICY, shop, out)
    assert result.exit_code == 0, result.output
    customers = pl.read_parquet(shop / "customers.parquet")
    orders = pl.read_parquet(shop / "orders.parquet")
    values = {
        str(v)
        for frame in (customers, orders)
        for column in frame.columns
        if frame[column].dtype == pl.String
        for v in frame[column].drop_nulls().to_list()
        if len(str(v)) >= 5
    }
    texts = [
        (out / "report.json").read_text(),
        (out / "report.html").read_text(),
        POLICY.read_text(),
        result.output,
    ]
    for text in texts:
        assert not [v for v in values if v in text]
        assert KEY not in text
    safe_c, safe_o = table(out, "customers"), table(out, "orders")
    for column in ("full_name", "email"):
        assert not set(customers[column]) & set(safe_c[column])
    assert not set(orders["card_number"]) & set(safe_o["card_number"])
    assert not set(customers["id"]) & set(safe_c["id"])
    assert "notes" not in safe_c.columns
    assert safe_c["phone"].null_count() == safe_c.height


def test_joins_and_date_shifts_survive_across_tables(shop: Path, tmp_path: Path) -> None:
    out = tmp_path / "safe"
    assert mask(POLICY, shop, out).exit_code == 0
    src_c, src_o = pl.read_parquet(shop / "customers.parquet"), pl.read_parquet(shop / "orders.parquet")
    safe_c, safe_o = table(out, "customers"), table(out, "orders")
    # Row order is kept, so row i of the output is row i of the input.
    before = src_o.join(src_c.with_row_index("row"), left_on="customer_id", right_on="id").sort("id")
    after = safe_o.join(safe_c.with_row_index("row"), left_on="customer_id", right_on="id").sort("id")
    assert after.height == before.height == src_o.height
    assert after["row"].to_list() == before["row"].to_list()  # every order points at the same customer
    gap = (pl.col("placed_at") - pl.col("created_at")).alias("gap")
    assert before.select(gap)["gap"].to_list() == after.select(gap)["gap"].to_list()
    assert (safe_c["created_at"] != src_c["created_at"]).all()


def test_the_same_key_gives_the_same_twin_also_in_a_fresh_process(shop: Path, tmp_path: Path) -> None:
    assert mask(POLICY, shop, tmp_path / "a").exit_code == 0
    assert mask(POLICY, shop, tmp_path / "b").exit_code == 0
    done = subprocess.run(
        [str(SAFETWIN), "mask", str(POLICY), "--source", str(shop), "--out", str(tmp_path / "c")],
        env={**os.environ, "SAFETWIN_KEY": KEY},
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr
    for name in ("customers", "orders"):
        first = table(tmp_path / "a", name)
        assert first.equals(table(tmp_path / "b", name))
        assert first.equals(table(tmp_path / "c", name))
        # The data files are the same bytes too (their names differ by run id).
        assert {f["sha256"] for f in report(tmp_path / "a")["files"]} == {
            f["sha256"] for f in report(tmp_path / "c")["files"]
        }


def test_another_key_changes_every_keyed_value(shop: Path, tmp_path: Path) -> None:
    assert mask(POLICY, shop, tmp_path / "a").exit_code == 0
    assert mask(POLICY, shop, tmp_path / "b", key=OTHER_KEY).exit_code == 0
    keyed = {"customers": ["id", "full_name", "email", "created_at"], "orders": ["customer_id", "placed_at"]}
    for name, columns in keyed.items():
        a, b = table(tmp_path / "a", name), table(tmp_path / "b", name)
        for column in columns:
            changed = (a[column] != b[column]).sum()
            # Fake values are picked from short word lists and a date shift from 60 offsets, so a few coincide
            # by chance; pseudonyms never do.
            small_range = column in ("full_name", "email", "created_at", "placed_at")
            assert changed >= (0.9 if small_range else 1.0) * a.height, column
        unkeyed = [c for c in a.columns if c not in columns]
        assert a.select(unkeyed).equals(b.select(unkeyed))


def test_csv_in_and_csv_out(shop: Path, tmp_path: Path) -> None:
    policy = tmp_path / "csv.yaml"
    policy.write_text(
        """\
apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {name: shop-csv}
spec:
  source: {folder: ./unused, format: csv}
  target: {folder: ./unused-out, format: csv}
  key: env://SAFETWIN_KEY
  unknown_columns: drop
  tables:
    customers:
      id: {method: pseudonymize, domain: customer, prefix: c_}
      email: {method: fake, kind: email}
      notes: {method: redact, with: "[REDACTED]"}
      city: keep
    orders:
      customer_id: {method: pseudonymize, domain: customer, prefix: c_}
      card_number: {method: redact, keep_last: 4}
  relationships: [orders.customer_id -> customers.id]
""",
        encoding="utf-8",
    )
    out = tmp_path / "safe"
    result = mask(policy, shop, out)
    assert result.exit_code == 0, result.output
    safe = table(out, "customers", "csv")
    assert safe.columns == ["id", "email", "city", "notes"] or safe.columns == [
        "id",
        "email",
        "notes",
        "city",
    ]
    assert safe["id"].str.starts_with("c_").all()
    (manifest,) = (out / "orders" / "_manifest").glob("*.json")
    data = json.loads(manifest.read_text())
    assert data["files"][0]["compression"] == "none"
    assert data["totals"]["rows"] == 3000
    assert {c["type"] for c in data["schema"]} == {"string"}
    assert report(out)["relationships"][0]["orphans"] == 0


def test_the_compiled_pipeline_holds_no_key_material(shop: Path) -> None:
    policy = load_policy_file(POLICY)
    tables, problems = discover(policy, shop)
    assert problems == [p for p in problems if p.severity == "warning"]
    compiled = compile_policy(policy, tables)
    text = dump_pipeline(compiled.pipeline)
    key = MasterKey(bytes.fromhex(KEY))
    assert KEY not in text.lower()
    for use in compiled.subkey_uses:
        assert key.subkey(*use).hex() not in text
    assert compiled.subkey_uses == {
        ("pseudonymize", "customer"),
        ("fake", "customers.full_name"),
        ("fake", "customers.email"),
        ("date_shift", "customer"),
    }
    reloaded = load_pipeline_text(text)
    assert validate_pipeline(reloaded) == []
    assert [n.operator for n in reloaded.spec.nodes] == [
        "source.parquet",
        "transform.mask",
        "sink.parquet",
    ] * 2


# --- check and key ------------------------------------------------------------------------------------------


def test_check(shop: Path, tmp_path: Path) -> None:
    ok = runner.invoke(app, ["check", str(POLICY), "--source", str(shop)], env={"SAFETWIN_KEY": KEY})
    assert ok.exit_code == 0
    assert ok.stdout.strip().endswith(": ok")
    bad = write_policy(
        tmp_path,
        {
            "      notes:       drop\n": "",
            "{ method: generalize, to: year }": "{ method: redact, keep_last: 2 }",
        },
    )
    result = runner.invoke(
        app, ["check", str(bad), "--source", str(shop), "--json"], env={"SAFETWIN_KEY": KEY}
    )
    assert result.exit_code == 1
    problems = json.loads(result.stdout)["problems"]
    assert {p["code"] for p in problems} == {"unknown_column", "method_type"}
    assert any("'notes'" in p["message"] for p in problems)
    assert any("redact needs a text column, but the column is date" in p["message"] for p in problems)
    no_key = runner.invoke(app, ["check", str(POLICY), "--source", str(shop)], env={"SAFETWIN_KEY": ""})
    assert no_key.exit_code == 1
    assert "SAFETWIN_KEY" in no_key.stderr


def test_key_commands(tmp_path: Path) -> None:
    printed = runner.invoke(app, ["key", "new", "--print"])
    assert printed.exit_code == 0
    assert len(printed.stdout.strip()) == 64
    assert "WARN" in printed.stderr
    assert printed.stdout.strip() not in printed.stderr
    made = runner.invoke(app, ["key", "new", "--file", str(tmp_path / "k")])
    assert made.exit_code == 0
    assert "(mode 0600); fingerprint " in made.stdout
    assert f"key: file://{tmp_path / 'k'}" in made.stdout
    hex_key = (tmp_path / "k").read_text().strip()
    assert hex_key not in made.stdout + made.stderr
    fp = runner.invoke(app, ["key", "fingerprint", str(POLICY)], env={"SAFETWIN_KEY": KEY})
    assert fp.exit_code == 0
    assert fp.stdout.strip() == MasterKey(bytes.fromhex(KEY)).fingerprint
    assert runner.invoke(app, ["key", "new"]).exit_code == 2
    assert runner.invoke(app, ["mask", str(tmp_path / "missing.yaml")]).exit_code == 2


# --- failure paths ------------------------------------------------------------------------------------------


def test_an_unknown_column_stops_the_run_before_anything_is_written(shop: Path, tmp_path: Path) -> None:
    policy = write_policy(tmp_path, {"      notes:       drop\n": ""})
    out = tmp_path / "safe"
    result = mask(policy, shop, out)
    assert result.exit_code == 1
    (line,) = result.stderr.splitlines()
    assert line.startswith("ERROR [unknown_column] table 'customers': the policy names no method for 'notes'")
    assert not out.exists()


def test_an_integer_collision_fails_and_suggests_hex_or_uuid(
    shop: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(methods, "INT_BITS", 4)  # 16 possible pseudonyms for 1000 customers
    out = tmp_path / "safe"
    result = mask(POLICY, shop, out)
    assert result.exit_code == 1
    assert result.stderr.splitlines()[-1].startswith(
        "ERROR customers.id was unique in the input but not after masking"
    )
    assert "format: hex or format: uuid" in result.stderr
    r = report(out)
    assert r["status"] == "failed"
    assert r["files"] == []
    assert r["uniqueness"][0]["unique_out"] is False
    assert data_files(out) == []  # the twin was removed; the report says why


def test_a_residual_finding_in_a_masked_column_fails(shop: Path, tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path,
        {"      notes:       drop\n": "      notes:       { method: generalize, keep_chars: 200 }\n"},
    )
    out = tmp_path / "safe"
    result = mask(policy, shop, out)
    assert result.exit_code == 1
    assert "residual scan: customers.notes:" in result.stderr
    assert "look like email, in a column that was masked" in result.stderr
    r = report(out)
    (finding,) = r["residual_scan"]["findings"]
    assert finding["column"] == "notes"
    assert finding["detector"] == "email"
    assert finding["level"] == "error"
    assert finding["count"] > 0
    assert data_files(out) == []


def test_a_kept_email_column_is_a_warning_and_fails_with_strict(shop: Path, tmp_path: Path) -> None:
    policy = write_policy(tmp_path, {"{ method: fake, kind: email }": "keep"})
    result = mask(policy, shop, tmp_path / "a")
    assert result.exit_code == 0, result.output
    assert (
        "WARN residual scan: customers.email: 1000 value(s) look like email, in a kept column"
        in result.stderr
    )
    strict = mask(policy, shop, tmp_path / "b", "--strict")
    assert strict.exit_code == 1
    assert strict.stderr.splitlines()[-1].startswith("ERROR --strict: 1 warning(s)")
    assert data_files(tmp_path / "b") == []


def test_json_prints_the_report(shop: Path, tmp_path: Path) -> None:
    result = mask(POLICY, shop, tmp_path / "safe", "--json")
    assert result.exit_code == 0
    assert json.loads(result.stdout) == report(tmp_path / "safe")


def test_ctrl_c_in_the_middle_of_a_run_leaves_nothing(tmp_path: Path) -> None:
    source = tmp_path / "big"
    source.mkdir()
    rows = 3_000_000
    pl.select(
        pl.int_range(rows, dtype=pl.Int64).alias("id"),
        pl.concat_str([pl.lit("person-"), pl.int_range(rows).cast(pl.String)]).alias("name"),
    ).write_parquet(source / "big.parquet")
    policy = tmp_path / "big.yaml"
    policy.write_text(
        "apiVersion: safetwin/v1\nkind: MaskingPolicy\nmetadata: {name: big}\nspec:\n"
        "  source: {folder: big, format: parquet}\n  target: {folder: out}\n  key: env://SAFETWIN_KEY\n"
        "  tables:\n    big:\n      id: {method: pseudonymize}\n"
        "      name: {method: pseudonymize, format: uuid}\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    process = subprocess.Popen(
        [str(SAFETWIN), "mask", str(policy)],
        env={**os.environ, "SAFETWIN_KEY": KEY},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
    )
    deadline = time.monotonic() + 120
    while not (out.exists() and any(".tmp-" in p.name for p in out.rglob("*"))):
        assert process.poll() is None, "the run ended before it could be interrupted"
        assert time.monotonic() < deadline
        time.sleep(0.005)
    process.send_signal(signal.SIGINT)
    stdout, stderr = process.communicate(timeout=120)
    assert process.returncode == 130, stderr
    assert stderr.splitlines()[-1] == "ERROR the run was interrupted: nothing was left in the output folder"
    assert stdout == ""
    assert [p for p in out.rglob("*") if p.is_file()] == []


FAILING = {"      notes:       drop\n": "      notes:       { method: generalize, keep_chars: 200 }\n"}


def test_a_folder_that_isnt_empty_is_refused_and_a_failed_replace_keeps_the_earlier_twin(
    shop: Path, tmp_path: Path
) -> None:
    out = tmp_path / "safe"
    assert mask(POLICY, shop, out).exit_code == 0
    before, first = data_files(out), report(out)
    refused = mask(POLICY, shop, out)
    assert refused.exit_code == 1
    assert "is not empty" in refused.stderr
    assert "--replace" in refused.stderr
    assert data_files(out) == before
    failed = mask(write_policy(tmp_path, FAILING), shop, out, "--replace")
    assert failed.exit_code == 1
    assert data_files(out) == before  # the earlier twin, untouched
    assert report(out) == first
    failed_report = json.loads((out / "failed-report.json").read_text(encoding="utf-8"))
    assert failed_report["status"] == "failed"
    assert failed_report["files"] == []
    assert "the earlier twin in the folder is untouched" in failed_report["errors"][-1]
    assert (out / "failed-report.html").is_file()
    assert not [p for p in out.rglob(".*") if p.name != ".DS_Store"]  # no temporary file left


def test_replace_swaps_in_the_new_twin_once_it_passes(shop: Path, tmp_path: Path) -> None:
    out = tmp_path / "safe"
    assert mask(POLICY, shop, out).exit_code == 0
    assert mask(write_policy(tmp_path, FAILING), shop, out, "--replace").exit_code == 1
    old_ids = set(table(out, "customers")["id"])
    result = mask(POLICY, shop, out, "--replace", key=OTHER_KEY)
    assert result.exit_code == 0, result.output
    r = report(out)
    assert r["status"] == "ok"
    assert sorted(f["path"] for f in r["files"]) == [f for f in data_files(out) if "_manifest" not in f]
    assert not set(table(out, "customers")["id"]) & old_ids  # one part file per table: only the new twin
    manifests = sorted(out.rglob("_manifest/*.json"))
    assert len(manifests) == 2
    assert all(r["run_id"] in m.name for m in manifests)
    assert not (out / "failed-report.json").exists()


def test_replace_refuses_a_folder_without_a_report(shop: Path, tmp_path: Path) -> None:
    out = tmp_path / "safe"
    out.mkdir()
    (out / "mine.txt").write_text("not a twin", encoding="utf-8")
    result = mask(POLICY, shop, out, "--replace")
    assert result.exit_code == 1
    assert "no readable safetwin report.json" in result.stderr
    assert sorted(p.name for p in out.iterdir()) == ["mine.txt"]


def test_ctrl_c_between_the_two_report_files_leaves_nothing(
    shop: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "safe"
    real_replace, calls = os.replace, []

    def interrupted(src: Any, dst: Any) -> None:
        if Path(dst).name.startswith("report."):
            calls.append(Path(dst).name)
            if Path(dst).name == "report.json":  # report.html is in place, report.json not yet
                raise KeyboardInterrupt
        real_replace(src, dst)

    monkeypatch.setattr(mask_run.os, "replace", interrupted)
    with pytest.raises(KeyboardInterrupt):
        mask_run.mask(POLICY, source=shop, out=out, environ={"SAFETWIN_KEY": KEY})
    assert calls == ["report.html", "report.json"]
    assert list(out.rglob("*")) == []


def test_date_shifts_agree_across_tables_through_a_kept_entity(shop: Path, tmp_path: Path) -> None:
    policy = write_policy(
        tmp_path,
        {
            "      id:          { method: pseudonymize, domain: customer }\n": "      id:          keep\n",
            "      customer_id: { method: pseudonymize, domain: customer }\n": "      customer_id: keep\n",
        },
    )
    out = tmp_path / "safe"
    result = mask(policy, shop, out)
    assert result.exit_code == 0, result.output
    shift = lambda col: (pl.col(f"{col}_out") - pl.col(col)).alias(col)  # noqa: E731
    src_c, src_o = pl.read_parquet(shop / "customers.parquet"), pl.read_parquet(shop / "orders.parquet")
    c = src_c.select("id", "created_at").with_columns(
        table(out, "customers")["created_at"].alias("created_at_out")
    )
    o = src_o.select("customer_id", "placed_at").with_columns(
        table(out, "orders")["placed_at"].alias("placed_at_out")
    )
    joined = o.select("customer_id", shift("placed_at")).join(
        c.select("id", shift("created_at")), left_on="customer_id", right_on="id"
    )
    assert joined.height == src_o.height
    assert (joined["placed_at"] == joined["created_at"]).all()


def test_an_entity_that_leads_to_two_columns_is_refused() -> None:
    text = POLICY.read_text(encoding="utf-8")
    for column in ("id:         ", "customer_id:"):
        old = f"      {column} {{ method: pseudonymize, domain: customer }}\n"
        text = text.replace(old, f"      {column} keep\n")
    text = text.replace(
        "    - orders.customer_id -> customers.id\n",
        "    - orders.customer_id -> customers.id\n    - orders.customer_id -> orders.id\n",
    )
    problems = validate_policy(load_policy_text(text))
    assert [p.code for p in problems] == ["entity_domain"]
    assert "2 different columns" in problems[0].message


def test_a_method_that_lets_values_through_is_caught_by_its_output_space(
    shop: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(methods, "fake", lambda series, kind, mac: series)  # input values pass through
    out = tmp_path / "safe"
    result = mask(POLICY, shop, out)
    assert result.exit_code == 1
    findings = report(out)["residual_scan"]["findings"]
    by_column = {f["column"]: f for f in findings}
    assert by_column["email"]["detector"] == "outside_output_space"
    assert by_column["email"]["level"] == "error"
    assert "are not what its method makes" in result.stderr
    assert data_files(out) == []


def test_fake_emails_that_collide_fail_the_run(
    shop: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = portable.fake_value
    same = "ann.lee.aaaaaa@example.com"
    monkeypatch.setattr(portable, "fake_value", lambda h, kind: same if kind == "email" else real(h, kind))
    out = tmp_path / "safe"
    result = mask(POLICY, shop, out)
    assert result.exit_code == 1
    assert "customers.email was unique in the input but not after masking" in result.stderr
    assert "same fake email" in result.stderr
