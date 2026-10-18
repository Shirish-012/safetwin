"""`safetwin export --to polars` (docs/guide.md): the exported script reproduces the engine's twin exactly
(same tables, schemas and rows in the same order), on the example shop and on a table that uses every method
and many types; in process on random tables; and it holds no key and no value."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any

import polars as pl
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.export import runner
from safetwin.export.to_polars import export_polars
from safetwin.keys import MasterKey, hkdf_sha256, resolve_key
from safetwin.masking import portable
from safetwin.masking.check import SourceTable
from safetwin.masking.run import Prepared
from safetwin.spec.policy import load_policy_text

from .conftest import KEY_A, run_mask
from .test_mask_run import KEY, POLICY, _generator

cli = CliRunner()
REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def shop(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert _generator().main([str(folder), "--csv"]) == 0
    return folder


def engine(policy: Path, source: Path, out: Path) -> dict[str, Any]:
    done = cli.invoke(
        app, ["mask", str(policy), "--source", str(source), "--out", str(out)], env={"SAFETWIN_KEY": KEY}
    )
    assert done.exit_code == 0, done.output
    report: dict[str, Any] = json.loads((out / "report.json").read_text(encoding="utf-8"))
    return report


def export(policy: Path, source: Path, script: Path) -> None:
    args = ["export", str(policy), "--to", "polars", "--source", str(source), "-o", str(script)]
    done = cli.invoke(app, args)
    assert done.exit_code == 0, done.output


def run_script(script: Path, *args: str, key: str = KEY) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SAFETWIN")} | {"SAFETWIN_KEY": key}
    command = [sys.executable, str(script), *args]
    return subprocess.run(command, capture_output=True, text=True, env=env, check=False, timeout=300)


def read(path: Path, fmt: str) -> pl.DataFrame:
    if fmt == "csv":
        return pl.read_csv(path, infer_schema=False)
    return pl.read_parquet(path)


def assert_same_twin(engine_out: Path, script_out: Path, tables: list[str], fmt: str, skip: Any = ()) -> None:
    for name in tables:
        (engine_file,) = (engine_out / name).glob(f"part-*.{fmt}")
        a, b = read(engine_file, fmt), read(script_out / f"{name}.{fmt}", fmt)
        assert a.schema == b.schema, name
        assert a.height == b.height, name
        for column in a.columns:
            if (name, column) in skip:  # random per row: the same nulls, not the same values
                assert a[column].is_null().equals(b[column].is_null()), (name, column)
            else:
                assert a[column].equals(b[column]), (name, column)


def policy_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "masking.yaml"
    path.write_text(text, encoding="utf-8")
    return path


SHOP = POLICY.read_text(encoding="utf-8")
SUBSET = "  subset:\n    root: customers\n    fraction: 0.10\n"
CSV = """apiVersion: safetwin/v1
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
      birth_date: {method: generalize, keep_chars: 4}
      notes: {method: redact, with: "[REDACTED]"}
      city: keep
    orders:
      customer_id: {method: pseudonymize, domain: customer, prefix: c_}
      card_number: {method: redact, keep_last: 4}
      ip_address: {method: generalize, ip: true}
  relationships: [orders.customer_id -> customers.id]
  subset: {root: customers, fraction: 0.2}
"""


@pytest.mark.parametrize(
    ("variant", "text", "fmt"),
    [("parquet", SHOP, "parquet"), ("subset", SHOP + SUBSET, "parquet"), ("csv", CSV, "csv")],
)
def test_the_exported_shop_reproduces_the_engine(
    shop: Path, tmp_path: Path, variant: str, text: str, fmt: str
) -> None:
    policy = policy_file(tmp_path, text)
    report = engine(policy, shop, tmp_path / "engine")
    script = tmp_path / "job" / "mask_shop.py"
    script.parent.mkdir()
    export(policy, shop, script)
    done = run_script(script, "--target", str(tmp_path / "script"))
    assert done.returncode == 0, done.stderr
    assert_same_twin(tmp_path / "engine", tmp_path / "script", ["customers", "orders"], fmt)
    # The script's own checks agree with the report.
    for name, facts in report["tables"].items():
        assert f"{name:<9}  {facts['rows_in']:,} → {facts['rows_out']:,} rows" in done.stdout
    assert "relationships: 1 checked, 0 orphans" in done.stdout
    assert f"key fingerprint {report['key_fingerprint']}" in done.stdout


KITCHEN = """apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {name: kitchen}
spec:
  source: {folder: ./data, format: parquet}
  target: {folder: ./safe}
  key: env://SAFETWIN_KEY
  unknown_columns: "null"
  tables:
    people:
      id: {method: pseudonymize}
      big: {method: pseudonymize, format: hex, prefix: "b_"}
      code: {method: pseudonymize, domain: code}
      tier: {method: generalize, keep_chars: 2}
      token: {method: pseudonymize, format: uuid}
      token_text: {method: pseudonymize, format: uuid}
      seen_at: {method: date_shift, entity: code, max_days: 400}
      born: {method: date_shift, entity: id}
      score: {method: pseudonymize, format: hex}
      amount: {method: pseudonymize, format: hex}
      active: {method: pseudonymize, format: hex}
      age: {method: generalize, bins: [0, 18, 30, 65]}
      weight: {method: generalize, bucket: 2.5}
      rank: {method: generalize, bucket: 10}
      name: {method: fake, kind: name, consistent: false}
      first: {method: fake, kind: first_name}
      last: {method: fake, kind: last_name}
      email: {method: fake, kind: email}
      phone: {method: fake, kind: phone}
      street: {method: fake, kind: street}
      town: {method: fake, kind: city}
      employer: {method: fake, kind: company}
      note: {method: fake, kind: text}
      ip: {method: generalize, ip: true}
      secret: {method: redact, keep_first: 2, char: "#"}
      card: {method: redact, keep_last: 4}
      ssn: {method: redact, with: "[removed]"}
      month: {method: generalize, to: month}
      week: {method: generalize, to: week}
      day: {method: generalize, to: day}
      gone: "null"
      dropped: drop
      kept: keep
"""


TIERS = ["gold", "silver", "bronze"]
START = datetime(2024, 1, 1, tzinfo=UTC)
NANOS = pl.Datetime("ns")
ZONE = "Asia/Kolkata"


def kitchen_data(folder: Path, n: int = 400) -> None:
    ids = list(range(1, n + 1))
    folder.mkdir()
    pl.DataFrame(
        {
            "id": pl.Series(ids, dtype=pl.Int32),
            "big": pl.Series([2**64 - 1 - i for i in ids], dtype=pl.UInt64),
            "code": pl.Series([f"C{i % 97:03d}" for i in ids], dtype=pl.Categorical),
            "tier": pl.Series([TIERS[i % 3] for i in ids], dtype=pl.Enum(TIERS)),
            "token": pl.Series([uuid.UUID(int=i).bytes for i in ids], dtype=pl.Binary),
            "token_text": [str(uuid.UUID(int=i * 7919)) if i % 9 else None for i in ids],
            "seen_at": pl.Series([START + timedelta(hours=7 * i) for i in ids]).dt.convert_time_zone(ZONE),
            "born": [date(1950, 1, 1) + timedelta(days=37 * i) for i in ids],
            "score": [float("nan") if i % 11 == 0 else -0.0 if i % 13 == 0 else i / 7 for i in ids],
            "amount": pl.Series([Decimal(f"{i}.{i % 10}0") for i in ids], dtype=pl.Decimal(10, 2)),
            "active": [None if i % 17 == 0 else i % 3 == 0 for i in ids],
            "age": pl.Series([None if i % 23 == 0 else i % 90 - 5 for i in ids], dtype=pl.Int16),
            "weight": pl.Series([50 + (i % 40) * 1.37 for i in ids], dtype=pl.Float32),
            "rank": pl.Series([i * 3 for i in ids], dtype=pl.Int64),
            "name": [None if i % 5 == 0 else f"Person {i}" for i in ids],
            "first": [f"F{i % 50}" for i in ids],
            "last": [f"L{i % 60}" for i in ids],
            "email": [f"user{i}@corp.test" for i in ids],
            "phone": [f"P-{i}" for i in ids],
            "street": [f"S{i}" for i in ids],
            "town": [f"T{i % 7}" for i in ids],
            "employer": [f"E{i % 11}" for i in ids],
            "note": [None if i % 4 == 0 else f"a note, number {i}" for i in ids],
            "ip": [f"10.1.{i % 256}.{i % 200}" if i % 5 else f"2001:db8:{i:x}::1" for i in ids],
            "secret": [f"S-{i:06d}" for i in ids],
            "card": [f"x{i:08d}" for i in ids],
            "ssn": [f"N{i}" for i in ids],
            "month": [datetime(2023, 1, 1) + timedelta(hours=13 * i) for i in ids],
            "week": [date(2023, 1, 1) + timedelta(days=3 * i) for i in ids],
            "day": pl.Series([datetime(2023, 1, 1) + timedelta(minutes=97 * i) for i in ids], dtype=NANOS),
            "gone": [f"g{i}" for i in ids],
            "dropped": [f"d{i}" for i in ids],
            "kept": [i % 3 for i in ids],
            "extra": [f"x{i}" for i in ids],
        }
    ).write_parquet(folder / "people.parquet")


def test_every_method_and_type_exports_exactly(tmp_path: Path) -> None:
    kitchen_data(tmp_path / "data")
    policy = policy_file(tmp_path, KITCHEN)
    report = engine(policy, tmp_path / "data", tmp_path / "engine")
    assert report["status"] == "ok", report["errors"]
    script = tmp_path / "mask_kitchen.py"
    export(policy, tmp_path / "data", script)
    done = run_script(script, "--target", str(tmp_path / "script"))
    assert done.returncode == 0, done.stderr
    random_column = {("people", "name")}
    assert_same_twin(tmp_path / "engine", tmp_path / "script", ["people"], "parquet", skip=random_column)


def test_the_script_holds_no_key_no_value_and_is_clean_python(shop: Path, tmp_path: Path) -> None:
    policy = policy_file(tmp_path, SHOP + SUBSET)
    script = tmp_path / "mask_shop.py"
    export(policy, shop, script)
    text = script.read_text(encoding="utf-8")
    assert KEY not in text
    assert 'key="env://SAFETWIN_KEY"' in text
    values: set[str] = set()
    for name in ("customers", "orders"):
        frame = pl.read_csv(shop / f"{name}.csv", infer_schema=False)
        for column in frame.columns:
            values |= {v for v in frame[column].drop_nulls().to_list() if len(v) >= 5}
    assert [v for v in values if v in text] == []
    rules = ["--select=E9,E501,F", "--line-length=110"]  # syntax, long lines, undefined or unused names
    lint = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "--isolated", *rules, str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert lint.returncode == 0, lint.stdout  # no undefined or unused name
    formatted = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--isolated", "--line-length=110", "--check", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert formatted.returncode == 0, formatted.stdout
    assert f"SHA-256 {hashlib.sha256(policy.read_bytes()).hexdigest()}." in " ".join(text.split())


def test_a_name_cannot_break_out_of_the_script(tmp_path: Path) -> None:
    folder = tmp_path / "data"
    folder.mkdir()
    evil = 'a"\nimport os; os.system("echo pwned")\n#'
    pl.DataFrame({evil: ["x", "y"], "id": [1, 2]}).write_parquet(folder / "t.parquet")
    policy = policy_file(
        tmp_path,
        "apiVersion: safetwin/v1\nkind: MaskingPolicy\nmetadata: {name: evil}\nspec:\n"
        "  source: {folder: ./data, format: parquet}\n  target: {folder: ./safe}\n  key: env://SAFETWIN_KEY\n"
        "  unknown_columns: drop\n  tables:\n    t:\n      id: {method: pseudonymize}\n",
    )
    script = tmp_path / "mask.py"
    export(policy, folder, script)
    text = script.read_text(encoding="utf-8")
    assert "\nimport os; os.system" not in text
    done = run_script(script, "--target", str(tmp_path / "out"))
    assert done.returncode == 0, done.stderr
    assert "pwned" not in done.stdout


def test_the_script_refuses_a_changed_source_and_files_it_would_replace(shop: Path, tmp_path: Path) -> None:
    policy = policy_file(tmp_path, SHOP)
    script = tmp_path / "mask_shop.py"
    export(policy, shop, script)
    out = tmp_path / "out"
    assert run_script(script, "--source", str(shop), "--target", str(out)).returncode == 0
    again = run_script(script, "--source", str(shop), "--target", str(out))
    assert again.returncode == 1
    assert "give --replace" in again.stderr
    assert run_script(script, "--source", str(shop), "--target", str(out), "--replace").returncode == 0
    changed = tmp_path / "changed"
    changed.mkdir()
    pl.read_parquet(shop / "customers.parquet").with_columns(pl.lit(1).alias("new")).write_parquet(
        changed / "customers.parquet"
    )
    (changed / "orders.parquet").write_bytes((shop / "orders.parquet").read_bytes())
    refused = run_script(script, "--source", str(changed), "--target", str(tmp_path / "out2"))
    assert refused.returncode == 1
    assert "table 'customers': its columns or types are not those of the export" in refused.stderr
    assert not (tmp_path / "out2").exists() or list((tmp_path / "out2").iterdir()) == []
    no_key = run_script(script, "--source", str(shop), "--target", str(tmp_path / "out3"), key="")
    assert no_key.returncode == 1
    assert "SAFETWIN_KEY" in no_key.stderr


def test_a_failed_check_or_ctrl_c_leaves_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "in"
    source.mkdir()
    pl.DataFrame({"id": [1, 2, 3]}).write_parquet(source / "t.parquet")
    monkeypatch.setenv("SAFETWIN_KEY", KEY)

    def job(mask: Any) -> runner.Job:
        table = runner.Table("t", "t.parquet", {"id": "Int64"}, mask, unique=("id",))
        out = str(tmp_path / "out")
        return runner.Job("t", "env://SAFETWIN_KEY", str(source), "parquet", ",", out, "parquet", (table,))

    collide = job(lambda frame, keys: frame.select((pl.col("id") * 0 + 7).alias("id")))
    assert runner.main(collide, tmp_path, []) == 1
    assert list((tmp_path / "out").iterdir()) == []

    def interrupt(frame: pl.LazyFrame, keys: Any) -> pl.LazyFrame:
        raise KeyboardInterrupt

    assert runner.main(job(interrupt), tmp_path, []) == 130
    assert list((tmp_path / "out").iterdir()) == []
    ok = job(lambda frame, keys: frame.select(runner.pseudonymize("id", keys.mac("p", "t"), "int")))
    assert runner.main(ok, tmp_path, []) == 0
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["t.parquet"]


def test_export_cli(shop: Path, tmp_path: Path) -> None:
    policy = policy_file(tmp_path, SHOP)
    printed = cli.invoke(app, ["export", str(policy), "--source", str(shop)], env={"SAFETWIN_KEY": ""})
    assert printed.exit_code == 0, printed.output  # no key needed to export
    assert printed.stdout.startswith('"""Write the safe twin of shop-to-staging')
    later = cli.invoke(app, ["export", str(policy), "--to", "sql"])
    assert later.exit_code == 2
    target = tmp_path / "mask.py"
    target.write_text("mine\n", encoding="utf-8")
    refused = cli.invoke(app, ["export", str(policy), "--source", str(shop), "-o", str(target)])
    assert refused.exit_code == 1
    assert "give --force" in refused.stderr
    assert target.read_text(encoding="utf-8") == "mine\n"


# --- the portable core agrees with the engine's key code ---------------------------------------------------


def test_the_portable_key_code_agrees_with_safetwin_keys(tmp_path: Path) -> None:
    raw = bytes(range(32))
    for method, domain in [("pseudonymize", "customer"), ("subset", "orders"), ("fake", "t.é")]:
        info = f"safetwin/v1/{method}/{domain}".encode()
        assert portable.hkdf_sha256(raw, info) == hkdf_sha256(raw, None, info)
    assert portable.Keys(raw).fingerprint == MasterKey(raw).fingerprint
    assert portable.read_key("env://K", {"K": raw.hex()}) == raw
    key_file = tmp_path / "k"
    key_file.write_text(raw.hex() + "\n", encoding="ascii")
    key_file.chmod(0o600)
    assert portable.read_key(f"file://{key_file}") == bytes.fromhex(
        resolve_key(f"file://{key_file}").hex_for_key_file()
    )
    key_file.chmod(0o640)
    with pytest.raises(portable.KeyProblem, match="chmod 600"):
        portable.read_key(f"file://{key_file}")
    with pytest.raises(portable.KeyProblem):
        portable.read_key(raw.hex())


# --- in process: the exported functions against the engine's step, on random tables ------------------------

RANDOM_POLICY = """apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {name: random}
spec:
  source: {folder: ., format: parquet}
  target: {folder: ./safe}
  key: env://K
  tables:
    t:
"""
RANDOM_SPECS: dict[str, Any] = {
    "i": {"method": "pseudonymize"},
    "s": {"method": "pseudonymize", "format": "hex", "prefix": "p_"},
    "u": {"method": "pseudonymize", "format": "uuid"},
    "e": {"method": "fake", "kind": "email"},
    "x": {"method": "fake", "kind": "text"},
    "r": {"method": "redact", "keep_last": 2},
    "k": {"method": "generalize", "keep_chars": 3},
    "d": {"method": "date_shift", "entity": "i", "max_days": 3650},
    "b": {"method": "generalize", "bucket": 7},
    "n": {"method": "generalize", "bins": [-100, 0, 100]},
    "w": {"method": "generalize", "to": "week"},
    "q": "null",
}
RANDOM_SCHEMA = pl.Schema(
    {
        "i": pl.Int64(), "s": pl.String(), "u": pl.String(), "e": pl.String(), "x": pl.String(),
        "r": pl.String(), "k": pl.String(), "d": pl.Date(), "b": pl.Int64(), "n": pl.Int32(), "w": pl.Date(),
        "q": pl.String(),
    }
)  # fmt: skip


@pytest.fixture(scope="module")
def exported(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    """The exported script of `RANDOM_POLICY`, imported as a module."""
    lines = "".join(
        f"      {c}: {s if isinstance(s, str) else json.dumps(s)}\n" for c, s in RANDOM_SPECS.items()
    )
    policy = load_policy_text(RANDOM_POLICY + lines)
    folder = tmp_path_factory.mktemp("exported")
    prepared = Prepared(policy, b"", None, folder, {"t": SourceTable("t", "t.parquet", [], RANDOM_SCHEMA)})
    path = folder / "mask_random.py"
    path.write_text(export_polars(prepared, folder / "masking.yaml", "0" * 64, path), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("mask_random", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["mask_random"] = module
    spec.loader.exec_module(module)
    return module


texts = st.one_of(st.none(), st.text(st.characters(blacklist_categories=("Cs",)), max_size=12))
dates = st.one_of(st.none(), st.dates(date(1000, 1, 1), date(9000, 12, 31)))
ints = st.one_of(st.none(), st.integers(-(2**63), 2**63 - 1))


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.lists(st.tuples(ints, texts, texts, texts, dates, st.integers(-1000, 1000), dates), max_size=40))
def test_random_tables_mask_the_same_in_the_script(exported: ModuleType, rows: list[tuple[Any, ...]]) -> None:
    i, s, x, k, d, b, w = (list(col) for col in zip(*rows, strict=True)) if rows else ([],) * 7
    uuids = [str(uuid.UUID(int=abs(v) % (1 << 128))) if v is not None else None for v in i]
    frame = pl.DataFrame(
        {"i": i, "s": s, "u": uuids, "e": x, "x": x, "r": s, "k": k, "d": d, "b": b, "n": b, "w": w, "q": k},
        schema=RANDOM_SCHEMA,
    )
    expected = run_mask(frame, RANDOM_SPECS)
    got = exported.mask_t(frame.lazy(), exported.Keys(bytes.fromhex("a1" * 32))).collect()
    assert KEY_A.fingerprint == exported.Keys(bytes.fromhex("a1" * 32)).fingerprint
    assert got.schema == expected.schema
    for column in expected.columns:
        assert got[column].equals(expected[column]), column
