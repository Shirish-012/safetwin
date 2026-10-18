"""`encrypt`, the reversible method: AES-SIV with the access key, `key access` and `unmask`."""

import os
import stat
from datetime import UTC, date, datetime, time
from decimal import Decimal
from pathlib import Path

import polars as pl
import pytest
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.keys import MasterKey
from safetwin.masking import portable
from safetwin.masking.portable import SEALED_PATTERN, Sealer, SealProblem, decrypt_series, encrypt_series
from safetwin.masking.scan import make_reversible, render
from safetwin.masking.scan import scan as run_scan
from safetwin.spec.policy import load_policy_text, validate_policy

from .conftest import KEY_A, KEY_B, run_mask
from .test_export import assert_same_twin, export, policy_file, run_script
from .test_mask_run import KEY, _generator

cli = CliRunner()
SEALER = Sealer(KEY_A.access_key())

COLUMNS = {
    "int": pl.Series([1, -7, None, 1, 2**62], dtype=pl.Int64),
    "int32": pl.Series([5, None, -3, 5, 0], dtype=pl.Int32),
    "big": pl.Series([2**64 - 1, 3, None, 2**64 - 1, 0], dtype=pl.UInt64),
    "text": pl.Series(["ann@example.org", "", None, "ann@example.org", "ü 名前"], dtype=pl.String),
    "cat": pl.Series(["a", "b", None, "a", "c"], dtype=pl.Categorical),
    "bytes": pl.Series([b"\x00\x01", b"", None, b"\x00\x01", b"x"], dtype=pl.Binary),
    "day": pl.Series([date(1970, 1, 1), date(1899, 12, 31), None, date(2026, 10, 17), date(1, 1, 1)]),
    "naive": pl.Series(
        [datetime(2024, 2, 29, 23, 59, 59, 999999), None, datetime(1960, 1, 1)] * 1 + [None, None]
    ),
    "zoned": pl.Series(
        [datetime(2024, 1, 1, 12, tzinfo=UTC), None, None, None, None], dtype=pl.Datetime("us", "UTC")
    ),
    "clock": pl.Series([time(0, 0), time(23, 59, 59, 999999), None, time(12), None]),
    "flag": pl.Series([True, False, None, True, False]),
    "real": pl.Series([1.5, -0.0, None, float("inf"), 1e-300]),
    "money": pl.Series(
        [Decimal("10.25"), Decimal("-3.10"), None, Decimal("0.00"), Decimal("7")], dtype=pl.Decimal(10, 2)
    ),
}


@pytest.mark.parametrize("name", list(COLUMNS))
def test_every_plain_type_comes_back_equal(name: str) -> None:
    series = COLUMNS[name].alias(name)
    sealed = encrypt_series(series, SEALER)
    assert sealed.dtype == pl.String
    assert sealed.is_null().equals(series.is_null())
    assert sealed.drop_nulls().str.contains(SEALED_PATTERN).all()
    back = decrypt_series(sealed, SEALER)
    expected = series.cast(pl.String) if name == "cat" else series
    if name == "money":  # a normalized decimal: the same numbers
        assert back.cast(pl.Float64).equals(expected.cast(pl.Float64))
    else:
        assert back.cast(expected.dtype).equals(expected), (back, expected)


def test_it_is_deterministic_and_hides_lengths_to_16_bytes() -> None:
    a = encrypt_series(pl.Series(["x", "x", "y" * 14, "y" * 15]), SEALER)
    assert a[0] == a[1]
    assert len(a[0]) == len(a[2])  # 2 and 15 bytes with the tag both pad to one block
    assert len(a[3]) > len(a[2])  # 16 bytes need a second block (the padding adds at least a byte)
    other = encrypt_series(pl.Series(["x"]), Sealer(KEY_B.access_key()))
    assert other[0] != a[0]


def test_a_changed_value_or_another_key_does_not_decrypt() -> None:
    sealed = encrypt_series(pl.Series("email", ["ann@example.org", "bob@example.org"]), SEALER)
    flipped = sealed[0][:-2] + ("A" if sealed[0][-2] != "A" else "B") + sealed[0][-1]
    with pytest.raises(SealProblem) as changed:
        decrypt_series(pl.Series("email", [flipped, sealed[1]]), SEALER)
    assert "ann" not in str(changed.value)
    with pytest.raises(SealProblem, match="2 distinct value"):
        decrypt_series(sealed, Sealer(KEY_B.access_key()))


def test_the_access_key_is_derived_the_same_way_by_the_engine_and_the_script() -> None:
    raw = bytes.fromhex("a1" * 32)
    assert KEY_A.access_key() == portable.access_key(raw)
    assert portable.Keys(raw).sealer().fingerprint == SEALER.fingerprint
    assert KEY_A.access_key() != raw
    assert "a1a1" not in repr(SEALER)


def test_the_mask_step_encrypts_and_relationships_need_the_same_method_on_both_sides() -> None:
    frame = pl.DataFrame({"id": [1, 2, 1], "email": ["a@x.org", None, "a@x.org"]})
    out = run_mask(frame, {"id": "encrypt", "email": {"method": "encrypt"}})
    assert out["id"][0] == out["id"][2]
    assert out["email"][1] is None
    base = """apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {name: p}
spec:
  source: {folder: ./in, format: parquet}
  target: {folder: ./out}
  key: env://SAFETWIN_KEY
  tables:
    a: {id: encrypt_or}
    b: {a_id: encrypt_or_b}
  relationships: [b.a_id -> a.id]
"""
    both = base.replace("encrypt_or_b", "{method: encrypt}").replace("encrypt_or", "{method: encrypt}")
    assert not validate_policy(load_policy_text(both))
    mixed = base.replace("encrypt_or_b", "{method: pseudonymize}").replace("encrypt_or", "{method: encrypt}")
    assert [p.code for p in validate_policy(load_policy_text(mixed))] == ["relationship_domain"]


@pytest.fixture(scope="module")
def shop(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert _generator().main([str(folder)]) == 0
    return folder


def _reversible_policy(shop: Path, tmp_path: Path, tables: list[str] | None = None) -> Path:
    result = run_scan(shop, fmt="parquet")
    make_reversible(result, tables)
    text = render(result, source=str(shop), name="shop", target=str(tmp_path / "safe"))
    return policy_file(tmp_path, text)


def test_a_reversible_twin_reads_back_to_the_source_and_the_script_agrees(shop: Path, tmp_path: Path) -> None:
    policy = _reversible_policy(shop, tmp_path)
    done = cli.invoke(app, ["mask", str(policy)], env={"SAFETWIN_KEY": KEY})
    assert done.exit_code == 0, done.output
    assert "0 orphans" in done.stdout
    script = tmp_path / "job" / "mask.py"
    script.parent.mkdir()
    export(policy, shop, script)
    assert "cryptography package" in script.read_text(encoding="utf-8")
    ran = run_script(script, "--target", str(tmp_path / "script"))
    assert ran.returncode == 0, ran.stderr
    assert_same_twin(tmp_path / "safe", tmp_path / "script", ["customers", "orders"], "parquet")

    access = tmp_path / "keys" / "access.key"
    made = cli.invoke(app, ["key", "access", str(policy), "--file", str(access)], env={"SAFETWIN_KEY": KEY})
    assert made.exit_code == 0, made.output
    assert stat.S_IMODE(os.stat(access).st_mode) == 0o600
    assert KEY not in made.output
    back = cli.invoke(
        app, ["unmask", str(tmp_path / "safe"), "--key", f"file://{access}", "--out", str(tmp_path / "r")]
    )
    assert back.exit_code == 0, back.output
    for table in ("customers", "orders"):
        original = pl.read_parquet(shop / f"{table}.parquet")
        readable = pl.read_parquet(tmp_path / "r" / f"{table}.parquet")
        assert readable.columns == original.columns
        for column in original.columns:
            assert readable[column].cast(original[column].dtype).equals(original[column]), (table, column)

    # The masking key works too; another key writes nothing; a one-way twin decrypts nothing.
    again = cli.invoke(
        app,
        ["unmask", str(tmp_path / "safe"), "--policy", str(policy), "--out", str(tmp_path / "r2")],
        env={"SAFETWIN_KEY": KEY},
    )
    assert again.exit_code == 0, again.output
    wrong = cli.invoke(
        app,
        ["unmask", str(tmp_path / "safe"), "--policy", str(policy), "--out", str(tmp_path / "r3")],
        env={"SAFETWIN_KEY": "e5" * 32},
    )
    assert wrong.exit_code == 1
    assert "don't decrypt with this key" in wrong.stderr
    assert not list((tmp_path / "r3").iterdir())


def test_a_link_to_a_one_way_table_stays_one_way(shop: Path, tmp_path: Path) -> None:
    result = run_scan(shop, fmt="parquet")
    make_reversible(result, ["customers"])
    customers, orders = result.tables["customers"].suggestions, result.tables["orders"].suggestions
    assert customers["email"].method == {"method": "encrypt"}
    assert customers["id"].method == orders["customer_id"].method
    assert customers["id"].method["method"] == "pseudonymize"
    assert all(s.method["method"] != "encrypt" for s in orders.values())


def test_unmask_of_a_one_way_twin_says_nothing_was_encrypted(shop: Path, tmp_path: Path) -> None:
    result = run_scan(shop, fmt="parquet")
    policy = policy_file(
        tmp_path, render(result, source=str(shop), name="shop", target=str(tmp_path / "safe"))
    )
    assert cli.invoke(app, ["mask", str(policy)], env={"SAFETWIN_KEY": KEY}).exit_code == 0
    done = cli.invoke(
        app,
        ["unmask", str(tmp_path / "safe"), "--policy", str(policy), "--out", str(tmp_path / "r")],
        env={"SAFETWIN_KEY": KEY},
    )
    assert done.exit_code == 0, done.output
    assert "no column was encrypted" in done.stderr


def test_master_key_object_never_shows_the_access_key() -> None:
    key = MasterKey(bytes.fromhex("c3" * 32))
    assert key.access_key().hex() not in repr(key)


def test_rekey_gives_what_masking_with_the_new_key_gives(shop: Path, tmp_path: Path) -> None:
    policy = _reversible_policy(shop, tmp_path)
    new = "e5" * 32
    for key, out in ((KEY, "old"), (new, "new")):
        done = cli.invoke(app, ["mask", str(policy), "--out", str(tmp_path / out)], env={"SAFETWIN_KEY": key})
        assert done.exit_code == 0, done.output
    args = ["rekey", str(tmp_path / "old"), "--out", str(tmp_path / "rekeyed")]
    args += ["--from-policy", str(policy), "--to", "env://NEW_ACCESS"]
    new_access = MasterKey(bytes.fromhex(new)).access_key().hex()
    done = cli.invoke(app, args, env={"SAFETWIN_KEY": KEY, "NEW_ACCESS": new_access})
    assert done.exit_code == 0, done.output
    assert new_access not in done.output
    for table in ("customers", "orders"):
        (direct,) = (tmp_path / "new" / table).glob("part-*.parquet")
        rekeyed = pl.read_parquet(tmp_path / "rekeyed" / f"{table}.parquet")
        expected = pl.read_parquet(direct)
        encrypted = [
            c for c in expected.columns if expected[c].dtype == pl.String and portable.is_sealed(expected[c])
        ]
        assert encrypted
        for column in encrypted:
            assert rekeyed[column].equals(expected[column]), (table, column)
    stale = cli.invoke(
        app,
        ["unmask", str(tmp_path / "rekeyed"), "--policy", str(policy), "--out", str(tmp_path / "r")],
        env={"SAFETWIN_KEY": KEY},
    )
    assert stale.exit_code == 1
    same = cli.invoke(
        app, [*args[:4], "--from-policy", str(policy), "--to-policy", str(policy)], env={"SAFETWIN_KEY": KEY}
    )
    assert same.exit_code == 1
    assert "the same" in same.stderr
