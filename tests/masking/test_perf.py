"""Masking speed (docs/internals.md): pseudonymize throughput per core, and a full `safetwin mask` of the
example shop at a million rows. Run with `pytest -m perf -s` (scripts/check.sh --perf); the numbers are
printed."""

import importlib.util
import json
import time
from pathlib import Path
from typing import Any

import polars as pl
import pytest
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.masking import methods

from .conftest import mac

pytestmark = pytest.mark.perf
REPO = Path(__file__).resolve().parents[2]
MILLION = 1_000_000


def _rate(series: pl.Series, fmt: str) -> float:
    m = mac("pseudonymize", "perf")
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        out = methods.pseudonymize(series, m, fmt)
        best = min(best, time.perf_counter() - started)
        assert out.len() == series.len()
    return series.len() / best


@pytest.mark.parametrize(
    ("label", "series", "fmt", "gate"),
    [
        ("1M distinct int64, format int", pl.Series(range(MILLION), dtype=pl.Int64), "int", 1_000_000),
        (
            "1M distinct text, format hex",
            pl.Series([f"user{i}@example.com" for i in range(MILLION)]),
            "hex",
            800_000,
        ),
        (
            "1M int64 with 10k distinct, format int",
            pl.Series([i % 10_000 for i in range(MILLION)]),
            "int",
            5_000_000,
        ),
        (
            "1M text with 10k distinct, format hex",
            pl.Series([f"u{i % 10_000}" for i in range(MILLION)]),
            "hex",
            5_000_000,
        ),
    ],
    ids=["int-distinct", "text-distinct", "int-10k", "text-10k"],
)
def test_pseudonymize_throughput_per_core(label: str, series: pl.Series, fmt: str, gate: int) -> None:
    rate = _rate(series, fmt)
    print(f"\npseudonymize {label}: {rate / 1e6:.2f}M values/s (one core; gate {gate / 1e6:.1f}M)")
    assert rate >= gate


def test_a_full_mask_of_the_example_at_a_million_rows(tmp_path: Path) -> None:
    spec = importlib.util.spec_from_file_location("shop_generate", REPO / "examples" / "shop" / "generate.py")
    assert spec is not None
    assert spec.loader is not None
    generator: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    customers, orders = generator.generate(250_000, orders_per_customer=3)  # 250k + 750k = 1M rows
    source = tmp_path / "shop"
    source.mkdir()
    customers.write_parquet(source / "customers.parquet")
    orders.write_parquet(source / "orders.parquet")
    started = time.perf_counter()
    result = CliRunner().invoke(
        app,
        [
            "mask",
            str(REPO / "examples" / "shop" / "masking.yaml"),
            "--source",
            str(source),
            "--out",
            str(tmp_path / "safe"),
        ],
        env={"SAFETWIN_KEY": "e5" * 32},
    )
    elapsed = time.perf_counter() - started
    assert result.exit_code == 0, result.output
    report = json.loads((tmp_path / "safe" / "report.json").read_text())
    rows = sum(t["rows_out"] for t in report["tables"].values())
    assert rows == 1_000_000
    assert report["status"] == "ok"
    print(f"\nsafetwin mask of the example shop, {rows:,} rows (checks and report included): {elapsed:.2f} s")
    assert elapsed < 60
