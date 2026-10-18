"""`safetwin demo` and `safetwin --version`."""

from importlib.metadata import version
from pathlib import Path

import polars as pl
from typer.testing import CliRunner

from safetwin.cli.main import app

runner = CliRunner()


def test_demo_writes_the_shop_and_never_replaces_it(tmp_path: Path) -> None:
    done = runner.invoke(app, ["demo", str(tmp_path / "try")])
    assert done.exit_code == 0, done.output
    data = tmp_path / "try" / "data"
    assert sorted(p.name for p in data.iterdir()) == ["customers.parquet", "orders.parquet"]
    assert pl.read_parquet(data / "customers.parquet").height == 1000
    assert pl.read_parquet(data / "orders.parquet").height == 3000
    assert "next:  cd" in done.stdout
    again = runner.invoke(app, ["demo", str(tmp_path / "try")])
    assert again.exit_code == 1
    assert "is not empty" in again.stderr
    csv = runner.invoke(app, ["demo", str(tmp_path / "csv"), "--csv"])
    assert csv.exit_code == 0, csv.output
    assert len(list((tmp_path / "csv" / "data").glob("*.csv"))) == 2


def test_version() -> None:
    done = runner.invoke(app, ["--version"])
    assert done.exit_code == 0
    assert done.stdout == f"safetwin {version('safetwin')}\n"
