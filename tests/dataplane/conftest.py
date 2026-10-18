"""Fixtures for the data plane tests: a messy CSV, folders for the sockets, and pipelines to run.

The helpers are fixtures because test modules (imported with `--import-mode=importlib`) can't import this
file.
"""

import csv
import random
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import polars as pl
import pytest

from safetwin.dataplane.runtime import StageResult
from safetwin.spec import Pipeline

HEADER = ["id", "name", "city", "amount", "signup", "note"]

# Names and cities with whitespace to trim (spaces, a tab), accents and other scripts, a comma, quotes and a
# line break inside quotes. Dates in the formats `parse_dates` knows and in some it doesn't (nulls).
NAMES = [
    "Alice",
    "  Bob",
    "Carol  ",
    "\tDave ",
    " Eve ",
    "Zoë",
    "日本語",
    "",
    "O'Brien, Jr.",
    'say "hi"',
    "a\nb",
]
CITIES = ["Berlin", " Paris", "Rome ", "  Madrid  ", "", "Wien"]
DATES = [
    "2026-01-05 10:00:00",
    "2026-01-05T10:00:00Z",
    "2026-01-05T10:00:00+05:30",
    "2026-02-11",
    "2026-03-01 23:59:59.250",
    "not a date",
    "2026-13-45",
    "",
    "05/01/2026",
]

Node = dict[str, Any]


@dataclass(frozen=True)
class Sockets:
    """Two empty folders, the inbox and the outbox, and the `sockets` argument of `run_pipeline_local`."""

    inbox: Path
    outbox: Path

    @property
    def folders(self) -> dict[str, Path]:
        return {"inbox": self.inbox, "outbox": self.outbox}

    def written(self) -> list[str]:
        """Every file in the outbox, by path below it. A temporary file or a stray manifest would show."""
        return sorted(str(p.relative_to(self.outbox)) for p in self.outbox.rglob("*") if p.is_file())


class Data:
    """Makes CSV files and reads what a stage wrote."""

    header = HEADER

    @staticmethod
    def messy_rows(count: int, seed: int = 7, first_id: int = 0) -> list[list[str]]:
        """Rows with one in ten without an id, amounts that are not numbers, and bad dates."""
        rng = random.Random(seed)
        rows = []
        for number in range(first_id, first_id + count):
            amount = rng.choice([f"{rng.random() * 1000:.2f}", "n/a", ""])
            rows.append(
                [
                    "" if rng.random() < 0.1 else str(number),
                    rng.choice(NAMES),
                    rng.choice(CITIES),
                    amount,
                    rng.choice(DATES),
                    f"note {number % 13}",
                ]
            )
        return rows

    @staticmethod
    def write_csv(path: Path, rows: Iterable[Sequence[str]], header: Sequence[str] | None = HEADER) -> Path:
        with path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            if header is not None:
                writer.writerow(header)
            writer.writerows(rows)
        return path

    @staticmethod
    def dataset(result: StageResult) -> pl.DataFrame:
        """The rows a stage wrote."""
        return pl.read_parquet([file.path for file in result.files])


class Nodes:
    """Builders for node documents and pipelines."""

    @staticmethod
    def read(node_id: str = "read", path: str = "*.csv", **config: Any) -> Node:
        return {
            "id": node_id,
            "operator": "source.csv",
            "socket": "inbox",
            "config": {"path": path, **config},
        }

    @staticmethod
    def step(node_id: str, operator: str, source: str, **config: Any) -> Node:
        return {"id": node_id, "operator": operator, "inputs": [source], "config": config}

    @staticmethod
    def write(node_id: str, source: str, path: str = "data/", **config: Any) -> Node:
        return {
            "id": node_id,
            "operator": "sink.parquet",
            "inputs": [source],
            "socket": "outbox",
            "config": {"path": path, **config},
        }

    @staticmethod
    def pipeline(*nodes: Node, name: str = "test", **spec: Any) -> Pipeline:
        """A batch pipeline around `nodes`, with the sockets `inbox` and `outbox`."""
        return Pipeline.model_validate(
            {
                "apiVersion": "safetwin/v1",
                "kind": "Pipeline",
                "metadata": {"name": name},
                "spec": {
                    "sockets": {"inbox": "socket://local-inbox", "outbox": "socket://local-outbox"},
                    "nodes": list(nodes),
                    **spec,
                },
            }
        )

    @staticmethod
    def copy(path: str = "data/", **config: Any) -> Pipeline:
        """Read the CSV files and write them unchanged."""
        return Nodes.pipeline(Nodes.read(**config), Nodes.write("write", "read", path=path))

    @staticmethod
    def messy() -> Pipeline:
        """Every Phase 0 operator, on the columns of `Data.messy_rows`."""
        n = Nodes
        return n.pipeline(
            n.read(),
            n.step("has_id", "transform.filter", "read", expr="id IS NOT NULL"),
            n.step("tidy", "transform.trim", "has_id", columns=["name", "city"]),
            n.step("dates", "transform.parse_dates", "tidy", columns=["signup"]),
            n.step("numbers", "transform.cast", "dates", columns={"id": "int", "amount": "float"}),
            n.step("shout", "transform.derive", "numbers", name="city_upper", expr="upper(city)"),
            n.step(
                "keep", "transform.select", "shout", columns=["id", "name", "city_upper", "amount", "signup"]
            ),
            n.write("write", "keep", path="messy/"),
        )


@pytest.fixture(autouse=True)
def safetwin_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The folder of the app is a folder of the test, so that no run touches the real one (it is not made)."""
    home = tmp_path / "safetwin-home"
    monkeypatch.setenv("SAFETWIN_HOME", str(home))
    return home


@pytest.fixture
def sockets(tmp_path: Path) -> Sockets:
    inbox, outbox = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outbox.mkdir()
    return Sockets(inbox, outbox)


@pytest.fixture
def nodes() -> type[Nodes]:
    return Nodes


@pytest.fixture
def data() -> type[Data]:
    return Data
