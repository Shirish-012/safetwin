"""Performance: the fused path against a hand-written Polars script (docs/internals.md: within 2x),
and the memory of the fused path on a big input (Spike B).

Not part of the usual run: `pytest -m perf -s` runs them and prints the numbers. The big input is opt-in as
well: `SAFETWIN_BIG_GB=4 pytest -m perf -s -k big_input` makes a CSV of that many GB under `.scratch/t4b/`
(and deletes it afterwards, whatever happens).
"""

import os
import shutil
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import polars as pl
import psutil
import pytest

from safetwin.dataplane import fused
from safetwin.dataplane.run import run_pipeline_local
from safetwin.dataplane.watchdog import Watchdog

REPO = Path(__file__).resolve().parents[2]
PERF_TEST = "test_the_fused_path_is_within_twice_the_time_of_a_hand_written_polars_script"
ROWS = 3_000_000
RUNS = 3  # the median of this many runs
MAX_RATIO = 2.0
SIGNUP_FORMAT = "%Y-%m-%d %H:%M:%S"

NAMES = ["Alice", "  Bob", "Carol  ", " Dave ", "Eve", "Frank  ", "  Grace", "Heidi"]
CITIES = ["Berlin", " Paris", "Rome ", "  Madrid  ", "Oslo", "Wien"]
DATES = [
    "2026-01-05 10:00:00",
    "2026-02-11 23:59:59",
    "not a date",
    "2026-03-01 00:00:00",
    "",
    "2025-12-31 12:30:45",
]


def generate(path: Path, rows: int) -> None:
    """A messy CSV: no id on every 20th row, whitespace to trim, dates that are not dates."""
    with path.open("w", encoding="utf-8", newline="") as file:
        file.write("id,name,city,amount,signup,note\n")
        for start in range(0, rows, 100_000):
            file.write(
                "".join(
                    f"{'' if i % 20 == 0 else i},{NAMES[i % 8]},{CITIES[i % 6]},{i % 1000}.25,{DATES[i % 6]},"
                    f"note {i % 97}\n"
                    for i in range(start, min(start + 100_000, rows))
                )
            )


def hand_written(source: Path, target: Path) -> None:
    """What a person would write with Polars for the pipeline below."""
    (
        pl.scan_csv(source, infer_schema=False)
        .filter(pl.sql_expr("id IS NOT NULL"))
        .with_columns(pl.col("name", "city").str.strip_chars())
        .with_columns(pl.sql_expr("upper(city)").alias("city_upper"))
        .with_columns(
            pl.col("signup").str.to_datetime(
                format=SIGNUP_FORMAT, time_zone="UTC", time_unit="us", strict=False
            )
        )
        .sink_parquet(target, compression="zstd", compression_level=3)
    )


def seconds(work: Callable[[], object]) -> float:
    started = time.perf_counter()
    work()
    return time.perf_counter() - started


@pytest.mark.perf
def test_the_fused_path_is_within_twice_the_time_of_a_hand_written_polars_script(
    nodes: Any, sockets: Any, tmp_path: Path
) -> None:
    source = sockets.inbox / "big.csv"
    generate(source, ROWS)
    pipeline = nodes.pipeline(
        nodes.read(),
        nodes.step("has_id", "transform.filter", "read", expr="id IS NOT NULL"),
        nodes.step("tidy", "transform.trim", "has_id", columns=["name", "city"]),
        nodes.step("shout", "transform.derive", "tidy", name="city_upper", expr="upper(city)"),
        nodes.step("dates", "transform.parse_dates", "shout", columns=["signup"], format=SIGNUP_FORMAT),
        nodes.write("write", "dates"),
    )
    hand_out = tmp_path / "hand.parquet"

    def engine(path: str) -> Callable[[], object]:
        def run() -> object:
            shutil.rmtree(sockets.outbox / "data", ignore_errors=True)  # a fresh folder for every run
            return run_pipeline_local(pipeline, sockets.folders, force_path=path)  # type: ignore[arg-type]

        return run

    try:
        hand_written(source, hand_out)  # warm up the file cache and the libraries
        engine("fused")()
        hand = statistics.median(seconds(lambda: hand_written(source, hand_out)) for _ in range(RUNS))
        fused = statistics.median(seconds(engine("fused")) for _ in range(RUNS))
        result = engine("fused")()
        written = pl.read_parquet([file.path for file in result.stages[0].files])
        assert written.equals(pl.read_parquet(hand_out)), (
            "the pipeline and the script do not do the same thing"
        )
        batched = statistics.median(seconds(engine("batch")) for _ in range(RUNS))

        megabytes = source.stat().st_size / 1e6
        print(
            f"\n{ROWS:,} rows, {megabytes:.0f} MB of CSV, {written.height:,} rows written, median of {RUNS}:"
            f"\n  hand-written Polars  {hand:.3f} s"
            f"\n  fused path           {fused:.3f} s  ({fused / hand:.2f}x)"
            f"\n  batch-by-batch path  {batched:.3f} s  ({batched / hand:.2f}x)"
        )
        assert fused / hand <= MAX_RATIO, f"the fused path took {fused / hand:.2f}x as long as plain Polars"
    finally:
        source.unlink(missing_ok=True)  # the big files
        shutil.rmtree(sockets.outbox, ignore_errors=True)
        hand_out.unlink(missing_ok=True)


BIG_GB = os.environ.get("SAFETWIN_BIG_GB")
BIG_BLOCK_ROWS = 1_000_000


@pytest.mark.perf
@pytest.mark.skipif(
    not BIG_GB, reason="set SAFETWIN_BIG_GB to the size of the input in GB (it is written to disk)"
)
def test_the_memory_of_the_fused_path_stays_bounded_on_a_big_input(
    nodes: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Spike B (docs/internals.md): the fused benchmark peaked at 1.1-1.3 GB of RSS on a 588 MB CSV, most of it
    # the mapped file. This runs CSV -> filter + trim -> Parquet on a CSV of SAFETWIN_BIG_GB GB with the
    # watchdog sampling, and prints the peak of the stage's memory (what the watchdog measures), the peak RSS,
    # the time and the rows per second.
    target = float(BIG_GB or 0) * 1e9
    folder = REPO / ".scratch" / "t4b" / f"big-{os.getpid()}"
    inbox, outbox = folder / "in", folder / "out"
    made: list[Watchdog] = []
    real = fused.stage_watchdog

    def spy(stage: Any, ctx: Any) -> Watchdog:
        made.append(real(stage, ctx))
        return made[-1]

    monkeypatch.setattr(fused, "stage_watchdog", spy)
    try:
        inbox.mkdir(parents=True)
        outbox.mkdir()
        source = inbox / "big.csv"
        generate(source, BIG_BLOCK_ROWS)  # one block of rows, written again and again: the values repeat
        block = source.read_bytes().split(b"\n", 1)[1]
        rows = BIG_BLOCK_ROWS
        with source.open("ab") as file:
            while file.tell() + len(block) <= target:
                file.write(block)
                rows += BIG_BLOCK_ROWS
        size = source.stat().st_size
        pipeline = nodes.pipeline(
            nodes.read(),
            nodes.step("has_id", "transform.filter", "read", expr="id IS NOT NULL"),
            nodes.step("tidy", "transform.trim", "has_id", columns=["name", "city"]),
            nodes.write("write", "tidy"),
        )
        process = psutil.Process()
        rss_peak = [process.memory_info().rss]
        done = threading.Event()

        def sample_rss() -> None:
            while not done.wait(0.05):
                rss_peak[0] = max(rss_peak[0], process.memory_info().rss)

        sampler = threading.Thread(target=sample_rss, daemon=True)
        rss_before = rss_peak[0]
        sampler.start()
        started = time.perf_counter()
        try:
            result = run_pipeline_local(
                pipeline, {"inbox": inbox, "outbox": outbox}, memory_limit_bytes=64 * 1000**3
            )
        finally:
            done.set()
            sampler.join()
        took = time.perf_counter() - started
        (stage,) = result.stages
        assert stage.path == "fused"
        assert stage.rows_per_node["read"] == rows
        assert stage.rows_per_node["write"] == rows - rows // 20  # every 20th row has no id
        (dog,) = made
        speed = f"{rows / took / 1e6:.1f} M rows/s, {size / took / 1e6:.0f} MB/s"
        rss_growth = (rss_peak[0] - rss_before) / 1e6
        print(
            f"\n{size / 1e9:.2f} GB of CSV, {rows:,} rows, fused CSV -> filter + trim -> Parquet:"
            f"\n  time                 {took:.1f} s ({speed})"
            f"\n  peak stage memory    {dog.peak_bytes / 1e6:,.0f} MB (phys_footprint growth)"
            f"\n  peak RSS             {rss_peak[0] / 1e6:,.0f} MB ({rss_growth:,.0f} MB growth)"
            f"\n  output               {stage.files[0].bytes / 1e6:,.0f} MB of Parquet"
        )
    finally:
        shutil.rmtree(folder, ignore_errors=True)  # the big files, even when the test failed


def collected(*options: str) -> str:
    """What pytest collects from this file, in the repository's own configuration plus `options`."""
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            __file__,
            *options,
        ],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_a_default_run_leaves_the_perf_tests_out_and_m_perf_brings_them_back() -> None:
    # scripts/check.sh and CI rely on this: `pytest` alone must not run the slow performance tests.
    default = collected()
    assert PERF_TEST not in default
    assert "deselected" in default
    only_perf = collected("-m", "perf")
    assert PERF_TEST in only_perf
    assert "test_a_default_run_leaves_the_perf_tests_out" not in only_perf  # this one is not marked perf
