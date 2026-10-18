"""What the history costs a run. Not part of the usual run: `pytest -m perf -s` prints the numbers.

An executor in this process, with real stage workers, runs a pipeline of two stages (1M rows of CSV) five
times with each store: `MemoryRunStore` and `DbRunStore` (the metadata database). It reports the time the
database's transactions took (each, and per run) and the median time of a run with each store. The gates are
loose: the writes of a run take under 100 ms in all, and a run with the database is at most 10% slower.
"""

import os
import statistics
import time
from pathlib import Path

import pytest

from safetwin.executor.executor import Executor
from safetwin.executor.history import DbRunStore, metadata_path
from safetwin.executor.settings import ExecutorSettings
from safetwin.executor.store import MemoryRunStore, RunStore

ROWS = 1_000_000
RUNS = 5
SECONDS = 120
PIPELINE = """\
apiVersion: safetwin/v1
kind: Pipeline
metadata: {name: history-perf}
spec:
  sockets: {inbox: socket://local-inbox, outbox: socket://local-outbox}
  nodes:
    - {id: read, operator: source.csv, socket: inbox, config: {path: "*.csv"}}
    - {id: keep, operator: transform.filter, inputs: [read], config: {expr: "id IS NOT NULL"}}
    - {id: raw, operator: sink.parquet, inputs: [keep], socket: outbox, config: {path: raw/}}
    - {id: tidy, operator: transform.trim, inputs: [raw], config: {columns: [name, city]}}
    - {id: write, operator: sink.parquet, inputs: [tidy], socket: outbox, config: {path: data/}}
"""


def timed_runs(home: Path, store: RunStore, inbox: Path, work: Path) -> list[float]:
    """How long each run took, from submit to its end; a first run, not counted, starts the warm worker."""
    executor = Executor(
        home, ExecutorSettings(memory_limit_bytes=4_000_000_000, warm_worker_s=60), store=store
    )
    executor.start()
    took = []
    try:
        for number in range(RUNS + 1):
            outbox = work / f"out-{number}"
            outbox.mkdir()
            started = time.perf_counter()
            run_id = executor.submit(
                pipeline="history-perf",
                pipeline_yaml=PIPELINE,
                sockets={"inbox": str(inbox), "outbox": str(outbox)},
            ).run_id
            deadline = time.monotonic() + SECONDS
            while not (record := executor.get(run_id)) or not record.ended:
                assert time.monotonic() < deadline
                time.sleep(0.002)
            assert record.state == "succeeded", record.error_class
            if number:
                took.append(time.perf_counter() - started)
    finally:
        executor.shutdown()
    return took


@pytest.mark.perf
def test_the_history_costs_a_run_a_few_milliseconds(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    with (inbox / "people.csv").open("w") as file:
        file.write("id,name,city\n")
        for start in range(0, ROWS, 100_000):
            file.write(
                "".join(
                    f"{'' if n % 10 == 0 else n}, name {n} ,city {n % 7}\n"
                    for n in range(start, min(ROWS, start + 100_000))
                )
            )
    homes = {}
    for kind in ("memory", "db"):
        homes[kind] = tmp_path / f"home-{kind}"
        homes[kind].mkdir(mode=0o700)
        os.chmod(homes[kind], 0o700)
        (tmp_path / kind).mkdir()
    in_memory = timed_runs(homes["memory"], MemoryRunStore(), inbox, tmp_path / "memory")
    store = DbRunStore.open(metadata_path(homes["db"]))
    try:
        in_database = timed_runs(homes["db"], store, inbox, tmp_path / "db")
    finally:
        store.close()
    per_run = store.write_seconds / (RUNS + 1)
    memory_median, database_median = statistics.median(in_memory), statistics.median(in_database)
    print(
        f"\nhistory: {store.writes} transactions for {RUNS + 1} runs of 2 stages "
        f"({store.writes // (RUNS + 1)} per run), {store.write_seconds / store.writes * 1000:.2f} ms each, "
        f"{per_run * 1000:.1f} ms per run; median run ({ROWS:,} rows): memory store {memory_median:.3f} s, "
        f"database {database_median:.3f} s ({(database_median / memory_median - 1) * 100:+.1f}%)"
    )
    assert per_run < 0.1
    assert database_median < memory_median * 1.1
