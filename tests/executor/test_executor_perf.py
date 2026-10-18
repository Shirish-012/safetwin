"""Performance of runs through the engine. Not part of the usual run: `pytest -m perf -s` prints the numbers.

It starts the engine in a process of its own (the warm worker kept for 3 s instead of 60) and measures:

- how long a stage waits for a cold worker (none started: it imports the data libraries) and for a warm one
  that has finished its imports;
- the memory of a warm worker that waits idle;
- the fused path through the engine against `run_pipeline_local` in this process, on the input of
  `dataplane/test_perf.py` (3M rows, 153 MB of CSV): the median of 3 runs each, reported, not a gate;
- the engine's own memory after the runs, once the warm worker has ended: rss must stay under 80 MB (the
  budget is 100 MB; the margin is kept for what later work adds to the control plane).
"""

import http.client
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import pytest

from safetwin.api.connection import ConnectionInfo, connection_path, read_connection_file
from safetwin.memory import footprint_sampler

ROWS = 3_000_000
RUNS = 3
MAX_RSS = 80_000_000
SECONDS = 120
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
PIPELINE = f"""\
apiVersion: safetwin/v1
kind: Pipeline
metadata: {{name: perf}}
spec:
  sockets: {{inbox: socket://local-inbox, outbox: socket://local-outbox}}
  nodes:
    - {{id: read, operator: source.csv, socket: inbox, config: {{path: "*.csv"}}}}
    - {{id: has_id, operator: transform.filter, inputs: [read], config: {{expr: "id IS NOT NULL"}}}}
    - {{id: tidy, operator: transform.trim, inputs: [has_id], config: {{columns: [name, city]}}}}
    - id: shout
      operator: transform.derive
      inputs: [tidy]
      config: {{name: city_upper, expr: "upper(city)"}}
    - id: dates
      operator: transform.parse_dates
      inputs: [shout]
      config: {{columns: [signup], format: "{SIGNUP_FORMAT}"}}
    - {{id: write, operator: sink.parquet, inputs: [dates], socket: outbox, config: {{path: data/}}}}
"""
DRIVER = """
import sys
from safetwin.executor import settings
settings.WARM_WORKER_S = 3.0
from safetwin.api import server
sys.exit(server.main([]))
"""


def generate(path: Path, rows: int) -> None:
    """The messy CSV of `dataplane/test_perf.py`."""
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


def request(info: ConnectionInfo, method: str, path: str, body: Any = None) -> Any:
    connection = http.client.HTTPConnection("127.0.0.1", info.port, timeout=SECONDS)
    headers = {"Authorization": f"Bearer {info.token}", "Content-Type": "application/json"}
    try:
        connection.request(method, path, body=None if body is None else json.dumps(body), headers=headers)
        return json.loads(connection.getresponse().read())
    finally:
        connection.close()


def run_in_engine(info: ConnectionInfo, sockets: dict[str, str]) -> tuple[float, dict[str, Any]]:
    """Submit a run and wait for it: the wall time from the request to its end, and its record."""
    started = time.perf_counter()
    run_id = request(info, "POST", "/v1/runs", {"pipeline_yaml": PIPELINE, "sockets": sockets})["run_id"]
    while (record := request(info, "GET", f"/v1/runs/{run_id}"))["state"] not in ("succeeded", "failed"):
        time.sleep(0.005)
    took = time.perf_counter() - started
    assert record["state"] == "succeeded", record
    return took, record


def memory_of(pid: int) -> str:
    rss = psutil.Process(pid).memory_info().rss
    footprint = footprint_sampler(pid)
    shown = f", phys_footprint {footprint() / 1e6:.1f} MB" if footprint is not None else ""
    return f"rss {rss / 1e6:.1f} MB{shown}"


@pytest.mark.perf
def test_runs_through_the_engine(tmp_path: Path) -> None:
    from safetwin.dataplane.run import run_pipeline_local
    from safetwin.spec import load_pipeline_text

    home, inbox, outbox = tmp_path / "home", tmp_path / "in", tmp_path / "out"
    home.mkdir(mode=0o700)
    os.chmod(home, 0o700)
    inbox.mkdir()
    outbox.mkdir()
    generate(inbox / "big.csv", ROWS)
    sockets = {"inbox": str(inbox), "outbox": str(outbox)}
    script = tmp_path / "driver.py"
    script.write_text(DRIVER)
    engine = subprocess.Popen(
        [sys.executable, str(script)],
        env={**os.environ, "SAFETWIN_HOME": str(home)},
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    try:
        assert engine.stdout is not None
        assert engine.stdout.readline().startswith("engine running")
        info = read_connection_file(connection_path(home))
        assert info is not None

        # Cold, then warm (the run before left a warm worker).
        _, cold = run_in_engine(info, sockets)
        engine_times = []
        warm_waits = []
        stage_times = []
        for _ in range(RUNS):
            shutil.rmtree(outbox / "data", ignore_errors=True)
            time.sleep(1.0)  # the warm worker started when the last stage ended: let it finish its imports
            took, record = run_in_engine(info, sockets)
            engine_times.append(took)
            warm_waits.append(record["stages"][0]["worker_wait_s"])
            stage_times.append(record["stages"][0]["duration_s"])
            assert record["stages"][0]["worker_start"] == "warm"
        time.sleep(1.0)
        idle = [child for child in psutil.Process(engine.pid).children() if child.is_running()]
        assert len(idle) == 1, idle
        idle_worker = memory_of(idle[0].pid)

        pipeline = load_pipeline_text(PIPELINE)
        local_times = []
        for _ in range(RUNS):
            shutil.rmtree(outbox / "data", ignore_errors=True)
            started = time.perf_counter()
            run_pipeline_local(pipeline, {"inbox": inbox, "outbox": outbox})
            local_times.append(time.perf_counter() - started)

        deadline = time.monotonic() + 30
        while request(info, "GET", "/v1/status")["runs"]["workers_idle"]:
            assert time.monotonic() < deadline, "the warm worker never ended"
            time.sleep(0.1)
        time.sleep(1.0)
        assert psutil.Process(engine.pid).children() == []
        engine_rss = psutil.Process(engine.pid).memory_info().rss
        engine_memory = memory_of(engine.pid)

        local, through = statistics.median(local_times), statistics.median(engine_times)
        megabytes = (inbox / "big.csv").stat().st_size / 1e6
        print(
            f"\nstage worker start: cold {cold['stages'][0]['worker_wait_s']:.3f} s, "
            f"warm {statistics.median(warm_waits):.3f} s (median of {RUNS})"
            f"\nwarm idle worker: {idle_worker}"
            f"\nfused, {ROWS:,} rows, {megabytes:.0f} MB of CSV, median of {RUNS}: "
            f"run_pipeline_local {local:.2f} s, through the engine {through:.2f} s "
            f"({through / local:.2f}x, request to end, warm worker; the stage itself took "
            f"{statistics.median(stage_times):.2f} s in its worker)"
            f"\nidle engine after the runs, warm worker gone: {engine_memory}"
        )
        assert engine_rss < MAX_RSS
        request(info, "POST", "/v1/shutdown")
        assert engine.wait(timeout=30) == 0
    finally:
        if engine.poll() is None:
            engine.kill()
            engine.wait()
