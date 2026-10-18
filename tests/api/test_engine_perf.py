"""Performance of the idle engine (docs/internals.md: the control plane stays under 100 MB when idle).

Not part of the usual run: `pytest -m perf -s` runs it and prints the numbers. It starts the engine as the app
would, with `safetwin engine start` in a process of its own, and measures:

- the cold start: from the launch until `GET /v1/status` answers;
- after 3 s idle, its memory: phys_footprint (macOS, `proc_pid_rusage`) and rss. rss must be under 80 MB:
  the budget is 100 MB, and the margin is kept for what later work adds to this process (it measured about
  58 MB on an Apple M4, with the metadata database open: the control plane uses sqlite3 only);
- its CPU time over the next 5 s idle: under 2% of one core.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest

from safetwin.api.client import EngineError, get_status, request_shutdown
from safetwin.api.connection import ConnectionFileError, connection_path, read_connection_file
from safetwin.memory import footprint_sampler

SAFETWIN = Path(sys.executable).parent / "safetwin"
MAX_RSS = 80_000_000
MAX_CPU_SHARE = 0.02
IDLE_BEFORE_MEMORY_S = 3.0
CPU_WINDOW_S = 5.0


@pytest.mark.perf
def test_the_idle_engine_stays_under_100_mb_and_2_percent_of_a_core(tmp_path: Path) -> None:
    home = tmp_path / "safetwin-home"
    launched = time.perf_counter()
    engine = subprocess.Popen(
        [str(SAFETWIN), "engine", "start"],
        env={**os.environ, "SAFETWIN_HOME": str(home)},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        info = None
        while info is None:
            assert engine.poll() is None, "the engine ended"
            assert time.perf_counter() - launched < 60, "the engine did not answer within 60 s"
            try:
                found = read_connection_file(connection_path(home))
                if found is not None and found.pid == engine.pid:
                    get_status(found, timeout=1.0)
                    info = found
            except (ConnectionFileError, EngineError):
                pass
            if info is None:
                time.sleep(0.005)
        cold_start = time.perf_counter() - launched

        time.sleep(IDLE_BEFORE_MEMORY_S)
        process = psutil.Process(engine.pid)
        rss = process.memory_info().rss
        footprint_of = footprint_sampler(engine.pid)
        footprint = footprint_of() if footprint_of is not None else None

        before, started = process.cpu_times(), time.monotonic()
        time.sleep(CPU_WINDOW_S)
        after, window = process.cpu_times(), time.monotonic() - started
        cpu_share = (after.user + after.system - before.user - before.system) / window

        shown = f"{footprint / 1e6:.1f} MB" if footprint is not None else "n/a (not macOS)"
        print(
            f"\nidle engine (safetwin engine start): cold start {cold_start:.2f} s, rss {rss / 1e6:.1f} MB, "
            f"phys_footprint {shown}, CPU {cpu_share * 100:.3f}% of a core over {window:.1f} s idle"
        )
        assert rss < MAX_RSS
        assert cpu_share < MAX_CPU_SHARE
        request_shutdown(info)
        assert engine.wait(timeout=30) == 0
    finally:
        if engine.poll() is None:
            engine.kill()
            engine.wait()
