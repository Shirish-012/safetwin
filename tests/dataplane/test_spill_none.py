"""No spill: DuckDB writes no temporary file anywhere, and a step that needs more memory fails cleanly.

Decided on 2026-10-01 (docs/internals.md, `spill.py`). A thread looks at every place a temporary file
could go while a sort or a self-join that does not fit in memory runs: the current folder (where DuckDB spills
by default, to `.tmp`), `$TMPDIR`, the home folder and the folder of the app, all of them folders of the test.
It must find nothing, during the run or after it. A control run with DuckDB's own defaults spills, and the
thread sees it: that is how we know that it can see.
"""

import os
import tempfile
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
import pytest

from safetwin.dataplane import hybrid
from safetwin.dataplane.run import run_pipeline_local
from safetwin.dataplane.spill import (
    OutOfMemory,
    SpillSettings,
    duckdb_session,
)

SORT = (
    "SELECT v FROM (SELECT md5(i::varchar) || md5((i * 7)::varchar) AS v FROM range(4000000) t(i)) ORDER BY v"
)
LIMIT = 60_000_000  # much less than the 4 million rows (about 260 MB) of SORT, or the 120 MB of `wide` below
WIDE_ROWS = 400_000


class Watcher(threading.Thread):
    """Notes every file and folder that is ever below `roots`, from the start to `finish()`."""

    def __init__(self, roots: list[Path]) -> None:
        super().__init__(daemon=True)
        self._roots = roots
        self._done = threading.Event()
        self.seen: set[str] = set()

    def run(self) -> None:
        while True:
            last = self._done.is_set()  # one more look after the end
            for root in self._roots:
                for dirpath, dirnames, filenames in os.walk(root):
                    self.seen.update(os.path.join(dirpath, name) for name in (*dirnames, *filenames))
            if last:
                return
            time.sleep(0.005)

    def finish(self) -> None:
        self._done.set()
        self.join(timeout=60)
        assert not self.is_alive()


@dataclass
class Places:
    """The folders where a temporary file could go. They are empty when the test starts."""

    cwd: Path
    tmpdir: Path
    home: Path
    app: Path

    @property
    def all(self) -> list[Path]:
        return [self.cwd, self.tmpdir, self.home, self.app]

    def files(self) -> list[str]:
        return sorted(str(path) for root in self.all for path in root.rglob("*"))


@pytest.fixture
def places(tmp_path: Path, safetwin_home: Path, monkeypatch: pytest.MonkeyPatch) -> Places:
    found = Places(tmp_path / "cwd", tmp_path / "tmpdir", tmp_path / "home", safetwin_home)
    for folder in found.all:
        folder.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(found.cwd)
    monkeypatch.setenv("TMPDIR", str(found.tmpdir))
    monkeypatch.setattr(tempfile, "tempdir", str(found.tmpdir))
    monkeypatch.setenv("HOME", str(found.home))
    return found


@contextmanager
def watching(places: Places) -> Iterator[Watcher]:
    watcher = Watcher(places.all)
    watcher.start()
    try:
        yield watcher
    finally:
        watcher.finish()


def sort_all(connection: Any) -> int:
    return sum(batch.num_rows for batch in connection.execute(SORT).to_arrow_reader(100_000))


# --- the connection -----------------------------------------------------------------------------------------


def test_control_with_duckdbs_defaults_the_same_sort_spills_into_the_current_folder(
    places: Places, tmp_path: Path
) -> None:
    # DuckDB's defaults for spilling, but not for extensions: even the control looks nowhere near ~/.duckdb.
    extensions = tmp_path / "control-extensions"
    connection = duckdb.connect(
        config={
            "extension_directory": str(extensions),
            "autoinstall_known_extensions": False,
            "autoload_known_extensions": False,
        }
    )
    assert connection.execute("SELECT current_setting('extension_directory')").fetchone() == (
        str(extensions),
    )
    connection.execute(f"SET memory_limit = '{LIMIT}B'")
    connection.execute("SET threads = 1")
    with watching(places) as watcher:
        assert sort_all(connection) == 4_000_000  # it fitted, because it spilled
        connection.close()
    spilled = [path for path in watcher.seen if path.startswith(str(places.cwd / ".tmp"))]
    assert spilled, "DuckDB spilled nowhere that the watcher looked: it can't be trusted"
    assert not extensions.exists()


def test_a_sort_that_does_not_fit_fails_and_no_file_appears_anywhere(places: Places) -> None:
    session = duckdb_session(SpillSettings(LIMIT))
    with watching(places) as watcher, session as connection, pytest.raises(duckdb.OutOfMemoryException):
        sort_all(connection)
    assert watcher.seen == set()
    assert places.files() == []


# --- a stage ------------------------------------------------------------------------------------------------


def write_wide(folder: Path) -> None:
    """About 120 MB of text in rows that are all different: much more than LIMIT."""
    with (folder / "wide.csv").open("w", encoding="utf-8") as file:
        file.write("id,name,city,amount\n")
        file.write("".join(f"{n},{n:07d}-{'x' * 270},city,1\n" for n in range(WIDE_ROWS)))


STAGES = {
    "a sort": {
        "id": "big",
        "operator": "transform.sort",
        "config": {"by": [{"column": "name", "descending": True}]},
    },
    "a self-join (input becomes a table)": {
        "id": "big",
        "operator": "transform.sql",
        "config": {"sql": "SELECT count(*) AS n FROM input a JOIN input b ON a.name = b.name"},
    },
}


@pytest.mark.parametrize("kind", STAGES)
def test_a_stage_that_needs_more_memory_fails_cleanly_and_writes_no_file_anywhere(
    nodes: Any, sockets: Any, places: Places, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # DuckDB's own limit is what this checks: the watchdog samples once a second, so on a system that counts
    # memory otherwise (Linux: rss less shared pages) it can't stop the stage first. Both stops are safe.
    monkeypatch.setenv("SAFETWIN_TEST_WATCHDOG_INTERVAL_S", "1")
    write_wide(sockets.inbox)
    pipeline = nodes.pipeline(nodes.read(), {**STAGES[kind], "inputs": ["read"]}, nodes.write("write", "big"))
    with watching(places) as watcher, pytest.raises(OutOfMemory) as failed:
        run_pipeline_local(pipeline, sockets.folders, memory_limit_bytes=LIMIT)
    message = str(failed.value)
    assert message.startswith("the DuckDB steps of this stage (big (")
    assert "ran out of memory (the limit is 60 MB), and DuckDB does not spill to disk" in message
    for advice in ("--memory-limit", "add a filter", "select fewer columns"):
        assert advice in message
    assert "x" * 20 not in message  # what DuckDB said is not repeated, nor any data
    assert watcher.seen == set()
    assert places.files() == []
    assert sockets.written() == []  # nothing half-written: no file, no temporary file, no manifest


def test_the_same_stage_with_enough_memory_runs_and_still_writes_nothing_but_its_output(
    nodes: Any, sockets: Any, places: Places
) -> None:
    write_wide(sockets.inbox)
    pipeline = nodes.pipeline(
        nodes.read(), {**STAGES["a sort"], "inputs": ["read"]}, nodes.write("write", "big")
    )
    with watching(places) as watcher:
        result = run_pipeline_local(pipeline, sockets.folders, memory_limit_bytes=2_000_000_000)
    assert result.stages[0].rows_per_node["write"] == WIDE_ROWS
    assert watcher.seen == set()
    assert [name for name in sockets.written() if name.endswith(".parquet")] == [
        f"data/part-00000-{result.run_id}.parquet"
    ]


def test_the_connection_of_a_running_stage_spills_nowhere_and_never_uses_the_unsafe_crypto(
    nodes: Any, data: Any, sockets: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[Any, ...]] = []
    real = hybrid.duckdb_session

    @contextmanager
    def spy(settings: SpillSettings) -> Iterator[duckdb.DuckDBPyConnection]:
        with real(settings) as connection:
            names = (
                "temp_directory",
                "max_temp_directory_size",
                "force_mbedtls_unsafe",
                "temp_file_encryption",
            )
            seen.append(
                tuple(connection.execute(f"SELECT current_setting('{n}')").fetchone()[0] for n in names)
            )  # type: ignore[index]
            yield connection

    monkeypatch.setattr(hybrid, "duckdb_session", spy)
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(100))
    pipeline = nodes.pipeline(
        nodes.read(),
        nodes.step("q", "transform.sql", "read", sql="SELECT * FROM input"),
        nodes.write("write", "q"),
    )
    run_pipeline_local(pipeline, sockets.folders)
    assert seen == [("", "0 bytes", False, False)]
