"""The DuckDB connection of a stage: how much memory it gets, that it never spills, and what SQL may do.

DuckDB is the only part of the engine that could write temporary data: a sort or an aggregate that is bigger
than memory goes through it, and DuckDB would put what does not fit in a folder. DuckDB **never spills**
(decided on 2026-10-01: docs/internals.md, decision 3 in docs/internals.md): the connection that
`open_duckdb` makes writes no temporary file anywhere, and a step that needs more than its memory limit fails
with `OutOfMemory`, whose message says what to do. Its memory limit is 80% of the stage's share of memory
(`DUCKDB_SHARE`): the rest is for the Polars and Arrow parts of the stage, and the memory watchdog
(`watchdog.py`) stops a stage that grows past the whole share. So DuckDB's own clear error normally comes
first.

Encrypted spill is not offered either. DuckDB's secure crypto (OpenSSL) is in its `httpfs` extension, which
DuckDB downloads from the internet the first time it needs it, and the app does not fetch native code at run
time. Its built-in fallback, mbedtls (`SET force_mbedtls_unsafe = true`), draws its IVs from a random number
generator that is not a secure one, and the IVs that are stored in the spill files are enough to recover the
key (advisory GHSA-vmp8-hg63-v2hp, fixed in DuckDB 1.4.2 by refusing to write with it unless told to).

What turns spilling off, measured with DuckDB 1.5.6 on an in-memory connection (`test_spill_none.py`): by
default DuckDB spills to `.tmp` in the current folder. `temp_directory = ''` takes that folder away, and
`max_temp_directory_size = '0KB'` leaves no room in any folder. Each alone makes a sort that does not fit
fail with an out-of-memory error, but with only the second DuckDB still makes `.tmp` and an empty file in
it. With the first, or both (as here), it writes nothing at all.

Nothing is installed or loaded, ever. The first things a connection is told are where its extensions are
(`extension_directory`, a folder of the app that stays empty: `default_extension_dir`) and that it may not
install or load any by itself (`autoinstall_known_extensions`, `autoload_known_extensions` and
`allow_community_extensions` are off, and `allow_unsigned_extensions` stays off). What the SQL of a stage
may use is what is built into DuckDB (JSON, Parquet, ICU for time zones and collations).

Then the connection is locked, in this order: `enable_external_access = false` (no file, no URL, no `COPY`,
no `ATTACH` of a file, no `INSTALL`, no `LOAD` of an extension that is not built in), then
`lock_configuration = true` (no `SET` of any setting, so none of this can be undone). A stage only runs a
single `SELECT` (`operators.py`) as well. SQL can still call table functions that have effects of their own
(`enable_logging()` is one, and DuckDB 1.5.6 aborts the process if it is asked to log to a file it may not
write): none of that reads or writes the data of a pipeline.
"""

import os
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import duckdb
import psutil as psutil  # tests patch the physical memory through it

# These three moved to safetwin.memory, so that the control plane can use them; still importable from here.
from safetwin.memory import default_memory_limit as default_memory_limit
from safetwin.memory import format_size as format_size
from safetwin.memory import parse_size as parse_size
from safetwin.paths import safetwin_home as safetwin_home  # moved there; still importable from here

# DuckDB's memory limit is this much of the stage's share of memory.
DUCKDB_SHARE: Final = 0.8

# DuckDB works with about this much memory for each of its threads: a limit of 150 MB with 4 threads failed
# with out-of-memory where 400 MB with 2 threads did not (measured with DuckDB 1.5).
MIN_BYTES_PER_THREAD: Final = 200_000_000


class SpillError(RuntimeError):
    """DuckDB can't be set up, or it ran out of memory. The message is safe to show.

    It names limits and settings, never data, and never what DuckDB said (which can quote data).
    """


class OutOfMemory(SpillError):
    """DuckDB used up the memory it was given, and it does not spill."""


@dataclass(frozen=True)
class SpillSettings:
    """What DuckDB may use in a run: some of the stage's share of memory, `memory_limit_bytes`, and no disk.

    DuckDB's own limit is `duckdb_memory_bytes`, 80% of the share. Messages name the share, which is what
    `--memory-limit` sets.
    """

    memory_limit_bytes: int

    def __post_init__(self) -> None:
        if self.memory_limit_bytes < 1:
            raise ValueError("the memory limit must be at least one byte")

    @property
    def duckdb_memory_bytes(self) -> int:
        """DuckDB's `memory_limit`: 80% of the share, at least one byte."""
        return max(1, int(self.memory_limit_bytes * DUCKDB_SHARE))


def duckdb_threads(memory_limit_bytes: int, cpus: int | None = None) -> int:
    """The threads DuckDB gets: one for each 200 MB of its memory (its own limit, not the stage's share), at
    least one, at most `cpus`."""
    return max(1, min(cpus or os.cpu_count() or 1, memory_limit_bytes // MIN_BYTES_PER_THREAD))


def default_extension_dir() -> Path:
    """The folder that DuckDB is told its extensions are in: `$SAFETWIN_DUCKDB_EXTENSIONS`, else
    `duckdb_extensions/` in the folder of the app.

    The app needs no extension, and none is ever installed or loaded: the folder is there so that, whatever
    happens, DuckDB has no place to put one but one of ours (and not `~/.duckdb`). It stays empty, and is not
    made.
    """
    configured = os.environ.get("SAFETWIN_DUCKDB_EXTENSIONS")
    return Path(configured).expanduser() if configured else safetwin_home() / "duckdb_extensions"


def open_duckdb(settings: SpillSettings, extension_dir: Path | None = None) -> duckdb.DuckDBPyConnection:
    """A DuckDB connection for one stage, set up as the module docs say and then locked.

    `extension_dir` is where DuckDB looks for extensions (`default_extension_dir()` if that is None). Whatever
    goes wrong is a `SpillError` that does not repeat what DuckDB said, and nothing is left open.

    Other connections for the same stage are made with `.cursor()`: they share the settings and the memory.
    """
    connection = duckdb.connect(":memory:")
    try:
        _configure(connection, settings, default_extension_dir() if extension_dir is None else extension_dir)
    except BaseException:
        close_duckdb(connection)
        raise
    return connection


def close_duckdb(connection: duckdb.DuckDBPyConnection) -> None:
    """Close the connection. Never raises."""
    with suppress(duckdb.Error):
        connection.close()


@contextmanager
def duckdb_session(
    settings: SpillSettings, extension_dir: Path | None = None
) -> Iterator[duckdb.DuckDBPyConnection]:
    """`open_duckdb`, and `close_duckdb` when the `with` block ends, however it ends."""
    connection = open_duckdb(settings, extension_dir)
    try:
        yield connection
    finally:
        close_duckdb(connection)


def out_of_memory(settings: SpillSettings, what: str) -> OutOfMemory:
    """The error for a DuckDB that ran out of memory in `what` (such as "the DuckDB steps of this stage")."""
    return OutOfMemory(
        f"{what} ran out of memory (the limit is {format_size(settings.memory_limit_bytes)}), and DuckDB "
        "does not spill to disk. Raise the memory limit (--memory-limit), or add a filter before it or "
        "select fewer columns so that less data reaches it."
    )


def _configure(connection: duckdb.DuckDBPyConnection, settings: SpillSettings, extension_dir: Path) -> None:
    try:
        run = connection.execute
        # First of all, before anything that could make DuckDB look for an extension: where they are, and
        # that it may not fetch or load one by itself.
        run("SET autoinstall_known_extensions = false")
        run("SET autoload_known_extensions = false")
        run("SET allow_community_extensions = false")
        run(f"SET extension_directory = {_literal(str(extension_dir))}")
        # So that the type of a timestamp column does not depend on the machine. GLOBAL, so that the cursors
        # of the connection get it too: the zone is a setting of each session, and then the lock comes.
        run("SET GLOBAL TimeZone = 'UTC'")
        run(f"SET memory_limit = '{settings.duckdb_memory_bytes}B'")
        run(f"SET threads = {duckdb_threads(settings.duckdb_memory_bytes)}")
        # No spill: no folder to spill to (else DuckDB would use ./.tmp), and no room in one either.
        run("SET temp_directory = ''")
        run("SET max_temp_directory_size = '0KB'")
        run("SET enable_external_access = false")
        run("SET lock_configuration = true")
    except duckdb.Error as err:  # what DuckDB says could quote the statement
        raise SpillError(f"DuckDB could not be set up for this stage ({type(err).__name__})") from None


def _literal(text: str) -> str:
    """`text` as an SQL string literal."""
    return "'" + text.replace("'", "''") + "'"
