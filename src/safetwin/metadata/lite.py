"""The metadata database without SQLAlchemy: what the engine's control plane needs. Standard library only.

The control plane never imports SQLAlchemy or Alembic (together about 35 MB of memory). It talks to the
database with `sqlite3`, through `connect`, which sets the same pragmas as `db.open_metadata_db` (the two
share `set_pragmas`), and it leaves what needs SQLAlchemy to a short-lived child process,
`python -m safetwin.metadata.maintain` (`run_maintenance`): migrating the schema to the latest version, and
pruning old history (whose audit event is chained by `audit.py`, so the hash chain is built in one place). The
models and the migrations stay the one definition of the schema.

Times are stored as SQLAlchemy's `DateTime` stores them in SQLite (`UTCDateTime` in `models.py`): naive UTC
text such as `2026-10-02 09:30:00.123000`, so that they sort, and compare with what the models write.
"""

import contextlib
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Final

BUSY_TIMEOUT_MS = 5000  # how long a connection waits for a lock that another one holds
HEAD_REVISION: Final = "0001"  # the latest migration in migrations/versions (a test checks that it is)
TIME_FORMAT: Final = "%Y-%m-%d %H:%M:%S.%f"  # SQLAlchemy's DateTime in SQLite
MAINTAIN_TIMEOUT_S: Final = 60.0  # the first start after an install can take seconds while macOS checks files
MAINTAIN_STDERR_BYTES: Final = 64 * 1024  # the last bytes of the child's stderr, kept in memory, never shown
_PRUNED = re.compile(rb"^pruned runs=(\d+) versions=(\d+) pipelines=(\d+)$", re.MULTILINE)


class MaintenanceFailed(Exception):
    """The maintenance child failed or took too long. The message says how it ended (an exit code, a signal or
    the timeout), never what it printed."""


@dataclass(frozen=True)
class Pruned:
    """What a prune deleted: runs, and pipeline versions and pipelines that nothing refers to any more (as
    `db.PruneResult` counts them)."""

    runs: int
    versions: int = 0
    pipelines: int = 0


def create_private_file(path: Path) -> None:
    """Make sure the file exists and only its owner can use it (the folder is made 0700 if it is missing).

    SQLite would create it with the usual umask (0644 or so), and it gives the -wal and -shm files the mode
    of the database, so the mode has to be right before SQLite opens the file.

    An existing file is never opened here: closing any descriptor of a file drops every POSIX lock this
    process holds on it, the shared lock of an open SQLite connection included. Another process (the
    maintenance child) would then take the database for its last user when it closes, and delete the -wal and
    -shm files that this process still writes to.
    """
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(FileExistsError):
        os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600))
    path.chmod(0o600)


def set_pragmas(connection: sqlite3.Connection) -> None:
    """WAL mode, foreign keys on, a busy timeout of `BUSY_TIMEOUT_MS` and `synchronous=NORMAL`."""
    cursor = connection.cursor()
    cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")  # first: the WAL switch below waits on it too
    _switch_to_wal(cursor)
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _switch_to_wal(cursor: sqlite3.Cursor) -> None:
    """`PRAGMA journal_mode=WAL`, waiting for other connections the way the busy timeout does for all else.

    The switch needs a moment in which no other connection has the file open. SQLite does not use the busy
    timeout for that: it fails at once with "database is locked". That happens when two connections meet on a
    file that is not in WAL mode yet. When one has made the switch, the other finds nothing left to do.
    """
    deadline = time.monotonic() + BUSY_TIMEOUT_MS / 1000
    while True:
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError as err:
            busy = getattr(err, "sqlite_errorcode", 0) & 0xFF == sqlite3.SQLITE_BUSY  # 0xFF: any kind of busy
            if not busy or time.monotonic() >= deadline:
                raise
            time.sleep(0.005)


def connect(path: Path) -> sqlite3.Connection:
    """A connection to the database at `path` (the file is made private first), with `set_pragmas`.

    It is in autocommit mode (`isolation_level=None`): a write starts its own transaction, with
    `BEGIN IMMEDIATE`, and commits it. It may be used from any thread, one at a time.
    """
    create_private_file(path)
    connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    try:
        set_pragmas(connection)
    except BaseException:
        connection.close()
        raise
    return connection


def current_revision(connection: sqlite3.Connection) -> str | None:
    """The migration the database is at. None for a database without tables."""
    try:
        row = connection.execute("SELECT version_num FROM alembic_version").fetchone()
    except sqlite3.OperationalError:  # no such table: a new file
        return None
    return None if row is None else str(row[0])


def last_prune(connection: sqlite3.Connection) -> datetime | None:
    """When the history was last pruned (the time of its `retention.prune` audit event), or None."""
    try:
        row = connection.execute(
            "SELECT ts FROM audit_events WHERE action = 'retention.prune' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    return None if row is None else from_db_time(str(row[0]))


def to_db_time(moment: datetime) -> str:
    """An aware datetime as the database stores it (naive UTC text). A naive one is an error."""
    if moment.utcoffset() is None:
        raise ValueError(f"{moment!r} has no timezone: use an aware datetime such as datetime.now(UTC)")
    return moment.astimezone(UTC).strftime(TIME_FORMAT)


def from_db_time(text: str) -> datetime:
    """A time as the database stores it, as an aware UTC datetime."""
    return datetime.fromisoformat(text).replace(tzinfo=UTC)


def maintain_command() -> list[str]:
    """How the maintenance child is started: this Python with the `maintain` module, or, in the frozen engine
    (whose executable is the engine itself), the executable with the `maintain` command."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "maintain"]
    return [sys.executable, "-m", "safetwin.metadata.maintain"]


def run_maintenance(
    path: Path,
    *,
    prune_at: datetime | None = None,
    runs_days: int = 90,
    timeout: float = MAINTAIN_TIMEOUT_S,
    stop: threading.Event | None = None,
    command: Sequence[str] | None = None,
) -> Pruned | None:
    """Run the maintenance child on the database at `path` and wait for it: it migrates the schema to the
    latest version and, with `prune_at`, prunes the history as of that time. What the prune deleted, or None.

    Its stdout gives the counts; its stderr is kept in a bounded buffer that is dropped, never shown. Raises
    `MaintenanceFailed` if it ends with another status, if it takes longer than `timeout` (it is killed), or
    if `stop` is set while it runs (it is killed: the engine is stopping). If anything else ends the wait
    (KeyboardInterrupt, say), the child is killed and reaped before that goes on.
    """
    argv = [*(command or maintain_command()), "--database", str(path)]
    if prune_at is not None:
        argv += [
            "--prune-at",
            prune_at.isoformat(),
            "--runs-days",
            str(runs_days),
        ]
    child = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,  # a Ctrl-C in the engine's terminal reaches the engine only
        close_fds=True,
    )
    out = bytearray()
    drains = [
        threading.Thread(target=_drain, args=(child.stdout, out, 4096), daemon=True),
        threading.Thread(target=_drain, args=(child.stderr, bytearray(), MAINTAIN_STDERR_BYTES), daemon=True),
    ]
    for drain in drains:
        drain.start()
    deadline = time.monotonic() + timeout
    reason = None
    try:
        while child.poll() is None:
            if stop is not None and stop.is_set():
                reason = "the engine is stopping"
            elif time.monotonic() >= deadline:
                reason = f"it took longer than {timeout:g} s"
            if reason is not None:
                break
            time.sleep(0.01)
    finally:
        # However the wait ends (the timeout, a stop, Ctrl-C or SIGTERM in the engine, any error), no child is
        # left running in its own session once the engine and its instance lock are gone.
        if child.poll() is None:
            child.kill()
            child.wait()
        for drain in drains:
            drain.join(5.0)
    if reason is None and child.returncode != 0:
        code = child.returncode
        reason = f"signal {-code}" if code < 0 else f"exit code {code}"
    if reason is not None:
        raise MaintenanceFailed(f"the maintenance of the metadata database failed ({reason})")
    found = _PRUNED.search(bytes(out))
    if found is None:
        return None
    return Pruned(runs=int(found[1]), versions=int(found[2]), pipelines=int(found[3]))


def _drain(pipe: IO[bytes] | None, kept: bytearray, limit: int) -> None:
    """Read a pipe of the child to its end, keeping its last `limit` bytes in `kept`."""
    if pipe is None:
        return
    fd = pipe.fileno()
    try:
        while chunk := os.read(fd, 65536):
            kept += chunk
            if len(kept) > limit:
                del kept[: len(kept) - limit]
    except OSError:
        pass
    finally:
        pipe.close()
