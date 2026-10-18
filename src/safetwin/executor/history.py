"""The history of the runs in the metadata database: `DbRunStore`, the `RunStore` of the engine
(docs/internals.md).

The control plane talks to the database with `sqlite3` only, never with SQLAlchemy or Alembic (they would
cost it about 35 MB of memory: `metadata.lite`). The SQL here is written against the schema that the models
and the Alembic migrations define; the tests run it against a database that the real migrations made, and
check that every column it writes is there (`WRITES`).

**Opening and maintenance.** The engine opens `$SAFETWIN_HOME/metadata.db` when it starts (`DbRunStore.open`:
the file is made 0600, WAL mode, the pragmas of `open_metadata_db`). If the schema is not at the latest
migration (read with a plain query), it runs the maintenance child (`python -m safetwin.metadata.maintain`),
which migrates it and prunes, and waits for it. Then `start` marks the runs that an engine which crashed left
unfinished as `interrupted`, runs the child again to prune if the last prune is a day old or more, and from
then on prunes once a day, from a thread of its own (90 days of runs). The child's output is
never shown: a failure is reported by its exit status.

**What is written.** Facts about runs, never data: ids, names, states, times, counts, sizes, SHA-256, paths,
and error codes (`error_class`, `exit_reason`), never an exception message and never a token. Table by table:

- `pipelines`: one row per pipeline, its id is `metadata.name`.
- `pipeline_versions`: the text of the pipeline and its SHA-256. A run of the same text as the pipeline's
  latest version uses that version; other text is a new version. The text was validated before it gets
  here, and validation refuses a value that looks like a secret; the whole text is scanned once more
  (comments and keys, which validation does not read, too), and if anything in it looks like a secret, a
  line that says so is kept instead of the text.
- `runs`: id, pipeline, version, state, start, end and `error_class`.
- `task_instances`: one per node of each stage, with the stage's index, state and times. The nodes of a
  stage are inserted in the order of the stage, so the last one (the highest id) is its sink.
- `task_attempts`: attempt 1 of each task instance, with the stage's state, times, `exit_reason` (how its
  worker ended: `exit_0`, `exit_1`, `signal_9`, `cancelled`) and `error_class`.
- `metrics` (raw): `rows_out` (rows) of every node, `bytes_written` (bytes) and `duration_s` (seconds) of each
  stage on the task instance of its sink, and `memory_peak_bytes` (bytes) of the run when its stages
  reported their memory.
- `run_files`: each file a stage committed, data files and the manifest, with path, size and SHA-256.
- `datasets` and `lineage`: the folder of each sink's dataset as a `file://` URI, with the run that last
  wrote it, and an `output` edge from the run.

**When.** On the transitions of a run, never for progress: when it is queued (`add`), when it starts, when
its stages are planned, when a stage starts, when a stage ends (with its final counts, files and metrics) and
when the run ends. Each is one short transaction (`BEGIN IMMEDIATE`, so two writers never interleave a read
and a write, with the database's 5 s busy timeout), one at a time in this process, on one connection. The
executor saves from the threads of the runs and the API reads through its thread pool (each read on a
connection of its own, in one read transaction), so the event loop never waits on the database. A write that
fails (the prune child holds the write lock past the busy timeout, a full disk) is logged by the type of its
error and the run goes on. What was missed is written by the next transition, or, when there is none (the
run ended), by a thread of the store that tries again a few times (`RETRY_DELAYS_S`), and once more when the
store closes. A run whose `add` failed is inserted, with everything since, by the first write that works. So a
run that ended is not left `running` in the database, to be marked `interrupted` by the next engine. The
latest progress of a run that is going is kept in memory only.

**What stays in memory.** The records of this engine's runs (the newest `max_runs`; one that has not ended is
never dropped): their progress while they go, and what the database has no place for: the engine's safe
messages (`error`, such as the advice of `OutOfMemory`), when the run was queued, its memory share, the way
each stage ran and its workers. `get` and `recent` read the database and add these while the run is in
memory. After a restart, the history shows the `error_class` of a failed run, never a message.

**Recovery.** When the engine starts (it holds the instance lock, so no other engine runs), every run that is
still `queued` or `running` was left by an engine that stopped without ending it: it is marked `interrupted`
with `error_class` `EngineStopped`, and so are its task instances and attempts that had not ended
(`exit_reason` `engine_stopped`).

Nothing here imports Polars, PyArrow, DuckDB, SQLAlchemy or Alembic.
"""

import hashlib
import logging
import re
import sqlite3
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from safetwin.metadata import lite
from safetwin.metadata.lite import HEAD_REVISION, Pruned, from_db_time, to_db_time
from safetwin.spec import SpecError, load_pipeline_text
from safetwin.spec.validate import text_secrets

from .protocol import utc_iso
from .settings import MAX_RUNS_KEPT, HistorySettings
from .store import (
    ENDED,
    RUN_ID_PATTERN,
    FileRecord,
    RunRecord,
    RunSummary,
    StageRecord,
    Totals,
    UnknownCursor,
)

_log = logging.getLogger(__name__)

METADATA_DB: Final = "metadata.db"
INTERRUPTED_ERROR: Final = "EngineStopped"
INTERRUPTED_EXIT: Final = "engine_stopped"
NOT_KEPT: Final = (
    "# The text of this pipeline is not kept: something in it looks like a secret (in a comment or a\n"
    "# key, which validation does not read). Keep secrets in the keychain: secret://<name>.\n"
)
MAX_CACHED_VERSIONS: Final = 256
RETRY_DELAYS_S: Final = (0.2, 1.0, 3.0)  # a write that failed is tried again after these, then at close

# Every column this module writes, by table, with the Python type of its values: inserts give all of them,
# updates some. A test checks them against the database that the migrations make.
WRITES: Final[dict[str, dict[str, type]]] = {
    "pipelines": {"id": str, "name": str, "description": str, "created_at": datetime, "updated_at": datetime},
    "pipeline_versions": {
        "pipeline_id": str,
        "version": int,
        "yaml_text": str,
        "spec_sha256": str,
        "created_at": datetime,
    },
    "runs": {
        "id": str,
        "pipeline_id": str,
        "pipeline_version_id": int,
        "state": str,
        "started_at": datetime,
        "ended_at": datetime,
        "error_class": str,
    },
    "task_instances": {
        "run_id": str,
        "node_id": str,
        "stage_index": int,
        "state": str,
        "started_at": datetime,
        "ended_at": datetime,
    },
    "task_attempts": {
        "task_instance_id": int,
        "attempt": int,
        "state": str,
        "started_at": datetime,
        "ended_at": datetime,
        "exit_reason": str,
        "error_class": str,
    },
    "metrics": {
        "run_id": str,
        "task_instance_id": int,
        "name": str,
        "value": float,
        "unit": str,
        "ts": datetime,
        "resolution": str,
    },
    "run_files": {
        "run_id": str,
        "stage_index": int,
        "path": str,
        "size_bytes": int,
        "sha256": str,
        "kind": str,
    },
    "datasets": {"uri": str, "last_run_id": str, "updated_at": datetime},
    "lineage": {"run_id": str, "dataset_id": int, "direction": str, "created_at": datetime},
}

# What only the engine that ran a run knows (the database has no place for it): added to what is read from
# the database while the run is in memory.
_MEMORY_ONLY_RUN: Final = ("created_at", "memory_limit_bytes", "path", "error")
_MEMORY_ONLY_STAGE: Final = (
    "path",
    "operators",
    "worker_id",
    "worker_pid",
    "worker_start",
    "worker_wait_s",
    "memory_bytes",
    "memory_peak_bytes",
    "output",
    "error",
)
# What changes between two transitions of a run that is going: taken from memory while it goes.
_LIVE_STAGE: Final = (
    "state",
    "started_at",
    "finished_at",
    "duration_s",
    "rows_per_node",
    "bytes_written",
    "files",
    "manifest",
    "manifest_bytes",
    "manifest_sha256",
    "exit_reason",
    "error_class",
)


def metadata_path(home: Path) -> Path:
    """`$SAFETWIN_HOME/metadata.db`."""
    return home / METADATA_DB


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _time(value: str | None) -> datetime | None:
    """A time of a record (`2026-10-02T09:30:00.123Z`) as an aware datetime."""
    return None if value is None else datetime.fromisoformat(value).astimezone(UTC)


def _text(value: str | None) -> str | None:
    """A time from the database as a record has it."""
    return None if value is None else utc_iso(from_db_time(value))


def kept_text(pipeline_yaml: str) -> str:
    """The text of a pipeline as `pipeline_versions` keeps it: itself, or `NOT_KEPT` if a line of it looks
    like it holds a secret (`spec.validate.text_secrets`: every line, comments and keys included, and a line
    that starts with `secret://`, `keychain://` or `socket://` is tested too).

    A plain password inside a URL or a comment may look like nothing in particular and not be found. That is
    why the text is not kept longer than its runs: the prune deletes a version once no run refers to it."""
    return NOT_KEPT if next(text_secrets(pipeline_yaml), None) is not None else pipeline_yaml


def _value(value: object) -> object:
    return to_db_time(value) if isinstance(value, datetime) else value


def _insert(connection: sqlite3.Connection, table: str, **values: object) -> int:
    """Insert a row that gives every column of `WRITES[table]`; its rowid (the id of tables that have one)."""
    columns = WRITES[table]
    if set(values) != set(columns):
        raise ValueError(f"an insert into {table} must give exactly its written columns")
    names = ", ".join(columns)
    marks = ", ".join("?" * len(columns))
    cursor = connection.execute(
        f"INSERT INTO {table} ({names}) VALUES ({marks})", [_value(values[name]) for name in columns]
    )
    return int(cursor.lastrowid or 0)


def _update(
    connection: sqlite3.Connection, table: str, where: str, args: Sequence[object], **values: object
) -> int:
    """`UPDATE table SET <values> WHERE <where>`, for columns of `WRITES[table]`. How many rows it changed."""
    if not set(values) <= set(WRITES[table]):
        raise ValueError(f"an update of {table} may only set its written columns")
    assignments = ", ".join(f"{name} = ?" for name in values)
    cursor = connection.execute(
        f"UPDATE {table} SET {assignments} WHERE {where}", [*map(_value, values.values()), *args]
    )
    return cursor.rowcount


def _marks(items: Sequence[object]) -> str:
    return ", ".join("?" * len(items))


@dataclass(frozen=True)
class _Task:
    id: int
    node_id: str
    stage_index: int
    state: str
    started_at: str | None
    ended_at: str | None


@dataclass(frozen=True)
class _Attempt:
    attempt: int
    exit_reason: str | None
    error_class: str | None


@dataclass(frozen=True)
class _File:
    stage_index: int
    path: str
    size_bytes: int
    sha256: str
    kind: str


class DbRunStore:
    """The runs in the metadata database, as the module docs say. Thread-safe.

    `open` it, `start` it (recovery, a prune if one is due, then a prune a day) before the engine serves, and
    `close` it once the engine has stopped. `clock` gives the time of the recovery and of each prune (tests
    give one of their own); `maintain_command` starts the maintenance child (`lite.maintain_command()`).
    """

    def __init__(
        self,
        path: Path,
        *,
        max_runs: int = MAX_RUNS_KEPT,
        settings: HistorySettings | None = None,
        clock: Callable[[], datetime] = _utc_now,
        maintain_command: Sequence[str] | None = None,
    ) -> None:
        self.path = path
        self._max_runs = max_runs
        self.settings = HistorySettings.from_defaults() if settings is None else settings
        self._clock = clock
        self._command = None if maintain_command is None else list(maintain_command)
        self._lock = threading.Lock()  # guards _memory and _operators
        self._write_lock = threading.Lock()  # one write at a time; guards _writer, _written and the counters
        self._writer = lite.connect(path)
        self._memory: OrderedDict[str, RunRecord] = OrderedDict()  # oldest first, by when first saved
        self._written: dict[str, RunRecord] = {}  # the runs going now, as the database last got them
        self._unadded: dict[str, tuple[RunRecord, str]] = {}  # runs whose add failed: as added, and the text
        self._behind: dict[str, RunRecord] = {}  # runs whose last write failed, with their latest state
        self._wake = threading.Event()  # a write failed: the retrier has work
        self._retrier: threading.Thread | None = None
        self.retry_delays_s: tuple[float, ...] = RETRY_DELAYS_S
        self._operators: dict[int, dict[str, str]] = {}  # pipeline version id -> node id -> operator
        self._stop = threading.Event()
        self._pruner: threading.Thread | None = None
        self._attempted: float | None = None  # time.monotonic() of the last prune that was tried
        self.writes = 0  # transactions written, and the time they took (for the measurements)
        self.write_seconds = 0.0
        self.maintenance_seconds = 0.0  # how long this store waited for the maintenance child

    @classmethod
    def open(cls, path: Path, **options: Any) -> "DbRunStore":
        """The store of the database at `path`, made private and in WAL mode. If its schema is not at the
        latest migration (a new file, or an engine that was upgraded), the maintenance child migrates it, and
        prunes as of now, first. Raises `lite.MaintenanceFailed` if that fails, and `sqlite3.Error`."""
        settings: HistorySettings = options.get("settings") or HistorySettings.from_defaults()
        clock: Callable[[], datetime] = options.get("clock", _utc_now)
        connection = lite.connect(path)
        try:
            behind = lite.current_revision(connection) != HEAD_REVISION
        finally:
            connection.close()
        waited = 0.0
        if behind:
            started = time.perf_counter()
            lite.run_maintenance(
                path,
                prune_at=clock(),
                runs_days=settings.runs_days,
                command=options.get("maintain_command"),
            )
            waited = time.perf_counter() - started
        store = cls(path, **options)
        store.maintenance_seconds = waited
        return store

    def start(self) -> None:
        """Mark the runs a dead engine left as interrupted, prune if a prune is due, and from then on prune
        when one is due, on a thread of its own."""
        interrupted = self.recover_interrupted()
        if interrupted:
            _log.warning(
                "%d run(s) left unfinished by an engine that stopped are marked interrupted", interrupted
            )
        if self._until_due() <= 0:
            started = time.perf_counter()
            self._prune_logged()
            self.maintenance_seconds += time.perf_counter() - started
        self._pruner = threading.Thread(target=self._prune_daily, name="safetwin-history-prune", daemon=True)
        self._pruner.start()

    def close(self) -> None:
        """Stop the daily prune (a child that runs is killed) and close the connection. Can be called
        again."""
        self._stop.set()
        self._wake.set()
        for thread in (self._pruner, self._retrier):
            if thread is not None:
                thread.join(10.0)
        with self._write_lock:
            for run in list(self._behind.values()):  # the last try for what is still missing
                if self._sync(run):
                    self._behind.pop(run.run_id, None)
            if self._behind:
                _log.error("%d run(s) could not be written to the history", len(self._behind))
            self._writer.close()

    # --- RunStore -----------------------------------------------------------------------------------------

    def add(self, run: RunRecord, pipeline_yaml: str) -> None:
        with self._write_lock:
            try:
                self._write(self._insert_run, run, pipeline_yaml)
            except Exception as err:  # inserted by the first write that works (`_sync`)
                _log.error("a run could not be added to the history (%s)", type(err).__name__)
                self._unadded[run.run_id] = (run, pipeline_yaml)
                self._fell_behind(run)
            else:
                self._written[run.run_id] = run
            self._remember(run)

    def save(self, run: RunRecord) -> None:
        with self._write_lock:
            if self._sync(run):
                self._behind.pop(run.run_id, None)
            else:  # the run goes on; what was missed is written later
                self._fell_behind(run)
            self._remember(run)

    def _sync(self, run: RunRecord) -> bool:
        """Write what the database is missing of `run` (the write lock is held): all of it if its add failed,
        else what changed since it last got the run. Whether the database has it all now."""
        unadded = self._unadded.get(run.run_id)
        before = self._written.get(run.run_id)
        if unadded is None and (before is None or not _transitions(before, run)):
            return True
        try:
            if unadded is not None:
                self._write(self._insert_and_change, *unadded, run)
            else:
                assert before is not None
                self._write(self._write_changes, before, run)
        except Exception as err:
            _log.error("the history of a run could not be written (%s)", type(err).__name__)
            return False
        self._unadded.pop(run.run_id, None)
        if run.ended:
            self._written.pop(run.run_id, None)
        else:
            self._written[run.run_id] = run
        return True

    def _fell_behind(self, run: RunRecord) -> None:
        """Keep `run` to be written again from the retrier's thread (started the first time it is needed)."""
        self._behind[run.run_id] = run
        if self._retrier is None and not self._stop.is_set():
            self._retrier = threading.Thread(target=self._retry, name="safetwin-history-retry", daemon=True)
            self._retrier.start()
        self._wake.set()

    def _retry(self) -> None:
        """Try what failed again after each of `retry_delays_s`, then wait for the next failure (or close)."""
        while not self._stop.is_set():
            self._wake.wait()
            self._wake.clear()
            for delay in self.retry_delays_s:
                if self._stop.wait(delay):
                    return
                with self._write_lock:
                    for run_id, run in list(self._behind.items()):
                        if self._sync(run):
                            self._behind.pop(run_id, None)
                    if not self._behind:
                        break

    def _insert_and_change(
        self, connection: sqlite3.Connection, added: RunRecord, pipeline_yaml: str, run: RunRecord
    ) -> None:
        """A run whose add failed: insert it as it was added, then write everything since, in one go."""
        self._insert_run(connection, added, pipeline_yaml)
        self._write_changes(connection, added, run)

    def get(self, run_id: str) -> RunRecord | None:
        with self._lock:
            known = self._memory.get(run_id)
        if not re.fullmatch(RUN_ID_PATTERN, run_id):
            return known
        try:
            with self._reading() as connection:
                stored = self._read(connection, run_id)
        except sqlite3.Error as err:
            _log.error("a run could not be read from the history (%s)", type(err).__name__)
            return known
        return _merge(stored, known)

    def recent(
        self,
        limit: int,
        *,
        before: str | None = None,
        pipeline: str | None = None,
        state: str | None = None,
    ) -> list[RunSummary]:
        with self._lock:
            known = dict(self._memory)
        with self._reading() as connection:
            summaries = _read_page(connection, limit, before, pipeline, state)
        return [_merge_summary(summary, known.get(summary.run_id)) for summary in summaries]

    # --- recovery and retention ---------------------------------------------------------------------------

    def recover_interrupted(self) -> int:
        """Mark every run that is still queued or running as `interrupted` (`EngineStopped`), with its task
        instances and attempts that had not ended. How many runs. Call it only while no engine runs runs."""
        now = self._clock()
        with self._write_lock, self._transaction() as connection:
            run_ids = [
                row[0]
                for row in connection.execute("SELECT id FROM runs WHERE state IN ('queued', 'running')")
            ]
            if not run_ids:
                return 0
            marks = _marks(run_ids)
            tasks = f"SELECT id FROM task_instances WHERE run_id IN ({marks})"
            _update(
                connection,
                "task_attempts",
                f"task_instance_id IN ({tasks}) AND ended_at IS NULL",
                run_ids,
                state="interrupted",
                ended_at=now,
                exit_reason=INTERRUPTED_EXIT,
                error_class=INTERRUPTED_ERROR,
            )
            _update(
                connection,
                "task_instances",
                f"run_id IN ({marks}) AND state = 'running'",
                run_ids,
                state="interrupted",
                ended_at=now,
            )
            _update(  # a stage that never started has no end either
                connection,
                "task_instances",
                f"run_id IN ({marks}) AND state = 'pending'",
                run_ids,
                state="interrupted",
            )
            _update(
                connection,
                "runs",
                f"id IN ({marks})",
                run_ids,
                state="interrupted",
                ended_at=now,
                error_class=INTERRUPTED_ERROR,
            )
        return len(run_ids)

    def prune(self) -> Pruned:
        """Delete runs that ended more than `settings.runs_days` ago, in the maintenance child
        (`metadata.prune`, which also adds its event to the audit log). What it deleted. Raises
        `lite.MaintenanceFailed`.

        A prune that deleted pipeline versions also empties the cache of their operators (`_operators_of`):
        `pipeline_versions.id` is an INTEGER PRIMARY KEY without AUTOINCREMENT, so SQLite may give the id of
        a deleted version to the next new one, which must not get the deleted version's operators."""
        pruned = lite.run_maintenance(
            self.path,
            prune_at=self._clock(),
            runs_days=self.settings.runs_days,
            stop=self._stop,
            command=self._command,
        )
        if pruned is None:
            return Pruned(runs=0)
        if pruned.versions:
            with self._lock:
                self._operators.clear()
        return pruned

    def _until_due(self) -> float:
        """Seconds until a prune is due: `settings.prune_interval_s` after the last one (0 if it is due)."""
        with self._write_lock:
            last = lite.last_prune(self._writer)
        if last is None:
            return 0.0
        return max(0.0, self.settings.prune_interval_s - (self._clock() - last).total_seconds())

    def _prune_logged(self) -> None:
        self._attempted = time.monotonic()
        try:
            result = self.prune()
        except Exception as err:
            if not self._stop.is_set():
                _log.error("old run history could not be deleted (%s)", type(err).__name__)
            return
        if result.runs:
            _log.info("deleted %d old run(s) from the history", result.runs)

    def _prune_daily(self) -> None:
        """Prune whenever a prune is due, but never more often than once an interval (a prune that fails is
        tried again an interval later)."""
        interval = self.settings.prune_interval_s
        while True:
            delay = self._until_due()
            if self._attempted is not None:
                delay = max(delay, self._attempted + interval - time.monotonic())
            if self._stop.wait(max(0.0, delay)):
                return
            self._prune_logged()

    # --- memory -------------------------------------------------------------------------------------------

    def _remember(self, run: RunRecord) -> None:
        with self._lock:
            self._memory[run.run_id] = run
            excess = len(self._memory) - self._max_runs
            if excess > 0:
                for run_id in [key for key, kept in self._memory.items() if kept.ended][:excess]:
                    del self._memory[run_id]

    # --- writing ------------------------------------------------------------------------------------------

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        """The writing connection in a transaction that takes the write lock at once (`BEGIN IMMEDIATE`),
        committed at the end or rolled back if anything fails. `_write_lock` is held."""
        connection = self._writer
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")

    @contextmanager
    def _reading(self) -> Iterator[sqlite3.Connection]:
        """A connection of its own, in one read transaction (every query sees the same moment)."""
        connection = lite.connect(self.path)
        try:
            connection.execute("BEGIN")
            yield connection
            connection.execute("COMMIT")
        finally:
            connection.close()

    def _write(self, step: Callable[..., None], *args: Any) -> None:
        """Run `step(connection, *args)` in one transaction, and count the time it took (the lock is held)."""
        started = time.perf_counter()
        try:
            with self._transaction() as connection:
                step(connection, *args)
        finally:
            self.writes += 1
            self.write_seconds += time.perf_counter() - started

    def _insert_run(self, connection: sqlite3.Connection, run: RunRecord, pipeline_yaml: str) -> None:
        now = self._clock()
        digest = hashlib.sha256(pipeline_yaml.encode("utf-8")).hexdigest()
        if connection.execute("SELECT 1 FROM pipelines WHERE id = ?", (run.pipeline,)).fetchone() is None:
            _insert(
                connection,
                "pipelines",
                id=run.pipeline,
                name=run.pipeline,
                description=None,
                created_at=now,
                updated_at=now,
            )
        latest = connection.execute(
            "SELECT id, version, spec_sha256 FROM pipeline_versions WHERE pipeline_id = ? "
            "ORDER BY version DESC LIMIT 1",
            (run.pipeline,),
        ).fetchone()
        if latest is not None and latest[2] == digest:
            version_id = int(latest[0])
        else:
            version_id = _insert(
                connection,
                "pipeline_versions",
                pipeline_id=run.pipeline,
                version=1 if latest is None else int(latest[1]) + 1,
                yaml_text=kept_text(pipeline_yaml),
                spec_sha256=digest,
                created_at=now,
            )
        _insert(
            connection,
            "runs",
            id=run.run_id,
            pipeline_id=run.pipeline,
            pipeline_version_id=version_id,
            state=run.state,
            started_at=_time(run.started_at),
            ended_at=_time(run.finished_at) if run.ended else None,
            error_class=run.error_class,
        )

    def _write_changes(self, connection: sqlite3.Connection, before: RunRecord, run: RunRecord) -> None:
        """What changed between `before` (as the database has the run) and `run`: its state, its planned
        stages, and each stage that started or ended."""
        if (before.state, before.started_at, before.finished_at) != (
            run.state,
            run.started_at,
            run.finished_at,
        ):
            _update(
                connection,
                "runs",
                "id = ?",
                (run.run_id,),
                state=run.state,
                started_at=_time(run.started_at),
                ended_at=_time(run.finished_at) if run.ended else None,
                error_class=run.error_class,
            )
        if not before.stages and run.stages:
            for stage in run.stages:
                for node_id in stage.node_ids:
                    _insert(
                        connection,
                        "task_instances",
                        run_id=run.run_id,
                        node_id=node_id,
                        stage_index=stage.index,
                        state=stage.state,
                        started_at=None,
                        ended_at=None,
                    )
        old_states = {stage.index: stage.state for stage in before.stages}
        for stage in run.stages:
            if old_states.get(stage.index, "pending") != stage.state:
                self._write_stage(connection, run, stage)
        if run.ended:
            peaks = [stage.memory_peak_bytes for stage in run.stages if stage.memory_peak_bytes is not None]
            if peaks:
                _insert(
                    connection,
                    "metrics",
                    run_id=run.run_id,
                    task_instance_id=None,
                    name="memory_peak_bytes",
                    value=float(max(peaks)),
                    unit="bytes",
                    ts=_time(run.finished_at) or self._clock(),
                    resolution="raw",
                )

    def _write_stage(self, connection: sqlite3.Connection, run: RunRecord, stage: StageRecord) -> None:
        """A stage that started (its task instances run and get attempt 1) or ended (their states, the
        attempts' ends, the metrics, the files and the lineage)."""
        tasks = {
            str(node_id): int(task_id)
            for node_id, task_id in connection.execute(
                "SELECT node_id, id FROM task_instances WHERE run_id = ? AND stage_index = ?",
                (run.run_id, stage.index),
            )
        }
        ids = [tasks[node_id] for node_id in stage.node_ids if node_id in tasks]
        if not ids:
            return
        marks = _marks(ids)
        started, finished = _time(stage.started_at), _time(stage.finished_at)
        ended = stage.state in ENDED
        _update(
            connection,
            "task_instances",
            f"id IN ({marks})",
            ids,
            state=stage.state,
            started_at=started,
            ended_at=finished if ended else None,
        )
        attempt: dict[str, Any] = {
            "state": stage.state,
            "ended_at": finished if ended else None,
            "exit_reason": stage.exit_reason,
            "error_class": stage.error_class,
        }
        changed = _update(
            connection,
            "task_attempts",
            f"task_instance_id IN ({marks}) AND attempt = ?",
            [*ids, stage.attempt],
            **attempt,
        )
        if changed == 0:  # the stage has not had an attempt yet
            began = started or finished or self._clock()
            for task_id in ids:
                _insert(
                    connection,
                    "task_attempts",
                    task_instance_id=task_id,
                    attempt=stage.attempt,
                    started_at=began,
                    **attempt,
                )
        if not ended:
            return
        at = finished or self._clock()
        for node_id, rows in stage.rows_per_node.items():
            if node_id in tasks:
                self._metric(connection, run.run_id, tasks[node_id], "rows_out", rows, "rows", at)
        sink = tasks.get(stage.node_ids[-1])
        if sink is not None:
            self._metric(connection, run.run_id, sink, "bytes_written", stage.bytes_written, "bytes", at)
            if stage.duration_s is not None:
                self._metric(connection, run.run_id, sink, "duration_s", stage.duration_s, "seconds", at)
        for file in stage.files:
            _insert(
                connection,
                "run_files",
                run_id=run.run_id,
                stage_index=stage.index,
                path=file.path,
                size_bytes=file.bytes,
                sha256=file.sha256,
                kind="data",
            )
        if stage.manifest and stage.manifest_sha256 and stage.manifest_bytes is not None:
            _insert(
                connection,
                "run_files",
                run_id=run.run_id,
                stage_index=stage.index,
                path=stage.manifest,
                size_bytes=stage.manifest_bytes,
                sha256=stage.manifest_sha256,
                kind="manifest",
            )
        if stage.state == "succeeded" and stage.output:
            self._write_output(connection, run.run_id, Path(stage.output).as_uri())

    @staticmethod
    def _metric(
        connection: sqlite3.Connection,
        run_id: str,
        task_id: int,
        name: str,
        value: float,
        unit: str,
        at: datetime,
    ) -> None:
        _insert(
            connection,
            "metrics",
            run_id=run_id,
            task_instance_id=task_id,
            name=name,
            value=float(value),
            unit=unit,
            ts=at,
            resolution="raw",
        )

    def _write_output(self, connection: sqlite3.Connection, run_id: str, uri: str) -> None:
        now = self._clock()
        row = connection.execute("SELECT id FROM datasets WHERE uri = ?", (uri,)).fetchone()
        if row is None:
            dataset_id = _insert(connection, "datasets", uri=uri, last_run_id=run_id, updated_at=now)
        else:
            dataset_id = int(row[0])
            _update(connection, "datasets", "id = ?", (dataset_id,), last_run_id=run_id, updated_at=now)
        edge = connection.execute(
            "SELECT 1 FROM lineage WHERE run_id = ? AND dataset_id = ? AND direction = 'output'",
            (run_id, dataset_id),
        ).fetchone()
        if edge is None:
            _insert(
                connection,
                "lineage",
                run_id=run_id,
                dataset_id=dataset_id,
                direction="output",
                created_at=now,
            )

    # --- reading ------------------------------------------------------------------------------------------

    def _read(self, connection: sqlite3.Connection, run_id: str) -> RunRecord | None:
        """The run as the database has it (`None` if it does not), without what only memory holds."""
        run = connection.execute(
            "SELECT id, pipeline_id, pipeline_version_id, state, started_at, ended_at, error_class "
            "FROM runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        if run is None:
            return None
        tasks = [
            _Task(*row)
            for row in connection.execute(
                "SELECT id, node_id, stage_index, state, started_at, ended_at FROM task_instances "
                "WHERE run_id = ? ORDER BY stage_index, id",
                (run_id,),
            )
        ]
        attempts: dict[int, _Attempt] = {}
        for task_id, number, exit_reason, error_class in connection.execute(
            "SELECT a.task_instance_id, a.attempt, a.exit_reason, a.error_class FROM task_attempts a "
            "JOIN task_instances t ON t.id = a.task_instance_id WHERE t.run_id = ? ORDER BY a.attempt",
            (run_id,),
        ):
            attempts[task_id] = _Attempt(number, exit_reason, error_class)  # the latest attempt of each
        metrics: dict[tuple[int | None, str], float] = {
            (task_id, name): float(value)
            for task_id, name, value in connection.execute(
                "SELECT task_instance_id, name, value FROM metrics WHERE run_id = ?", (run_id,)
            )
        }
        files = [
            _File(*row)
            for row in connection.execute(
                "SELECT stage_index, path, size_bytes, sha256, kind FROM run_files "
                "WHERE run_id = ? ORDER BY id",
                (run_id,),
            )
        ]
        stages = _stages(tasks, attempts, metrics, files, self._operators_of(connection, int(run[2])))
        return RunRecord(
            run_id=run[0],
            state=run[3],
            pipeline=run[1],
            started_at=_text(run[4]),
            finished_at=_text(run[5]),
            stages=stages,
            totals=_totals(stages),
            error_class=run[6],
        )

    def _operators_of(self, connection: sqlite3.Connection, version_id: int) -> dict[str, str]:
        """The operator of each node of a pipeline version, from its text (cached by version)."""
        with self._lock:
            cached = self._operators.get(version_id)
        if cached is not None:
            return cached
        row = connection.execute(
            "SELECT yaml_text FROM pipeline_versions WHERE id = ?", (version_id,)
        ).fetchone()
        try:
            found = {node.id: node.operator for node in load_pipeline_text(row[0] if row else "").spec.nodes}
        except SpecError:  # a text that is not kept
            found = {}
        with self._lock:
            if len(self._operators) >= MAX_CACHED_VERSIONS:
                self._operators.clear()
            self._operators[version_id] = found
        return found


def _read_page(
    connection: sqlite3.Connection, limit: int, before: str | None, pipeline: str | None, state: str | None
) -> list[RunSummary]:
    """A page of runs, newest first: in the order they were added (SQLite's rowid, which only grows for a
    table that never loses its newest row: retention deletes old runs only).

    The metadata database must never be VACUUMed: `runs` has a text primary key, so its rowids are SQLite's
    own, and VACUUM may renumber them, which would reorder the history and break the `before` cursors of the
    API. (`auto_vacuum` moves pages, not rowids.) A test checks that nothing in the engine issues VACUUM.
    """
    where: list[str] = []
    args: list[object] = []
    if before is not None:
        cursor = connection.execute("SELECT rowid FROM runs WHERE id = ?", (before,)).fetchone()
        if cursor is None:
            raise UnknownCursor(before)
        where.append("rowid < ?")
        args.append(cursor[0])
    if pipeline is not None:
        where.append("pipeline_id = ?")
        args.append(pipeline)
    if state is not None:
        where.append("state = ?")
        args.append(state)
    clause = f"WHERE {' AND '.join(where)} " if where else ""
    runs = connection.execute(
        f"SELECT id, pipeline_id, state, started_at, ended_at, error_class FROM runs {clause}"
        "ORDER BY rowid DESC LIMIT ?",
        [*args, limit],
    ).fetchall()
    totals = _page_totals(connection, [run[0] for run in runs])
    return [
        RunSummary(
            run_id=run_id,
            state=run_state,
            pipeline=pipeline_id,
            created_at=None,
            started_at=_text(started),
            finished_at=_text(ended),
            error_class=error_class,
            totals=totals.get(run_id, Totals()),
        )
        for run_id, pipeline_id, run_state, started, ended, error_class in runs
    ]


def _transitions(before: RunRecord, run: RunRecord) -> bool:
    """Whether `run` differs from `before` by more than progress: its state, or the state of a stage."""
    return (
        before.state != run.state
        or before.started_at != run.started_at
        or len(before.stages) != len(run.stages)
        or any(old.state != new.state for old, new in zip(before.stages, run.stages, strict=False))
    )


def _stages(
    tasks: Sequence[_Task],
    attempts: dict[int, _Attempt],
    metrics: dict[tuple[int | None, str], float],
    files: Sequence[_File],
    operators: dict[str, str],
) -> list[StageRecord]:
    """The stages of a run from its rows: each stage's task instances in node order, the last one its sink."""
    grouped: dict[int, list[_Task]] = {}
    for task in tasks:
        grouped.setdefault(task.stage_index, []).append(task)
    stages = []
    for index, members in sorted(grouped.items()):
        sink = members[-1]
        attempt = attempts.get(sink.id)
        manifest = next((f for f in files if f.stage_index == index and f.kind == "manifest"), None)
        stages.append(
            StageRecord(
                index=index,
                node_ids=[task.node_id for task in members],
                operators=[operators.get(task.node_id, "unknown") for task in members],
                state=sink.state,  # type: ignore[arg-type]  # a state this module wrote
                attempt=attempt.attempt if attempt is not None else 1,
                started_at=_text(sink.started_at),
                finished_at=_text(sink.ended_at),
                duration_s=metrics.get((sink.id, "duration_s")),
                rows_per_node={
                    task.node_id: int(metrics[(task.id, "rows_out")])
                    for task in members
                    if (task.id, "rows_out") in metrics
                },
                bytes_written=int(metrics.get((sink.id, "bytes_written"), 0)),
                files=[
                    FileRecord(path=f.path, bytes=f.size_bytes, sha256=f.sha256)
                    for f in files
                    if f.stage_index == index and f.kind == "data"
                ],
                manifest=manifest.path if manifest is not None else None,
                manifest_bytes=manifest.size_bytes if manifest is not None else None,
                manifest_sha256=manifest.sha256 if manifest is not None else None,
                exit_reason=attempt.exit_reason if attempt is not None else None,
                error_class=attempt.error_class if attempt is not None else None,
            )
        )
    return stages


def _totals(stages: Sequence[StageRecord]) -> Totals:
    """What the run wrote, as the executor counts it: the rows of the sinks of the stages that succeeded."""
    done = [stage for stage in stages if stage.state == "succeeded"]
    return Totals(
        rows=sum(stage.rows_per_node.get(stage.node_ids[-1], 0) for stage in done if stage.node_ids),
        bytes=sum(file.bytes for stage in done for file in stage.files),
        files=sum(len(stage.files) for stage in done),
    )


def _page_totals(connection: sqlite3.Connection, run_ids: list[str]) -> dict[str, Totals]:
    """The totals of these runs, in two queries: their data files, and the rows of their sinks."""
    if not run_ids:
        return {}
    found: dict[str, Totals] = {run_id: Totals() for run_id in run_ids}
    marks = _marks(run_ids)
    for run_id, count, size in connection.execute(
        f"SELECT run_id, count(*), coalesce(sum(size_bytes), 0) FROM run_files "
        f"WHERE run_id IN ({marks}) AND kind = 'data' GROUP BY run_id",
        run_ids,
    ):
        found[run_id].files, found[run_id].bytes = int(count), int(size)
    sinks: dict[tuple[str, int], tuple[int, str, float]] = {}  # (run, stage) -> the last task instance
    for run_id, stage_index, task_id, state, value in connection.execute(
        "SELECT t.run_id, t.stage_index, t.id, t.state, m.value FROM task_instances t "
        f"JOIN metrics m ON m.task_instance_id = t.id AND m.name = 'rows_out' WHERE t.run_id IN ({marks})",
        run_ids,
    ):
        known = sinks.get((run_id, stage_index))
        if known is None or task_id > known[0]:
            sinks[(run_id, stage_index)] = (task_id, state, value)
    for (run_id, _), (_, state, value) in sinks.items():
        if state == "succeeded":
            found[run_id].rows += int(value)
    return found


def _merge(stored: RunRecord | None, known: RunRecord | None) -> RunRecord | None:
    """The run from the database, with what only this engine's memory holds (`known`), and with its latest
    progress while it is going. A run that is only in one of them, or whose state the database does not have
    yet (a write failed), is taken from memory as it is."""
    if stored is None or known is None:
        return stored or known
    if stored.state != known.state:
        return known
    merged = stored.model_copy(update={name: getattr(known, name) for name in _MEMORY_ONLY_RUN})
    live = not known.ended
    if live:
        merged.state, merged.started_at = known.state, known.started_at
        merged.totals = known.totals.model_copy()
    if len(known.stages) != len(stored.stages):  # planned in memory, not written yet
        merged.stages = [stage.model_copy() for stage in known.stages] if live else merged.stages
        return merged
    fields = _MEMORY_ONLY_STAGE + (_LIVE_STAGE if live else ())
    merged.stages = [
        kept.model_copy(update={name: getattr(memory, name) for name in fields})
        for kept, memory in zip(stored.stages, known.stages, strict=True)
    ]
    return merged


def _merge_summary(summary: RunSummary, known: RunRecord | None) -> RunSummary:
    """A summary from the database, with when the run was queued, and its progress while it is going."""
    if known is None:
        return summary
    if not known.ended:
        return known.summary()
    return summary.model_copy(update={"created_at": known.created_at})
