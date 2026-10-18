"""The state of the runs: what the control API shows, behind one small interface.

`RunRecord` is a run as `GET /v1/runs/{run_id}` shows it, with its stages. The executor keeps the record of a
run that is queued or running, and hands a copy to the `RunStore` each time it changes: `add` when the run is
queued (with the text of its pipeline), then `save` for every change: state, a stage that starts or ends,
progress. `MemoryRunStore` keeps the runs of this engine's life in memory (the newest `max_runs`), for tests
and for an executor without a database. The engine itself uses `history.DbRunStore`, which keeps the runs in
the metadata database and writes less often than it is called (not at every progress).

A record holds ids, names, states, times, counts, sizes, paths of committed files, SHA-256 and safe errors:
never data. Standard library and pydantic only.

A run that an engine left queued or running when it stopped without ending it (a crash, SIGKILL) is
`interrupted`, and so are its stages that had not ended: the next engine marks them so in the database. Some
fields are known only to the engine that ran the run (they are not in the database): when it was queued, its
memory share, the way each stage ran, the stage workers, and the engine's safe messages (`error`). A record
read from the database after a restart has None there.
"""

import threading
from collections import OrderedDict
from typing import Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

RunState = Literal["queued", "running", "succeeded", "failed", "cancelled", "interrupted"]
StageState = Literal["pending", "running", "succeeded", "failed", "cancelled", "interrupted"]
DataPath = Literal["fused", "batch", "hybrid"]
ENDED: frozenset[str] = frozenset({"succeeded", "failed", "cancelled", "interrupted"})
RUN_ID_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"  # as a manifest allows it
PIPELINE_ID_PATTERN: Final = r"^[a-z0-9][a-z0-9-]*$"  # metadata.name


class UnknownCursor(Exception):
    """The run that a listing should continue after (`before`) is not known."""


class _Record(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FileRecord(_Record):
    path: str
    bytes: int
    sha256: str


class StageRecord(_Record):
    """One stage of a run (`index` counts from 0). `attempt` is 1: stages are not retried.

    `exit_reason` is how the stage's worker ended, as a short code: `exit_0`, `exit_1`, `signal_9` or
    `cancelled`. `output` is the folder of the dataset its sink writes. `memory_peak_bytes` is the most memory
    any progress of the stage reported.
    """

    index: int
    node_ids: list[str]
    operators: list[str]
    path: DataPath | None = None  # None in a record read from the database
    state: StageState = "pending"
    attempt: int = 1
    worker_id: str | None = None
    worker_pid: int | None = None
    worker_start: Literal["warm", "cold"] | None = None  # a worker started before it was needed, or not
    worker_wait_s: float | None = None  # how long the stage waited for its worker to be ready
    started_at: str | None = None
    finished_at: str | None = None
    duration_s: float | None = None
    rows_per_node: dict[str, int] = Field(default_factory=dict)
    bytes_written: int = 0
    memory_bytes: int | None = None  # at the last progress
    memory_peak_bytes: int | None = None
    files: list[FileRecord] = Field(default_factory=list)
    manifest: str | None = None
    manifest_bytes: int | None = None
    manifest_sha256: str | None = None
    output: str | None = None
    exit_reason: str | None = None
    error_class: str | None = None
    error: str | None = None


class Totals(_Record):
    """What the run wrote: the rows of its sinks, the bytes and the number of files."""

    rows: int = 0
    bytes: int = 0
    files: int = 0


class RunRecord(_Record):
    run_id: str
    state: RunState = "queued"
    pipeline: str
    created_at: str | None = None  # when it was queued; None in a record read from the database
    started_at: str | None = None
    finished_at: str | None = None
    memory_limit_bytes: int | None = None  # the share of each of its stages; None from the database
    path: DataPath | None = None  # every stage forced to run this way
    stages: list[StageRecord] = Field(default_factory=list)
    totals: Totals = Field(default_factory=Totals)
    error_class: str | None = None
    error: str | None = None

    @property
    def ended(self) -> bool:
        return self.state in ENDED

    def summary(self) -> "RunSummary":
        return RunSummary(
            run_id=self.run_id,
            state=self.state,
            pipeline=self.pipeline,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            error_class=self.error_class,
            totals=self.totals.model_copy(),
        )


class RunSummary(_Record):
    """A run as `GET /v1/runs` lists it."""

    run_id: str
    state: RunState
    pipeline: str
    created_at: str | None
    started_at: str | None
    finished_at: str | None
    error_class: str | None
    totals: Totals = Field(default_factory=Totals)


class RunStore(Protocol):
    """Where the state of the runs is kept."""

    def add(self, run: RunRecord, pipeline_yaml: str) -> None:
        """Keep a run that has just been queued, with the text of its pipeline (validated already)."""

    def save(self, run: RunRecord) -> None:
        """Keep this state of the run (it is a copy: the store may keep it as it is)."""

    def get(self, run_id: str) -> RunRecord | None:
        """The last state saved for the run, or None."""

    def recent(
        self,
        limit: int,
        *,
        before: str | None = None,
        pipeline: str | None = None,
        state: str | None = None,
    ) -> list[RunSummary]:
        """The runs, newest first, at most `limit`: only those of `pipeline` and in `state` when they are
        given, and only those queued before the run `before` (raises `UnknownCursor` if it is not known)."""


class MemoryRunStore:
    """The runs of this engine's life, in memory: the newest `max_runs`. A run that has not ended is never
    dropped to make room."""

    def __init__(self, max_runs: int = 100) -> None:
        self._max_runs = max_runs
        self._runs: OrderedDict[str, RunRecord] = OrderedDict()  # oldest first, by when first saved
        self._lock = threading.Lock()

    def add(self, run: RunRecord, pipeline_yaml: str) -> None:
        self.save(run)

    def save(self, run: RunRecord) -> None:
        with self._lock:
            self._runs[run.run_id] = run
            excess = len(self._runs) - self._max_runs
            if excess > 0:
                for run_id in [key for key, kept in self._runs.items() if kept.ended][:excess]:
                    del self._runs[run_id]

    def get(self, run_id: str) -> RunRecord | None:
        with self._lock:
            return self._runs.get(run_id)

    def recent(
        self,
        limit: int,
        *,
        before: str | None = None,
        pipeline: str | None = None,
        state: str | None = None,
    ) -> list[RunSummary]:
        with self._lock:
            newest_first = list(reversed(self._runs.values()))
        if before is not None:
            ids = [run.run_id for run in newest_first]
            if before not in ids:
                raise UnknownCursor(before)
            newest_first = newest_first[ids.index(before) + 1 :]
        chosen = [
            run
            for run in newest_first
            if (pipeline is None or run.pipeline == pipeline) and (state is None or run.state == state)
        ]
        return [run.summary() for run in chosen[:limit]]
