"""The executor: the queue of runs, the stage workers that run their stages, and their events
(docs/internals.md).

**Runs.** `submit` queues a run (state `queued`). At most `max_stage_workers` runs (2) are active at once,
each on a thread of its own; the others wait in a FIFO queue of at most `max_queued_runs` (32: `QueueFull`
beyond). The stages of a run go one after the other
(linear chains), so an active run has at most one stage worker at any time, and at most `max_stage_workers`
workers run at once. An active run:

1. takes a worker (the warm one if there is one, else it starts one: a cold start), and asks it to plan the
   run (a `plan` job: validate, split into stages, check every config, plan every sink). Planning needs
   Polars (the steps are built to check them), so it happens in the worker and the control plane stays light;
2. for each stage: takes a worker (the first stage uses the one that planned), sends it the stage with what
   the earlier stages committed and its share of memory, forwards its progress (at most four events a second
   for each stage), and records its result. The worker ends after its stage, and its private temporary
   folder is deleted (`process.py`);
3. ends `succeeded`, `failed` (with a safe error: a class name, and the engine's own message where it has
   one) or `cancelled`.

**Memory.** The engine's global limit is split between the workers that may run at once: each stage gets
`limit // max_stage_workers` (`ExecutorSettings.share_for`; a run may ask for less). The worker's watchdog
and DuckDB use that share. The share is what a stage may *grow by*: the watchdog measures from a baseline
taken when the stage starts, so the memory every worker holds once it has imported its libraries (about
110 MB rss, 60 MB phys_footprint, measured on an Apple M4) is outside the shares. That includes the one warm
worker that may wait idle besides the running ones: so the engine's processes can hold up to about three of
those baselines (two running, one idle) on top of the global limit, plus the control plane itself.

**The warm worker.** Importing the data libraries takes about 3 s on a cold start. So when a stage starts and
its run has more stages to go, a worker is started for the next one; and when a stage ends, one idle worker
is kept (started if need be) for `warm_worker_s` (60 s) for the next stage or run. Then it is told to end, so
an idle engine holds no worker. At most one worker is idle at any time. A warm worker that turns out to have
died before it got its job is replaced by a cold start, not reported as a failure.

**Locks.** The executor's lock is never held while a process is started or waited for, so the API (which
calls `submit`, `cancel` and `counts` from a thread pool) never waits on a worker.

**Failures and cleanup.** Whatever ends a stage early (an error in the stage, a worker that dies: a crash,
SIGKILL, the system's OOM killer, a message that breaks the protocol, a cancel), the control plane waits
until the worker's process is gone (SIGKILL after a grace period), deletes its temporary folder, and then
removes what the stage may have left in its sink, as `run_pipeline_local` does
(`dataplane.cleanup.remove_stage_leftovers`): the temporary files, and the data file of this run if no
manifest lists it. A worker that dies is reported as "the stage worker stopped (signal 9)" or "(exit code N)",
never with what it wrote on stderr. There are no retries yet: every stage is attempt 1.

**Cancel.** A queued run is cancelled at once. An active run's worker gets SIGINT (the stage cleans up and the
worker ends), then SIGKILL after `cancel_grace_s` (5 s) if it is still there, and the cleanup above runs.

**Events** go to `on_event(type, data)`, from the thread of a run or of the caller: `run.queued`,
`run.started`, `stage.started`, `stage.progress`, `stage.finished`, `run.finished`, `run.failed` and
`run.cancelled`. Their data are ids, names, states, counts, sizes, paths of committed files and safe errors.
The events of a run are sent in order. The state of every run is saved in the `RunStore` at every change:
`add` when it is queued (with the text of its pipeline), `save` after that. The engine's store is the metadata
database (`history.DbRunStore`); without one, the runs of this engine's life are kept in memory.

**Exit reasons.** Each stage records how its worker ended, as a short code (`exit_0`, `exit_1`, `signal_9`),
or `cancelled`: the history keeps it with the attempt.

Nothing here imports Polars, PyArrow or DuckDB.
"""

import logging
import os
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from safetwin.dataplane.cleanup import remove_stage_leftovers

from .process import WorkerProcess, WorkerStopped
from .protocol import (
    Failed,
    FileOut,
    PlanDone,
    PlanJob,
    PlannedStageOut,
    Progress,
    ProtocolError,
    StageDone,
    StageJob,
    utc_iso,
)
from .settings import ExecutorSettings
from .store import (
    DataPath,
    FileRecord,
    MemoryRunStore,
    RunRecord,
    RunState,
    RunStore,
    RunSummary,
    StageRecord,
)
from .tmp import TmpFolderError, ensure_tmp_root

_log = logging.getLogger(__name__)

EventSink = Callable[[str, dict[str, Any]], None]
WORKER_STOPPED = "the stage worker stopped"
PROTOCOL_BROKEN = "the stage worker sent a message that does not fit the protocol"
JOB_TOO_LARGE = "the job is too large to send to a stage worker"


class RunNotFound(Exception):
    """No run has this id."""


class RunEnded(Exception):
    """The run has ended already: it can't be cancelled."""


class ExecutorClosed(Exception):
    """The engine is stopping: no run is accepted."""


class QueueFull(Exception):
    """Too many runs wait already: this one is not accepted."""


class _Ended(Exception):
    """The run ends here, in `state`, with a safe error, and how the worker of its stage ended (a code)."""

    def __init__(
        self,
        state: RunState,
        error_class: str | None = None,
        error: str | None = None,
        *,
        exit_reason: str | None = None,
    ) -> None:
        super().__init__(state)
        self.state: RunState = state
        self.error_class = error_class
        self.error = error
        self.exit_reason = "cancelled" if state == "cancelled" else exit_reason
        self.stage: int | None = None


@dataclass(eq=False)
class _Run:
    """A run that is queued or active, with what the control plane needs to drive it."""

    record: RunRecord
    pipeline_yaml: str = field(repr=False)
    sockets: dict[str, str] = field(repr=False)
    share: int = 1  # the memory each of its stages may use
    started_at: datetime | None = None
    cancel_requested: bool = False
    worker: WorkerProcess | None = None
    stages_left: int = 0  # stages after the one that runs now (known once the run is planned)
    stage: PlannedStageOut | None = None  # the stage that runs now
    stage_existed: bool = False  # whether its data file was there before it started
    thread: threading.Thread | None = None
    last_progress: dict[int, float] = field(default_factory=dict)

    @property
    def run_id(self) -> str:
        return self.record.run_id


def _now() -> str:
    return utc_iso(datetime.now(UTC))


def exit_code(description: str) -> str:
    """How a worker ended (`process.describe_exit`: `signal 9`, `exit code 1`) as a short code: `signal_9`,
    `exit_1`."""
    kind, _, number = description.rpartition(" ")
    return f"signal_{number}" if kind == "signal" else f"exit_{number}"


class Executor:
    """Runs pipelines in stage workers, as the module docs say. Call `start` first and `shutdown` last."""

    def __init__(
        self,
        home: Path,
        settings: ExecutorSettings,
        *,
        store: RunStore | None = None,
        on_event: EventSink | None = None,
        worker_command: Sequence[str] | None = None,
        worker_env: Mapping[str, str] | None = None,
    ) -> None:
        self.home = home
        self.settings = settings
        self.store: RunStore = MemoryRunStore(settings.max_runs_kept) if store is None else store
        self._on_event = on_event
        self._command = worker_command
        self._env = worker_env
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._queue: deque[_Run] = deque()
        self._active: dict[str, _Run] = {}
        self._live: dict[str, _Run] = {}  # queued or active, by id
        self._idle: WorkerProcess | None = None
        self._idle_until = 0.0
        self._spawning_idle = False
        self._closing = False
        self._housekeeper: threading.Thread | None = None
        self._reapers: list[threading.Thread] = []  # threads that end workers in the background

    def set_event_sink(self, on_event: EventSink | None) -> None:
        self._on_event = on_event

    def start(self) -> None:
        """Make the temporary folder of the workers and start the thread that lets the warm worker go."""
        ensure_tmp_root(self.home)
        self._housekeeper = threading.Thread(target=self._housekeep, name="safetwin-executor", daemon=True)
        self._housekeeper.start()

    # --- what the API calls ---------------------------------------------------------------------------------

    def submit(
        self,
        *,
        pipeline: str,
        pipeline_yaml: str,
        sockets: Mapping[str, str],
        memory_limit_bytes: int | None = None,
        path: DataPath | None = None,
    ) -> RunRecord:
        """Queue a run of a pipeline that was validated (`pipeline` is its name). Returns its record.

        `sockets` maps aliases (or socket URIs) to absolute folders. `memory_limit_bytes` can make the share
        of its stages smaller than a worker's share, never larger. Raises `ExecutorClosed` and `QueueFull`.
        """
        with self._lock:
            if self._closing:
                raise ExecutorClosed("the engine is stopping")
            free = self.settings.max_stage_workers - len(self._active)
            if free <= 0 and len(self._queue) >= self.settings.max_queued_runs:
                raise QueueFull("too many runs are waiting")
            run_id = self._new_run_id()
            share = self.settings.share_for(memory_limit_bytes)
            record = RunRecord(
                run_id=run_id, pipeline=pipeline, created_at=_now(), memory_limit_bytes=share, path=path
            )
            run = _Run(record, pipeline_yaml, dict(sockets), share)
            self.store.add(record.model_copy(deep=True), pipeline_yaml)
            self._live[run_id] = run
            self._queue.append(run)
            # Its place in the queue, or None if it starts at once (there is a free slot).
            position = len(self._queue) if free <= 0 else None
            self._emit("run.queued", {"run_id": run_id, "pipeline": pipeline, "position": position})
            self._dispatch()
            return record.model_copy(deep=True)

    def cancel(self, run_id: str) -> RunRecord:
        """Cancel a run: at once if it is queued, else as the module docs say (it ends a moment later).

        Raises `RunNotFound` or `RunEnded`. Returns the record as it is now.
        """
        with self._lock:
            run = self._live.get(run_id)
            if run is None:
                if self.store.get(run_id) is None:
                    raise RunNotFound(run_id)
                raise RunEnded(run_id)
            if run in self._queue:
                self._queue.remove(run)
                self._end(run, _Ended("cancelled"))
                return run.record.model_copy(deep=True)
            run.cancel_requested = True
            worker = run.worker
            record = run.record.model_copy(deep=True)
        if worker is not None:
            self._interrupt(worker)
        return record

    def get(self, run_id: str) -> RunRecord | None:
        return self.store.get(run_id)

    def recent(
        self,
        limit: int,
        *,
        before: str | None = None,
        pipeline: str | None = None,
        state: str | None = None,
    ) -> list[RunSummary]:
        """The runs, newest first (`RunStore.recent`). Raises `UnknownCursor` for an unknown `before`."""
        return self.store.recent(limit, before=before, pipeline=pipeline, state=state)

    def counts(self) -> dict[str, int]:
        """How many runs are active and queued, and how many workers run a job or wait idle."""
        with self._lock:
            return {
                "runs_active": len(self._active),
                "runs_queued": len(self._queue),
                "workers_running": sum(run.worker is not None for run in self._active.values()),
                "workers_idle": int(self._idle is not None),
            }

    def shutdown(self, timeout: float | None = None) -> None:
        """Cancel every run, end every worker and wait for them (the engine stops). Can be called again."""
        with self._lock:
            self._closing = True
            for run in list(self._queue):
                self._queue.remove(run)
                self._end(run, _Ended("cancelled"))
            active = list(self._active.values())
            workers = []
            for run in active:
                run.cancel_requested = True
                workers.append(run.worker)
            idle, self._idle = self._idle, None
            self._changed.notify_all()
        for worker in workers:
            if worker is not None:
                self._interrupt(worker)
        wait = (
            timeout
            if timeout is not None
            else self.settings.cancel_grace_s + self.settings.stage_exit_timeout_s + 5.0
        )
        deadline = time.monotonic() + wait
        for run in active:
            if run.thread is not None:
                run.thread.join(max(0.0, deadline - time.monotonic()))
        if idle is not None:
            idle.finish(self.settings.cancel_grace_s)
        # Workers that are being ended in the background (a warm one started while the engine began to stop,
        # say): wait for them, so their folders are deleted by this engine and not left for the next one.
        with self._lock:
            reapers = list(self._reapers)
        deadline = time.monotonic() + self.settings.stage_exit_timeout_s + 5.0
        for reaper in reapers:
            reaper.join(max(0.0, deadline - time.monotonic()))
        if self._housekeeper is not None:
            self._housekeeper.join(5.0)

    # --- the queue ------------------------------------------------------------------------------------------

    def _new_run_id(self) -> str:
        while True:
            run_id = f"r{secrets.token_hex(4)}"
            if run_id not in self._live and self.store.get(run_id) is None:
                return run_id

    def _dispatch(self) -> None:
        """Start queued runs while there is room (the lock is held)."""
        while self._queue and len(self._active) < self.settings.max_stage_workers and not self._closing:
            run = self._queue.popleft()
            self._active[run.run_id] = run
            run.thread = threading.Thread(target=self._drive, args=(run,), name="safetwin-run", daemon=True)
            run.thread.start()

    def _drive(self, run: _Run) -> None:
        """The thread of an active run."""
        try:
            self._execute(run)
        except _Ended as ended:
            self._end(run, ended)
        except Exception as err:  # a bug of the engine: the message could quote anything, so only the type
            _log.error("a run failed in the engine with %s", type(err).__name__)
            internal = _Ended("failed", "InternalError", "the engine failed while it ran this run")
            worker = run.worker
            if worker is not None:
                internal.exit_reason = exit_code(self._let_go(run, worker, kill=True))
            self._close_stage(run, internal)
            self._end(run, internal)
        else:
            self._end(run, _Ended("succeeded"))
        finally:
            with self._lock:
                self._active.pop(run.run_id, None)
                self._dispatch()
                self._changed.notify_all()

    def _end(self, run: _Run, ended: _Ended) -> None:
        """Record how the run ended and say it."""
        with self._lock:
            record = run.record
            record.state = ended.state
            record.finished_at = _now()
            record.error_class, record.error = ended.error_class, ended.error
            self._live.pop(run.run_id, None)
            self._save(run, quiet=True)
            base: dict[str, Any] = {"run_id": run.run_id, "pipeline": record.pipeline}
            if ended.state == "succeeded":
                self._emit("run.finished", {**base, "state": "succeeded", **self._totals_data(record)})
            elif ended.state == "failed":
                self._emit(
                    "run.failed",
                    {**base, "stage": ended.stage, "error_class": ended.error_class, "error": ended.error},
                )
            else:
                self._emit("run.cancelled", {**base, "stage": ended.stage})

    @staticmethod
    def _totals_data(record: RunRecord) -> dict[str, Any]:
        return {"totals": record.totals.model_dump()}

    # --- one run --------------------------------------------------------------------------------------------

    def _execute(self, run: _Run) -> None:
        with self._lock:
            run.started_at = datetime.now(UTC)
            run.record.state = "running"
            run.record.started_at = utc_iso(run.started_at)
            self._save(run)
            self._emit("run.started", {"run_id": run.run_id, "pipeline": run.record.pipeline})
        worker, start, waited = self._acquire(run)
        plan, worker, start = self._plan(run, worker, start)
        with self._lock:
            run.record.stages = [
                StageRecord(
                    index=stage.index,
                    node_ids=stage.node_ids,
                    operators=stage.operators,
                    path=stage.path,
                    output=stage.sink.dataset_dir,
                )
                for stage in plan.stages
            ]
            self._save(run)
        committed: dict[str, list[FileOut]] = {}
        for stage in plan.stages:
            if stage.index > 0:
                worker, start, waited = self._acquire(run)
            with self._lock:
                run.stages_left = len(plan.stages) - stage.index - 1
                self._changed.notify_all()
            if run.stages_left:
                self._ensure_idle(time.monotonic() + self.settings.warm_worker_s)  # for the next stage
            self._run_stage(run, worker, stage, start, waited, committed)

    def _acquire(
        self, run: _Run, *, cold: bool = False
    ) -> tuple[WorkerProcess, Literal["warm", "cold"], float]:
        """A worker that is ready, for the next job of `run`: the warm one (unless `cold`), or a new one. How
        it was started, and how long the run waited for it. A warm worker that has died is replaced."""
        started = time.monotonic()
        with self._lock:
            if run.cancel_requested:
                raise _Ended("cancelled")
            worker = None if cold else self._take_idle()
        start: Literal["warm", "cold"] = "warm"
        if worker is None:
            start = "cold"
            try:
                worker = self._spawn()
            except (OSError, TmpFolderError) as err:
                reason = (
                    os.strerror(err.errno) if isinstance(err, OSError) and err.errno else type(err).__name__
                )
                raise _Ended(
                    "failed", "WorkerStartFailed", f"the stage worker could not start ({reason})"
                ) from None
        with self._lock:
            run.worker = worker
            cancelled = run.cancel_requested
        if cancelled:
            self._interrupt(worker)
        try:
            worker.wait_ready(self.settings.worker_start_timeout_s)
        except WorkerStopped:
            if start == "warm" and not run.cancel_requested:  # it died while it waited: start another
                self._let_go(run, worker)
                return self._acquire(run, cold=True)
            raise self._stopped(run, worker) from None
        except TimeoutError:
            self._let_go(run, worker, kill=True)
            raise _Ended(
                "failed",
                "WorkerStartTimeout",
                f"the stage worker did not start within {self.settings.worker_start_timeout_s:g} s",
            ) from None
        except ProtocolError:
            self._let_go(run, worker, kill=True)
            raise _Ended("failed", "ProtocolError", PROTOCOL_BROKEN) from None
        return worker, start, time.monotonic() - started

    def _plan(
        self, run: _Run, worker: WorkerProcess, start: Literal["warm", "cold"]
    ) -> tuple[PlanDone, WorkerProcess, Literal["warm", "cold"]]:
        job = PlanJob(**self._job_fields(run))
        worker, start = self._deliver(run, worker, start, job)
        answer = self._converse(run, worker, job)
        if isinstance(answer, PlanDone):
            return answer, worker, start
        exit = self._let_go(run, worker, kill=not isinstance(answer, Failed))
        if run.cancel_requested:
            raise _Ended("cancelled")
        if isinstance(answer, Failed):
            raise _Ended("failed", answer.error_class, answer.message, exit_reason=exit_code(exit))
        raise _Ended("failed", "ProtocolError", PROTOCOL_BROKEN, exit_reason=exit_code(exit))

    def _job_fields(self, run: _Run) -> dict[str, Any]:
        assert run.started_at is not None
        return {
            "job_id": f"j{secrets.token_hex(4)}",
            "pipeline_yaml": run.pipeline_yaml,
            "sockets": run.sockets,
            "run_id": run.run_id,
            "started_at": run.started_at,
            "path": run.record.path,
            "memory_limit_bytes": run.share,
        }

    def _run_stage(
        self,
        run: _Run,
        worker: WorkerProcess,
        planned: PlannedStageOut,
        start: Literal["warm", "cold"],
        waited: float,
        committed: dict[str, list[FileOut]],
    ) -> None:
        stage = run.record.stages[planned.index]
        sink = planned.sink
        existed = os.path.lexists(sink.file)  # then the file is not this stage's, whatever happens
        with self._lock:
            run.stage, run.stage_existed = planned, existed
        job = StageJob(**self._job_fields(run), stage_index=planned.index, committed=committed)
        try:
            worker, start = self._deliver(run, worker, start, job)
        except _Ended as ended:
            self._close_stage(run, ended)
            raise
        with self._lock:
            stage.state = "running"
            stage.started_at = _now()
            stage.worker_id, stage.worker_pid = worker.worker_id, worker.pid
            stage.worker_start, stage.worker_wait_s = start, round(waited, 3)
            self._save(run)
            self._emit(
                "stage.started",
                {
                    "run_id": run.run_id,
                    "stage": stage.index,
                    "node_ids": stage.node_ids,
                    "path": stage.path,
                    "attempt": stage.attempt,
                    "worker_id": worker.worker_id,
                    "worker_pid": worker.pid,
                    "worker_start": start,
                    "worker_wait_s": stage.worker_wait_s,
                },
            )
        try:
            answer = self._stage_answer(run, worker, job)
        except _Ended as ended:
            self._let_go(run, worker)  # the process is gone after this: nothing writes to the sink any more
            self._close_stage(run, ended)
            raise
        exit = self._let_go(run, worker)
        committed[planned.node_ids[-1]] = answer.files
        with self._lock:
            run.stage = None
            stage.state = "succeeded"
            stage.finished_at = _now()
            stage.duration_s = answer.duration_s
            stage.rows_per_node = dict(answer.rows_per_node)
            stage.files = [FileRecord(path=f.path, bytes=f.bytes, sha256=f.sha256) for f in answer.files]
            stage.bytes_written = sum(f.bytes for f in answer.files)
            stage.manifest = answer.manifest
            stage.manifest_bytes, stage.manifest_sha256 = answer.manifest_bytes, answer.manifest_sha256
            stage.exit_reason = exit_code(exit)
            totals = run.record.totals
            totals.rows += answer.rows_per_node.get(planned.node_ids[-1], 0)
            totals.bytes += stage.bytes_written
            totals.files += len(answer.files)
            self._save(run)
            self._emit("stage.finished", self._stage_data(run, stage))
        if self.settings.warm_worker_s > 0:
            self._ensure_idle(time.monotonic() + self.settings.warm_worker_s)

    def _stage_answer(self, run: _Run, worker: WorkerProcess, job: StageJob) -> StageDone:
        """What the worker did with the stage, or `_Ended`: for an error of the stage, a worker that ended,
        a cancel, and an error of the engine itself (so the stage is cleaned up whatever went wrong)."""
        try:
            answer = self._converse(run, worker, job)
        except _Ended:
            raise
        except Exception as err:  # a bug of the engine: the message could quote anything, so only the type
            _log.error("a stage failed in the engine with %s", type(err).__name__)
            exit = self._let_go(run, worker, kill=True)
            raise _Ended(
                "failed",
                "InternalError",
                "the engine failed while it ran this stage",
                exit_reason=exit_code(exit),
            ) from None
        if isinstance(answer, StageDone):
            return answer
        exit = self._let_go(run, worker, kill=not isinstance(answer, Failed))
        if run.cancel_requested:
            raise _Ended("cancelled")
        if isinstance(answer, Failed):
            raise _Ended("failed", answer.error_class, answer.message, exit_reason=exit_code(exit))
        raise _Ended("failed", "ProtocolError", PROTOCOL_BROKEN, exit_reason=exit_code(exit))

    def _close_stage(self, run: _Run, ended: _Ended) -> None:
        """The stage that ran has ended early (its worker is gone): remove what it may have left in its sink,
        record it as failed or cancelled and say so. Nothing if no stage runs."""
        with self._lock:
            planned, run.stage = run.stage, None
        if planned is None:
            return
        sink = planned.sink
        remove_stage_leftovers(
            Path(sink.file), Path(sink.dataset_dir), sink.relative, run.run_id, existed=run.stage_existed
        )
        ended.stage = planned.index
        with self._lock:
            stage = run.record.stages[planned.index]
            stage.state = "cancelled" if ended.state == "cancelled" else "failed"
            stage.finished_at = _now()
            stage.error_class, stage.error = ended.error_class, ended.error
            stage.exit_reason = ended.exit_reason
            self._save(run, quiet=True)
            self._emit("stage.finished", self._stage_data(run, stage))

    def _deliver(
        self, run: _Run, worker: WorkerProcess, start: Literal["warm", "cold"], job: PlanJob | StageJob
    ) -> tuple[WorkerProcess, Literal["warm", "cold"]]:
        """Send `job`. A warm worker that died before it got the job (it never started it) is replaced by a
        cold start, and the job goes there. The worker that has the job, and how it was started."""
        try:
            worker.send(job)
            return worker, start
        except WorkerStopped:
            if start != "warm" or run.cancel_requested:
                raise self._stopped(run, worker) from None
        except ProtocolError:
            exit = self._let_go(run, worker, kill=True)
            raise _Ended("failed", "ProtocolError", JOB_TOO_LARGE, exit_reason=exit_code(exit)) from None
        self._let_go(run, worker)
        worker, start, _ = self._acquire(run, cold=True)
        return self._deliver(run, worker, start, job)

    @staticmethod
    def _stage_data(run: _Run, stage: StageRecord) -> dict[str, Any]:
        return {
            "run_id": run.run_id,
            "stage": stage.index,
            "state": stage.state,
            "path": stage.path,
            "rows_per_node": stage.rows_per_node,
            "bytes_written": stage.bytes_written,
            "files": [file.model_dump() for file in stage.files],
            "duration_s": stage.duration_s,
            "error_class": stage.error_class,
            "error": stage.error,
        }

    def _converse(
        self, run: _Run, worker: WorkerProcess, job: PlanJob | StageJob
    ) -> PlanDone | StageDone | Failed:
        """Forward the worker's progress on `job` (sent already) until its answer. A worker that ends, or
        breaks the protocol, ends the run here (`_Ended`), once its process is gone."""
        try:
            while True:
                message = worker.receive()
                if (
                    isinstance(message, Progress)
                    and isinstance(job, StageJob)
                    and message.job_id == job.job_id
                ):
                    self._progress(run, message)
                elif isinstance(message, PlanDone | StageDone | Failed) and message.job_id == job.job_id:
                    return message
                else:
                    raise ProtocolError("an answer to another job")
        except WorkerStopped:
            raise self._stopped(run, worker) from None
        except ProtocolError:
            exit = self._let_go(run, worker, kill=True)
            if run.cancel_requested:
                raise _Ended("cancelled") from None
            raise _Ended("failed", "ProtocolError", PROTOCOL_BROKEN, exit_reason=exit_code(exit)) from None

    def _progress(self, run: _Run, message: Progress) -> None:
        with self._lock:
            if not 0 <= message.stage < len(run.record.stages):
                return
            stage = run.record.stages[message.stage]
            stage.rows_per_node = dict(message.rows_per_node)
            stage.bytes_written = message.bytes_written
            stage.memory_bytes = message.memory_bytes
            if message.memory_bytes is not None:
                stage.memory_peak_bytes = max(stage.memory_peak_bytes or 0, message.memory_bytes)
            now = time.monotonic()
            if now - run.last_progress.get(message.stage, -1e9) < self.settings.progress_interval_s:
                return
            run.last_progress[message.stage] = now
            self._save(run)
            self._emit(
                "stage.progress",
                {
                    "run_id": run.run_id,
                    "stage": message.stage,
                    "path": message.path,
                    "rows_per_node": stage.rows_per_node,
                    "bytes_written": message.bytes_written,
                    "memory_bytes": message.memory_bytes,
                    "elapsed_s": message.elapsed_s,
                },
            )

    def _stopped(self, run: _Run, worker: WorkerProcess) -> _Ended:
        """The worker ended before it answered: once its process is gone, how the run ends."""
        exit = self._let_go(run, worker)
        if run.cancel_requested:
            return _Ended("cancelled")
        return _Ended("failed", "WorkerStopped", f"{WORKER_STOPPED} ({exit})", exit_reason=exit_code(exit))

    def _let_go(self, run: _Run, worker: WorkerProcess, *, kill: bool = False) -> str:
        """The run is done with `worker`: wait until its process is gone (SIGKILL after the grace period, or
        at once with `kill`) and its folder is deleted. How it ended."""
        if kill:
            worker.kill()
        timeout = self.settings.cancel_grace_s if run.cancel_requested else self.settings.stage_exit_timeout_s
        exit = worker.finish(timeout)
        with self._lock:
            if run.worker is worker:
                run.worker = None
        return exit

    def _interrupt(self, worker: WorkerProcess) -> None:
        """SIGINT now, SIGKILL after the grace period if the worker is still there."""
        worker.interrupt()
        timer = threading.Timer(self.settings.cancel_grace_s, worker.kill)
        timer.daemon = True
        timer.start()

    # --- the workers ----------------------------------------------------------------------------------------

    def _spawn(self) -> WorkerProcess:
        """Start a worker. Never with the lock held: starting a process takes a while."""
        return WorkerProcess(
            self.home, command=self._command, env=self._env, grace_s=self.settings.cancel_grace_s
        )

    def _take_idle(self) -> WorkerProcess | None:
        """The idle worker, if there is one that still runs (the lock is held)."""
        idle, self._idle = self._idle, None
        if idle is None:
            return None
        if not idle.alive:
            self._finish_later(idle)
            return None
        return idle

    def _ensure_idle(self, until: float) -> None:
        """Keep an idle worker until `until` (a `time.monotonic()`), starting one if there is none."""
        with self._lock:
            if self._closing:
                return
            self._idle_until = max(self._idle_until, until)
            self._changed.notify_all()
            if self._idle is not None or self._spawning_idle:
                return
            self._spawning_idle = True
        worker: WorkerProcess | None = None
        try:
            worker = self._spawn()  # outside the lock
        except (OSError, TmpFolderError) as err:  # the next stage starts one itself
            _log.warning("a warm stage worker could not be started (%s)", type(err).__name__)
        with self._lock:
            self._spawning_idle = False
            if worker is not None and self._idle is None and not self._closing:
                self._idle, worker = worker, None
            self._changed.notify_all()
        if worker is not None:  # the engine is stopping, or another one is idle already
            self._finish_later(worker)

    def _finish_later(self, worker: WorkerProcess) -> None:
        """End `worker` on a thread of its own; `shutdown` waits for these threads."""
        reaper = threading.Thread(
            target=worker.finish,
            args=(self.settings.stage_exit_timeout_s,),
            name="safetwin-reap",
            daemon=True,
        )
        with (
            self._lock
        ):  # started under the lock (a thread, not a process), so shutdown never joins it unstarted
            self._reapers = [thread for thread in self._reapers if thread.is_alive()]
            self._reapers.append(reaper)
            reaper.start()

    def _housekeep(self) -> None:
        """Let the idle worker go once its time is up, unless a run has stages to go; reap it if it died."""
        while True:
            expired: WorkerProcess | None = None
            with self._changed:
                if self._closing:
                    return
                idle = self._idle
                if idle is not None:
                    waiting = any(run.stages_left for run in self._active.values())
                    if not idle.alive or (time.monotonic() >= self._idle_until and not waiting):
                        self._idle, expired = None, idle
                if expired is None:
                    # Until the idle time is up, or (after it, while a run still has stages to go) until
                    # something changes; every 5 s at most while a worker is idle, to see whether it died.
                    remaining = self._idle_until - time.monotonic()
                    timeout = None if self._idle is None else (min(remaining, 5.0) if remaining > 0 else 5.0)
                    self._changed.wait(timeout)
            if expired is not None:
                expired.finish(self.settings.stage_exit_timeout_s)

    # --- state ----------------------------------------------------------------------------------------------

    def _save(self, run: _Run, *, quiet: bool = False) -> None:
        """Hand a copy of the run's record to the store. `quiet` (when a run or stage ends): a store that
        fails is logged, by the type of its error, and the run ends anyway."""
        try:
            self.store.save(run.record.model_copy(deep=True))
        except Exception as err:
            if not quiet:
                raise
            _log.error("the state of a run could not be saved (%s)", type(err).__name__)

    def _emit(self, kind: str, data: dict[str, Any]) -> None:
        sink = self._on_event
        if sink is None:
            return
        try:
            sink(kind, data)
        except Exception as err:  # an event that can't be sent must not stop a run
            _log.warning("an event could not be sent (%s)", type(err).__name__)
