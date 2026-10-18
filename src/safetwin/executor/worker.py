"""The stage worker: a process that plans a run and runs one of its stages (docs/internals.md).

Run as `python -m safetwin.executor.worker` (or `<engine> worker` in the frozen build) by the control
plane, never by hand. It speaks the protocol of `protocol.py` on its stdin and stdout, and the control plane
keeps its stderr in a bounded buffer that nobody reads.

1. It keeps the stdout it was given for the protocol alone, and points file descriptor 1 at stderr, so a
   library that prints can't put a stray line into the protocol.
2. It imports the data plane (Polars, PyArrow, DuckDB) and says `ready`: a worker that is started before it is
   needed (the warm worker) hides the import time.
3. It answers `plan` jobs (validate the pipeline and plan every stage, `run.plan_pipeline`) and runs one
   `stage` job (`run.run_pipeline_stage`), sending `progress` while the stage runs, and then it ends. A stage
   that fails leaves no file behind (the data plane cleans up), and the error crosses the pipe as its class
   name and, for the engine's own safe errors only, its message.
4. SIGINT cancels the job: the stage cleans up and the worker ends with status 130.
5. If its stdin closes while a job is queued or running (the control plane is gone: killed, crashed), it
   cancels the job the same way (SIGINT to itself) and starts no other. Python handles a signal only when
   the main thread is back in Python code, and a long call into Polars or DuckDB can delay that for the rest
   of the stage, so the thread that read the end of stdin waits `cancel grace` seconds (the engine's
   `CANCEL_GRACE_S`, passed in `GRACE_ENV`) and then ends the process with `os._exit`, which works whatever
   the main thread is doing. Before that exit it removes what the stage may have left in its sink, as the
   control plane would have (`dataplane.cleanup.remove_stage_leftovers`: the temporary files, and the data
   file of this run if no manifest lists it), once the stage is planned. When it is idle, it just ends.

**The commit lock.** That cleanup runs on the stdin thread while the main thread may still be working, so it
could meet the stage's commit: `remove_uncommitted` looks for a manifest that lists the data file and then
deletes the file, and a manifest written in between would list a file that is gone. So the data plane holds
`_COMMIT_LOCK` from just before it renames the data file into place until the manifest is written
(`RunContext.commit_lock`), and the cleanup takes the same lock first, waiting at most one more grace period,
and never lets go of it before `os._exit`. Then either the commit has finished (the manifest lists the file,
which is kept), or it never happens (the main thread waits for the lock until the process ends, or gives up
on SIGINT and cleans up after itself the same way). Every step
of a commit runs on the main thread: the batch path's reader thread only reads, the fused path's Polars
threads only write bytes into the temporary file, and DuckDB's threads only produce batches; the rename
(`CommitWriter.commit`) and the manifest (`finish_stage`) are called by the thread that runs the stage.

The forced cleanup is best effort. If the commit has not finished within that second grace period (a drive
that hangs in fsync, say), the worker ends without cleaning: a temporary file, or a data file that no
manifest lists, may be left in the sink. What the lock guarantees is that a manifest never lists a file that
the cleanup deleted. So a worker never outlives its engine by more than two grace periods, and by one when
no commit is under way.

Lines on stdin are read with a bound (`MAX_MESSAGE_BYTES`): a longer one ends the worker (exit status 2).

For tests only, `TEST_HOOK_ENV` makes the worker misbehave on purpose: `ignore_sigint` (it ignores SIGINT,
as a worker stuck in native code would), `print` (it prints to stdout and writes to file descriptor 1
during the stage, as a library might), `hold_commit` (it ignores SIGINT and stops for one and a half grace
periods between the rename of the data file and the manifest) or `hold_commit_sigint` (the same stop, but
SIGINT is honoured). Any other value is ignored.

It ends with `os._exit`, after the last message is flushed: everything it wrote is committed by then, and
the threads of the libraries are not waited for.
"""

import hashlib
import logging
import os
import queue
import signal
import sys
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, NoReturn

from .process import GRACE_ENV
from .protocol import (
    MAX_ERROR_MESSAGE,
    Failed,
    FileOut,
    PlanDone,
    PlanJob,
    PlannedStageOut,
    Progress,
    ProtocolError,
    Ready,
    SinkOut,
    StageDone,
    StageJob,
    _Message,
    decode_job,
    encode,
    safe_class,
)
from .settings import CANCEL_GRACE_S, MAX_MESSAGE_BYTES

if TYPE_CHECKING:
    from safetwin.dataplane.manifest import Manifest

EXIT_CANCELLED = 130
EXIT_PROTOCOL = 2
TEST_HOOK_ENV = "SAFETWIN_TEST_WORKER_HOOK"
HOLD_COMMIT_GRACES = 1.5  # how long `hold_commit` stops in the commit, in grace periods

# Held by the main thread from the rename of a stage's data file until its manifest is written; the cleanup
# before a forced exit takes it and keeps it (see the module docs).
_COMMIT_LOCK = threading.Lock()


def _grace_s() -> float:
    """The grace period after the end of stdin, from `GRACE_ENV` (0.1 to 60 s), else `CANCEL_GRACE_S`."""
    try:
        configured = float(os.environ.get(GRACE_ENV, ""))
    except ValueError:
        return CANCEL_GRACE_S
    return configured if 0.1 <= configured <= 60.0 else CANCEL_GRACE_S


def _hook() -> str:
    return os.environ.get(TEST_HOOK_ENV, "")


class _Channel:
    """The protocol's stdout: whole messages, from any thread, one at a time."""

    def __init__(self, out: BinaryIO) -> None:
        self._out = out
        self._lock = threading.Lock()

    def send(self, message: _Message) -> None:
        data = encode(message)
        with self._lock:
            self._out.write(data)
            self._out.flush()


class _Jobs:
    """Reads jobs from stdin on a thread of its own, so that the end of stdin is seen even while a stage runs.

    `next` gives the next job, or None once stdin has ended; `done` says the job it gave has been answered. A
    job counts as active from the moment it is read until `done`, so the end of stdin cancels a job that is
    queued as well as one that runs. A line that is not a job, or is too long, ends the worker.
    """

    def __init__(self) -> None:
        self._queue: queue.Queue[PlanJob | StageJob | None] = queue.Queue()
        self._lock = threading.Lock()
        self._active = 0  # jobs read and not answered yet
        self.ended = threading.Event()  # stdin has ended
        self._thread = threading.Thread(target=self._read, name="safetwin-worker-stdin", daemon=True)
        self._thread.start()

    def next(self) -> PlanJob | StageJob | None:
        return self._queue.get()

    def done(self) -> None:
        with self._lock:
            self._active -= 1

    def _read(self) -> None:
        stdin = sys.stdin.buffer
        try:
            while line := stdin.readline(MAX_MESSAGE_BYTES + 1):
                if len(line) > MAX_MESSAGE_BYTES:
                    _exit(EXIT_PROTOCOL)
                try:
                    job = decode_job(line)
                except ProtocolError:
                    _exit(EXIT_PROTOCOL)
                with self._lock:
                    self._active += 1
                self._queue.put(job)
        except (OSError, ValueError):
            pass
        with self._lock:
            self.ended.set()
            active = self._active > 0
        self._queue.put(None)
        if active:  # the control plane is gone while a job is queued or runs: cancel it, and end for sure
            os.kill(os.getpid(), signal.SIGINT)
            time.sleep(_grace_s())
            _remove_leftovers()
            _exit(EXIT_CANCELLED)


@dataclass(frozen=True)
class _Sink:
    """The sink of the stage that runs, as the worker needs it to clean up after itself."""

    file: Path
    dataset_dir: Path
    relative: str
    run_id: str
    existed: bool


_current: list[_Sink] = []  # the sink of the stage that runs, once it is planned (at most one)


def _remove_leftovers() -> None:
    """Before a forced exit: what the stage may have left in its sink. Never raises; nothing if no stage is
    planned yet, and nothing if a commit under way does not finish within a grace period.

    The commit lock is taken first and never let go of (the process ends next), so no commit can start or
    finish after the cleanup has looked at the manifests.
    """
    with suppress(Exception):
        if not _current or not _COMMIT_LOCK.acquire(timeout=_grace_s()):
            return
        from safetwin.dataplane.cleanup import remove_stage_leftovers

        sink = _current[0]
        remove_stage_leftovers(sink.file, sink.dataset_dir, sink.relative, sink.run_id, existed=sink.existed)


def main() -> NoReturn:
    """The worker, as the module docs say. Never returns."""
    protocol = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    channel = _Channel(protocol)
    started = time.perf_counter()
    try:
        from safetwin.dataplane import run as _run  # noqa: F401  (Polars, PyArrow and DuckDB, now)

        if _hook() in ("ignore_sigint", "hold_commit"):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        channel.send(Ready(pid=os.getpid(), import_s=round(time.perf_counter() - started, 3)))
        jobs = _Jobs()
        while (job := jobs.next()) is not None:
            if jobs.ended.is_set():  # the control plane is gone: start nothing
                _exit(EXIT_CANCELLED)
            if isinstance(job, PlanJob):
                answer: _Message = _plan(job)
                jobs.done()
                channel.send(answer)
                continue
            answer = _stage(job, channel)
            jobs.done()  # answered: the end of stdin no longer cancels anything
            channel.send(answer)
            break
    except KeyboardInterrupt:
        _exit(EXIT_CANCELLED)
    except BrokenPipeError:  # the control plane is gone
        _exit(EXIT_CANCELLED)
    _exit(0)


def _exit(status: int) -> NoReturn:
    with suppress(OSError, ValueError):
        sys.stderr.flush()
    os._exit(status)


def _plan(job: PlanJob) -> PlanDone | Failed:
    from safetwin.dataplane.run import plan_pipeline
    from safetwin.spec import SpecError, load_pipeline_text

    try:
        pipeline = load_pipeline_text(job.pipeline_yaml)
        plan = plan_pipeline(
            pipeline,
            _folders(job),
            run_id=job.run_id,
            started_at=job.started_at,
            force_path=job.path,
            memory_limit_bytes=job.memory_limit_bytes,
        )
    except SpecError:
        return _failed(job, "PipelineInvalid", INVALID)
    except Exception as err:
        return _failure(job, err)
    return PlanDone(
        job_id=job.job_id,
        pipeline=pipeline.metadata.name,
        stages=[
            PlannedStageOut(
                index=planned.stage.index,
                node_ids=[node.id for node in planned.stage.nodes],
                operators=[node.operator for node in planned.stage.nodes],
                path=planned.path,
                input_from=planned.stage.input_from,
                sink=SinkOut(
                    file=str(planned.sink.file),
                    dataset_dir=str(planned.sink.dataset_dir),
                    relative=planned.sink.relative,
                ),
            )
            for planned in plan.stages
        ],
    )


def _stage(job: StageJob, channel: _Channel) -> StageDone | Failed:
    from safetwin.dataplane.run import PlannedStage, run_pipeline_stage
    from safetwin.dataplane.runtime import ProgressEvent
    from safetwin.dataplane.writer import FileCommit
    from safetwin.spec import SpecError, load_pipeline_text

    def progress(event: ProgressEvent) -> None:
        if _hook() == "print":
            _print_noise()
        channel.send(
            Progress(
                job_id=job.job_id,
                stage=event.stage,
                path=event.path,
                rows_per_node=event.rows_per_node,
                bytes_written=event.bytes_written,
                memory_bytes=event.memory_bytes,
                elapsed_s=round(event.elapsed_s, 3),
            )
        )

    def planned(stage: PlannedStage) -> None:
        sink = stage.sink
        existed = os.path.lexists(sink.file)
        _current[:] = [_Sink(sink.file, sink.dataset_dir, sink.relative, job.run_id, existed)]

    committed = {
        node_id: [FileCommit(Path(file.path), file.bytes, file.sha256) for file in files]
        for node_id, files in job.committed.items()
    }
    if _hook() == "print":
        _print_noise()
    if _hook() in ("hold_commit", "hold_commit_sigint"):
        _hold_before_manifest()
    try:
        pipeline = load_pipeline_text(job.pipeline_yaml)
        result = run_pipeline_stage(
            pipeline,
            _folders(job),
            job.stage_index,
            run_id=job.run_id,
            started_at=job.started_at,
            committed=committed,
            memory_limit_bytes=job.memory_limit_bytes,
            on_event=progress,
            force_path=job.path,
            on_planned=planned,
            commit_lock=_COMMIT_LOCK,
        )
    except SpecError:
        return _failed(job, "PipelineInvalid", INVALID)
    except Exception as err:
        return _failure(job, err)
    manifest_bytes, manifest_sha256 = _checksum(result.manifest)
    return StageDone(
        job_id=job.job_id,
        rows_per_node=result.rows_per_node,
        files=[FileOut(path=str(file.path), bytes=file.bytes, sha256=file.sha256) for file in result.files],
        duration_s=round(result.duration_s, 3),
        path=result.path,
        manifest=str(result.manifest),
        manifest_bytes=manifest_bytes,
        manifest_sha256=manifest_sha256,
    )


def _checksum(manifest: Path) -> tuple[int | None, str | None]:
    """The size and SHA-256 of the manifest the stage wrote (a few KB of metadata), or None if it can't be
    read back."""
    try:
        data = manifest.read_bytes()
    except OSError:
        return None, None
    return len(data), hashlib.sha256(data).hexdigest()


def _hold_before_manifest() -> None:
    """For tests (`TEST_HOOK_ENV=hold_commit` or `hold_commit_sigint`): stop for `HOLD_COMMIT_GRACES` grace
    periods after the data file is renamed into place and before the manifest is written."""
    from safetwin.dataplane import runtime
    from safetwin.dataplane.manifest import write_manifest

    def held(dataset_dir: Path, manifest: "Manifest") -> Path:
        time.sleep(_grace_s() * HOLD_COMMIT_GRACES)
        return write_manifest(dataset_dir, manifest)

    runtime.write_manifest = held  # type: ignore[attr-defined]  # what finish_stage calls


INVALID = "the pipeline is not valid: check it with safetwin validate"


def _print_noise() -> None:
    """For tests (`TEST_HOOK_ENV=print`): what a library that prints would do, by both routes."""
    print("a library printed this line", flush=True)
    os.write(1, b"and this one, to file descriptor 1\n")


def _folders(job: PlanJob | StageJob) -> dict[str, Path]:
    return {alias: Path(folder) for alias, folder in job.sockets.items()}


def _failed(job: PlanJob | StageJob, error_class: str, message: str | None) -> Failed:
    return Failed(job_id=job.job_id, error_class=error_class, message=message)


def _failure(job: PlanJob | StageJob, err: Exception) -> Failed:
    """The safe form of an error: its class, and the engine's own message for the classes that have one.

    The messages of Polars, PyArrow and DuckDB can quote a row, so for any other error only the class goes.
    An OSError says the reason of the system and the file, not its free text, as `safetwin run-local` does.
    """
    from safetwin.dataplane.operators import ConfigError, Unsupported
    from safetwin.dataplane.run import PipelineInvalid
    from safetwin.dataplane.spill import SpillError
    from safetwin.dataplane.watchdog import MemoryLimitReached

    name = type(err).__name__
    if not name.isidentifier() or len(name) > 100:
        name = "Error"
    if isinstance(err, PipelineInvalid):
        return _failed(job, "PipelineInvalid", INVALID)
    if isinstance(err, OSError):
        reason = os.strerror(err.errno) if err.errno else name
        message = f"{reason}: {err.filename}" if err.filename else reason
        return _failed(job, name if safe_class(name) else "OSError", message)
    if isinstance(err, ConfigError | Unsupported | SpillError | MemoryLimitReached) and safe_class(name):
        return _failed(job, name, str(err)[:MAX_ERROR_MESSAGE])
    return _failed(job, name, None)


if __name__ == "__main__":
    main()
