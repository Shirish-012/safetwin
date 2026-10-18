"""Run a batch pipeline on this machine, with folders as its sockets.

The stages run one after the other, each one fused, batch by batch, or hybrid (with DuckDB for its SQL steps)
(docs/internals.md).

`run_pipeline_local` runs every stage in this process (`safetwin run-local`). The engine runs each stage in a
stage worker of its own instead (`safetwin.executor`): the worker calls `plan_pipeline` to plan the run, and
`run_pipeline_stage` to run its one stage, with what the earlier stages committed.
"""

import os
import re
import secrets
import time
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from safetwin.spec import Pipeline, Problem, validate_pipeline

from .batch import run_batch_stage
from .cleanup import remove_temporary_files, remove_uncommitted
from .fused import run_fused_stage
from .hybrid import run_hybrid_stage
from .manifest import RUN_ID_PATTERN
from .operators import ConfigError, LocalSocketResolver, SinkPlan, is_duckdb_operator, plan_sink
from .planner import DataPath, Stage, choose_path, split_stages
from .runtime import ProgressEvent, RunContext, StageResult, prepare_stage
from .spill import SpillSettings, default_memory_limit
from .watchdog import Sampler
from .writer import FileCommit

_RUNNERS: dict[DataPath, Callable[[Stage, RunContext], StageResult]] = {
    "fused": run_fused_stage,
    "batch": run_batch_stage,
    "hybrid": run_hybrid_stage,
}


class PipelineInvalid(Exception):
    """The pipeline has errors, so nothing was run. `problems` are all the problems found, warnings too."""

    def __init__(self, problems: list[Problem]) -> None:
        self.problems = problems
        super().__init__("; ".join(f"[{p.code}] {p.message}" for p in problems if p.severity == "error"))


@dataclass(frozen=True)
class RunResult:
    """What a run did: the id of the run and the result of each stage, in the order the stages ran."""

    run_id: str
    stages: list[StageResult]
    duration_s: float


@dataclass(frozen=True)
class PlannedStage:
    """A stage of a planned run: its nodes, the way it runs and where its sink writes."""

    stage: Stage
    path: DataPath
    sink: SinkPlan


@dataclass(frozen=True)
class RunPlan:
    """A run whose every stage is planned, and the context the stages share."""

    ctx: RunContext
    stages: list[PlannedStage]


def run_pipeline_local(
    pipeline: Pipeline,
    sockets: Mapping[str, Path],
    *,
    run_id: str | None = None,
    on_event: Callable[[ProgressEvent], None] | None = None,
    force_path: DataPath | None = None,
    memory_limit_bytes: int | None = None,
    memory_sampler: Sampler | None = None,
    subkeys: object = None,
) -> RunResult:
    """Run a batch-mode pipeline. `sockets` says which folder each socket is (by alias or by URI).

    The pipeline is validated first: if it has errors this raises `PipelineInvalid` and nothing runs. Then
    every stage is planned (configs, sockets, paths) before the first one starts, so a mistake in the last
    stage does not show up after the first has written its files. `ConfigError` says what is wrong with a
    config or a path, and `Unsupported` (a `NotImplementedError`) what the pipeline uses that can't run yet
    (a pipeline that is not a linear chain).

    `on_event` gets `ProgressEvent`s, at most four a second. `force_path` makes every stage run fused, batch
    by batch or hybrid instead of the way the planner would choose. A file that exists is never replaced: a
    run with the id of an earlier run fails with `FileExistsError`. A stage that fails leaves no file behind,
    not even a temporary one, and no manifest; the stages that finished before it keep theirs.

    Every stage may use `memory_limit_bytes` of memory (a quarter of the physical memory if that is None): a
    watchdog samples the memory of the process (with `memory_sampler`, for tests, if one is given), pauses
    the stage's sources at 90% of it and stops the stage with `MemoryLimitReached` at 100% (`watchdog.py`).
    A stage with a step that DuckDB runs (`transform.sql`, `transform.sort`) is hybrid. DuckDB gets 80% of
    the limit and writes no temporary file: a step that needs more raises `OutOfMemory` (`spill.py`).
    """
    plan = plan_pipeline(
        pipeline,
        sockets,
        run_id=run_id,
        on_event=on_event,
        force_path=force_path,
        memory_limit_bytes=memory_limit_bytes,
        memory_sampler=memory_sampler,
        subkeys=subkeys,
    )
    started = time.perf_counter()
    results = [run_planned_stage(plan, planned) for planned in plan.stages]
    return RunResult(plan.ctx.run_id, results, time.perf_counter() - started)


def run_pipeline_stage(
    pipeline: Pipeline,
    sockets: Mapping[str, Path],
    stage_index: int,
    *,
    run_id: str,
    started_at: datetime,
    committed: Mapping[str, list[FileCommit]],
    memory_limit_bytes: int,
    on_event: Callable[[ProgressEvent], None] | None = None,
    force_path: DataPath | None = None,
    memory_sampler: Sampler | None = None,
    on_planned: Callable[[PlannedStage], object] | None = None,
    commit_lock: AbstractContextManager[object] | None = None,
) -> StageResult:
    """Run one stage of a run, as a stage worker does (`safetwin.executor.worker`).

    The run is planned as `run_pipeline_local` plans it (and raises what it raises), with the run's id and
    its start time (`started_at`, UTC, which fills the placeholders of the sinks: every stage of a run must
    get the same). `committed` holds what the sinks of the earlier stages wrote, by node id. The stage may
    use `memory_limit_bytes`: its share of the engine's memory. When the stage fails, it leaves what
    `run_pipeline_local` leaves: nothing. `on_planned` is called with the planned stage before it starts (the
    worker keeps its sink, to clean up if it has to end the process itself). `commit_lock` is held from just
    before the data file is renamed into place until the manifest is written (`RunContext.commit_lock`).
    """
    plan = plan_pipeline(
        pipeline,
        sockets,
        run_id=run_id,
        started_at=started_at,
        on_event=on_event,
        force_path=force_path,
        memory_limit_bytes=memory_limit_bytes,
        memory_sampler=memory_sampler,
    )
    plan.ctx.commit_lock = commit_lock
    if not 0 <= stage_index < len(plan.stages):
        raise ConfigError(f"the run has {len(plan.stages)} stage(s): there is no stage {stage_index + 1}")
    plan.ctx.committed.update({node_id: list(files) for node_id, files in committed.items()})
    if on_planned is not None:
        on_planned(plan.stages[stage_index])
    return run_planned_stage(plan, plan.stages[stage_index])


def plan_pipeline(
    pipeline: Pipeline,
    sockets: Mapping[str, Path],
    *,
    run_id: str | None = None,
    started_at: datetime | None = None,
    on_event: Callable[[ProgressEvent], None] | None = None,
    force_path: DataPath | None = None,
    memory_limit_bytes: int | None = None,
    memory_sampler: Sampler | None = None,
    subkeys: object = None,
    subset_filters: dict[str, Any] | None = None,
) -> RunPlan:
    """Validate a pipeline and plan every stage of a run of it; nothing is written.

    What `run_pipeline_local` checks before its first stage, and raises: `PipelineInvalid`, `ConfigError`,
    `Unsupported`. `started_at` is the start of the run (now if None). `subkeys` are the masking subkeys
    (`safetwin.masking.hmacs.Subkeys`) that `transform.mask` steps use, and `subset_filters` the row filters
    of a subset, by table; both stay in memory.
    """
    problems = validate_pipeline(pipeline)
    if any(problem.severity == "error" for problem in problems):
        raise PipelineInvalid(problems)
    if run_id is None:
        run_id = f"r{secrets.token_hex(4)}"
    elif not re.fullmatch(RUN_ID_PATTERN, run_id):
        raise ConfigError(
            "the run id must be 1 to 64 letters, digits, '-' or '_', and start with a letter or digit"
        )
    if memory_limit_bytes is not None and memory_limit_bytes < 1:
        raise ConfigError("the memory limit must be at least one byte")
    limit = default_memory_limit() if memory_limit_bytes is None else memory_limit_bytes
    ctx = RunContext(
        pipeline=pipeline,
        resolver=LocalSocketResolver(sockets, pipeline.spec.sockets),
        run_id=run_id,
        started_at=datetime.now(UTC) if started_at is None else started_at,
        on_event=on_event,
        memory_limit_bytes=limit,  # one stage runs at a time in a process, so its share is all of it
        memory_sampler=memory_sampler,
        subkeys=subkeys,
        subset_filters=dict(subset_filters or {}),
    )
    stages = split_stages(pipeline)
    paths = [choose_path(stage, force_path=force_path) for stage in stages]
    for stage in stages:
        prepare_stage(stage, ctx)
    if any(is_duckdb_operator(node.operator) for stage in stages for node in stage.nodes):
        ctx.spill = SpillSettings(limit)
    sinks = [plan_sink(stage.nodes[-1], ctx.resolver, run_id, ctx.started_at) for stage in stages]
    return RunPlan(
        ctx, [PlannedStage(stage, path, sink) for stage, path, sink in zip(stages, paths, sinks, strict=True)]
    )


def run_planned_stage(plan: RunPlan, planned: PlannedStage) -> StageResult:
    """Run one planned stage, and record what its sink committed for the stages after it.

    If it fails, what it may have left is removed (`cleanup.py`) before the error goes on.
    """
    ctx, sink = plan.ctx, planned.sink
    existed = os.path.lexists(sink.file)  # then it is not this stage's, whatever happens (FileExistsError)
    try:
        result = _RUNNERS[planned.path](planned.stage, ctx)
    except BaseException:
        _remove_temporaries(sink, ctx.run_id)
        if not existed:
            _remove_uncommitted(sink, ctx.run_id)
        raise
    ctx.committed[planned.stage.nodes[-1].id] = result.files
    return result


def _remove_temporaries(sink: SinkPlan, run_id: str) -> None:
    """After a stage failed: the temporary files of its data file and of its manifest (`cleanup.py`)."""
    remove_temporary_files(sink.file, sink.dataset_dir, run_id)


def _remove_uncommitted(sink: SinkPlan, run_id: str) -> None:
    """After a stage failed: its data file, if no manifest of this run lists it (`cleanup.py`)."""
    remove_uncommitted(sink.file, sink.dataset_dir, sink.relative, run_id)
