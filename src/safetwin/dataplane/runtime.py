"""What the two ways of running a stage have in common: its plan, its counters and its commit.

Both paths plan the stage the same way, count the rows that leave each node the same way, report progress
the same way, and finish the same way: check the committed file against the counts, then write the manifest.
"""

import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import polars as pl
import pyarrow.parquet as pq

from safetwin.spec import Pipeline
from safetwin.spec.models import Node

from .manifest import Column, FileEntry, Lineage, Manifest, Totals, write_manifest
from .operators import (
    FUSED_ONLY,
    PARQUET_COMPRESSION,
    CsvSource,
    LocalSocketResolver,
    ParquetSource,
    SinkPlan,
    SqlStep,
    Step,
    Transform,
    Unsupported,
    build_step,
    csv_columns,
    csv_files,
    operator_key,
    parquet_columns,
    parse_config,
    plan_sink,
    socket_of,
)
from .planner import DataPath, Stage
from .spill import SpillSettings, default_memory_limit
from .watchdog import Sampler, Watchdog
from .writer import FileCommit

EVENT_INTERVAL_S = 0.25  # progress is reported at most four times a second


@dataclass(frozen=True)
class ProgressEvent:
    """How far a stage has got: the bytes written so far and the rows that have left each node so far.

    `memory_bytes` is the stage's memory at the last sample of its watchdog (what the process has grown by
    since the stage started), or None when nothing measures it.
    """

    stage: int
    path: DataPath
    bytes_written: int
    rows_per_node: dict[str, int]
    elapsed_s: float
    memory_bytes: int | None = None


@dataclass(frozen=True)
class StageResult:
    """What a stage did.

    `rows_per_node` has the rows that left each node, in the order of the nodes: the source reads rows, each
    step passes on some of them, and the sink's number is the rows in its file. `manifest` is the path of the
    manifest that was written for the files.
    """

    rows_per_node: dict[str, int]
    files: list[FileCommit]
    duration_s: float
    path: DataPath
    manifest: Path


@dataclass
class RunContext:
    """One run of a pipeline on this machine. `committed` holds what each sink wrote so far, by node id.

    `memory_limit_bytes` is each stage's share of memory: one stage runs at a time, so it is the run's memory
    limit. The watchdog of a stage (`watchdog.py`) samples the memory with `memory_sampler` (the memory of
    the process if it is None; tests give one of their own). `spill` says what DuckDB may use (some of the
    share: it never spills). It is set when the run has a step that DuckDB runs, and is not needed otherwise.

    `commit_lock`, when there is one, is held from just before the data file of a stage is renamed into
    place until its manifest is written (`hold_commit_lock`). A stage worker gives one, so that a thread of
    its own that cleans up before a forced exit never runs in the middle of a commit (`executor.worker`).
    `run_pipeline_local` gives none.
    """

    pipeline: Pipeline
    resolver: LocalSocketResolver
    run_id: str
    started_at: datetime  # UTC: the time of the {yyyy}, {MM} and {dd} placeholders
    on_event: Callable[[ProgressEvent], None] | None = None
    committed: dict[str, list[FileCommit]] = field(default_factory=dict)
    spill: SpillSettings | None = None
    memory_limit_bytes: int = field(default_factory=default_memory_limit)
    memory_sampler: Sampler | None = None
    commit_lock: AbstractContextManager[object] | None = None
    # The masking subkeys (`safetwin.masking.hmacs.Subkeys`), in memory only, for `transform.mask`; and what
    # its steps counted (values set to null and why), by node id. Never written anywhere but the report.
    subkeys: Any = None
    mask_stats: dict[str, Any] = field(default_factory=dict)
    # The row filter of each table of a subset (`safetwin.masking.subset`, Polars expressions that hold data
    # values), by table name: in memory only, like the subkeys.
    subset_filters: dict[str, Any] = field(default_factory=dict)


def hold_commit_lock(ctx: RunContext, stack: ExitStack) -> None:
    """Take the run's commit lock, if it has one, until `stack` closes.

    Call it just before the data file is renamed into place (`CommitWriter.commit`), with a stack that
    closes after `finish_stage` has written the manifest: so the rename and the manifest happen together,
    under the lock, or not at all.
    """
    if ctx.commit_lock is not None:
        stack.enter_context(ctx.commit_lock)


class StageMeter:
    """Counts the rows that leave each node and the bytes written, and reports progress.

    Counting works from any thread. `on_event` is called at most once per `interval` seconds, the first time
    one interval after the start (a stage that is done sooner reports nothing), by whichever thread adds the
    count that is due, and never by two at once.

    With a `watchdog`, `check` and the counters of `counter` obey it: they raise `MemoryLimitReached` once it
    has stopped the stage, and the counter at the source's side of a Polars query (`source=True`) waits while
    it is paused. Progress events then carry the stage's memory.
    """

    def __init__(
        self,
        stage: int,
        path: DataPath,
        node_ids: list[str],
        on_event: Callable[[ProgressEvent], None] | None,
        *,
        interval: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        watchdog: Watchdog | None = None,
    ) -> None:
        self._stage = stage
        self._watchdog = watchdog
        self._path: DataPath = path
        self._rows = dict.fromkeys(node_ids, 0)
        self._bytes = 0
        self._on_event = on_event
        self._interval = EVENT_INTERVAL_S if interval is None else interval
        self._clock = clock
        self._started = self._last = clock()
        self._lock = threading.Lock()

    @property
    def rows(self) -> dict[str, int]:
        with self._lock:
            return dict(self._rows)

    def add_rows(self, node_id: str, rows: int) -> None:
        with self._lock:
            self._rows[node_id] += rows
            self._report()

    def set_bytes(self, total: int) -> None:
        with self._lock:
            self._bytes = total
            self._report()

    def check(self, *, wait: bool = True) -> None:
        """Wait while the watchdog has paused the stage (unless `wait` is false); raise if it stopped it."""
        if self._watchdog is not None:
            self._watchdog.check(wait=wait)

    @property
    def paused(self) -> bool:
        """Whether the watchdog has paused the stage just now."""
        return self._watchdog is not None and self._watchdog.state == "paused"

    def counter(self, node_id: str, *, source: bool = False) -> Callable[[pl.DataFrame], pl.DataFrame]:
        """For `map_batches`: counts the rows of each frame that passes and hands the frame on unchanged.

        It is also where a Polars query obeys the watchdog: every counter raises when the stage is stopped,
        and the first counter of the query (`source`: the one after the source, or after the first step when
        the stage reads what an earlier stage wrote) waits while it is paused. That stops the sources, and
        what has passed it already goes on to the sink and leaves memory (backpressure, docs/internals.md).
        """

        def count(frame: pl.DataFrame) -> pl.DataFrame:
            self.check(wait=source)
            self.add_rows(node_id, frame.height)
            return frame

        return count

    def _report(self) -> None:  # the lock is held
        if self._on_event is None:
            return
        now = self._clock()
        if now - self._last < self._interval:
            return
        self._last = now
        memory = None if self._watchdog is None else self._watchdog.memory_bytes
        self._on_event(
            ProgressEvent(self._stage, self._path, self._bytes, dict(self._rows), now - self._started, memory)
        )


@dataclass(frozen=True)
class StagePlan:
    """A stage with its configs checked: what it reads, the step of each transform, and where it writes."""

    stage: Stage
    source: CsvSource | None  # the config of the source node, when the stage starts at a CSV source
    files: list[Path]  # the files of that source (CSV or Parquet)
    columns: list[str]  # the columns they all have
    steps: list[tuple[Node, Step]]  # a Polars step, or a `SqlStep` for DuckDB
    sink: SinkPlan
    inputs: list[str]  # URIs of what the stage reads, for the lineage of its manifest
    parquet_source: ParquetSource | None = None  # the config of the source node, for a Parquet source
    sink_format: str = "parquet"  # or "csv"


def refuse_fused_only(plan: StagePlan, path: DataPath) -> None:
    """The batch and hybrid paths can't run `source.parquet`, `sink.csv` or `transform.mask`: say so."""
    for node in plan.stage.nodes:
        if operator_key(node.operator) in FUSED_ONLY:
            raise Unsupported(f"{node.operator} runs on the fused path only, not the {path} path")


def prepare_stage(stage: Stage, ctx: RunContext) -> StagePlan:
    """Check the configs of a stage, find what it reads and plan where it writes. Nothing is written.

    Raises `ConfigError` for a config or a path that is wrong and `Unsupported` for an operator that can't run
    yet, before any data moves.
    """
    nodes = stage.nodes
    sink_node = nodes[-1]
    if operator_key(sink_node.operator) not in ("sink.parquet", "sink.csv"):
        raise Unsupported(f"{sink_node.operator} can't be run yet")
    source: CsvSource | None = None
    parquet_source: ParquetSource | None = None
    files: list[Path] = []
    columns: list[str] = []
    if stage.input_from is None:
        source_node = nodes[0]
        if operator_key(source_node.operator) == "source.parquet":
            parquet_source = parse_config(ParquetSource, source_node)
            files = csv_files(source_node, parquet_source, ctx.resolver)
            columns = parquet_columns(source_node, files)
            path = parquet_source.path
        elif operator_key(source_node.operator) == "source.csv":
            config = parse_config(CsvSource, source_node)
            source, files = config, csv_files(source_node, config, ctx.resolver)
            columns = csv_columns(source_node, config, files)
            path = config.path
        else:
            raise Unsupported(f"{source_node.operator} can't be run yet")
        inputs = [f"{ctx.resolver.uri(socket_of(source_node))}/{path}"]
        body = nodes[1:-1]
    else:
        upstream = next(node for node in ctx.pipeline.spec.nodes if node.id == stage.input_from)
        inputs = [plan_sink(upstream, ctx.resolver, ctx.run_id, ctx.started_at).uri]
        body = nodes[:-1]
    steps = [(node, build_step(node, ctx)) for node in body]
    sink = plan_sink(sink_node, ctx.resolver, ctx.run_id, ctx.started_at)
    sink_format = "csv" if operator_key(sink_node.operator) == "sink.csv" else "parquet"
    return StagePlan(stage, source, files, columns, steps, sink, inputs, parquet_source, sink_format)


def stage_watchdog(stage: Stage, ctx: RunContext) -> Watchdog:
    """The memory watchdog of a stage: its share is the run's memory limit. Start it with `watching`."""
    names = ", ".join(f"{node.id} ({node.operator})" for node in stage.nodes)
    return Watchdog(ctx.memory_limit_bytes, f"the stage of {names}", sampler=ctx.memory_sampler)


def polars_steps(plan: StagePlan) -> list[tuple[Node, Transform]]:
    """The steps of a stage that has none for DuckDB, for the paths that only run Polars steps.

    Raises `Unsupported` for a stage that has one: `transform.sql` and `transform.sort` need the hybrid path.
    """
    steps: list[tuple[Node, Transform]] = []
    for node, step in plan.steps:
        if isinstance(step, SqlStep):
            raise Unsupported(f"{node.operator} runs in DuckDB: only the hybrid path can run it")
        steps.append((node, step))
    return steps


def committed_files(plan: StagePlan, ctx: RunContext) -> list[Path]:
    """The files that the sink before the stage committed, for a stage that starts after a sink."""
    if plan.stage.input_from is None:
        raise ValueError("this stage starts at a source, not after a sink")
    return [file.path for file in ctx.committed[plan.stage.input_from]]


def finish_stage(
    plan: StagePlan,
    ctx: RunContext,
    meter: StageMeter,
    commit: FileCommit,
    path: DataPath,
    started: float,
    *,
    columns: list[str] | None = None,
) -> StageResult:
    """After the data file is committed: check it against the counts, then write the manifest.

    The manifest is the commit marker, so it comes last. If anything fails before it is in place the data
    file is removed again: no manifest lists it, so it is not part of any dataset, and a reader that looks
    at the folder instead of the manifest must not find it either.
    """
    sink_id = plan.stage.nodes[-1].id
    try:
        counted = meter.rows.get(plan.stage.nodes[-2].id) if len(plan.stage.nodes) > 1 else None
        if (
            plan.sink_format == "csv"
        ):  # the rows that reached the sink; CSV is text, so every column is a string
            rows = counted or 0
            schema = [Column(name=name, type="string") for name in columns or []]
            compression = "none"
        else:
            rows = pq.read_metadata(commit.path).num_rows  # the footer only: no data is read
            schema = [
                Column(name=field.name, type=_type_name(field.type)) for field in pq.read_schema(commit.path)
            ]
            compression = PARQUET_COMPRESSION
        if counted is not None and counted != rows:
            raise RuntimeError(f"{rows} rows were written but {counted} reached the sink")
        manifest = Manifest(
            dataset=plan.sink.dataset,
            run_id=ctx.run_id,
            pipeline=ctx.pipeline.metadata.name,
            committed_at=datetime.now(UTC).replace(microsecond=0),
            columns=schema,
            files=[
                FileEntry(
                    path=plan.sink.relative,
                    rows=rows,
                    bytes=commit.bytes,
                    sha256=commit.sha256,
                    compression=compression,
                )
            ],
            totals=Totals(rows=rows, bytes=commit.bytes),
            classification=_classification(plan),
            lineage=Lineage(inputs=plan.inputs, operators=[node.operator for node, _ in plan.steps]),
        )
        manifest_path = write_manifest(plan.sink.dataset_dir, manifest)
    except BaseException:
        commit.path.unlink(missing_ok=True)
        raise
    return StageResult(
        rows_per_node={**meter.rows, sink_id: rows},
        files=[commit],
        duration_s=time.perf_counter() - started,
        path=path,
        manifest=manifest_path,
    )


def _classification(plan: StagePlan) -> dict[str, str]:
    """The report class of each output column, from the stage's `transform.mask` step (empty without one)."""
    for node, _ in plan.steps:
        if operator_key(node.operator) == "transform.mask":
            from safetwin.masking.step import classification  # here: masking imports this module

            return classification(node)
    return {}


def _type_name(arrow_type: object) -> str:
    """An Arrow type as the manifest names it. Polars writes `large_string`, which is a string for readers."""
    return str(arrow_type).replace("large_", "")
