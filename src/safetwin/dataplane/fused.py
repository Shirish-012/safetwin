"""The fused path: the whole stage is one lazy Polars query, run in pieces (docs/internals.md).

The source, every step, and the write to Parquet are one query, so Polars reads, transforms and writes in
parallel, in pieces, and keeps memory bounded. After every node the query passes through a small counter
(`map_batches`), which gives the row count of each node, and it writes into a `CommitWriter`, which counts
the bytes for progress, computes the SHA-256 and publishes the file only when the query has finished.

The counters are also where the query obeys the memory watchdog of the stage (`watchdog.py`): the first one
waits while it is paused (the sources stop, and what is past it drains to the sink), and every one raises when
it stops the stage, which ends the query with `MemoryLimitReached`.

The counters switch Polars' pushdowns off for themselves. With them on, Polars would move a filter that
comes after a counter to before it (into the CSV reader, even), and the counter would count the rows after
the filter: the funnel would be wrong.
"""

import time
from collections.abc import Callable
from contextlib import ExitStack
from typing import IO, cast

import polars as pl

from .operators import PARQUET_COMPRESSION, PARQUET_COMPRESSION_LEVEL, scan_csv, scan_parquet_files
from .planner import Stage
from .runtime import (
    RunContext,
    StageMeter,
    StagePlan,
    StageResult,
    committed_files,
    finish_stage,
    hold_commit_lock,
    polars_steps,
    prepare_stage,
    stage_watchdog,
)
from .watchdog import watching
from .writer import CommitWriter


def run_fused_stage(stage: Stage, ctx: RunContext) -> StageResult:
    """Run the stage as one Polars query, commit its file, then write its manifest."""
    started = time.perf_counter()
    plan = prepare_stage(stage, ctx)
    steps = polars_steps(plan)
    with watching(stage_watchdog(stage, ctx)) as watchdog:
        meter = StageMeter(
            stage.index, "fused", [node.id for node in stage.nodes[:-1]], ctx.on_event, watchdog=watchdog
        )
        frame = read_input(plan, ctx)
        first = True  # the first counter is at the source's side: only it waits while the stage is paused
        if plan.source is not None or plan.parquet_source is not None:  # the rows that were read
            frame, first = counted(frame, meter.counter(stage.nodes[0].id, source=True)), False
        for node, step in steps:
            frame, first = counted(step(frame), meter.counter(node.id, source=first)), False
        columns = frame.collect_schema().names()
        with ExitStack() as committing, CommitWriter(plan.sink.file, on_progress=meter.set_bytes) as writer:
            target = cast("IO[bytes]", writer)  # a binary file object, as far as Polars is concerned
            if plan.sink_format == "csv":
                frame.sink_csv(target)
            else:
                frame.sink_parquet(
                    target, compression=PARQUET_COMPRESSION, compression_level=PARQUET_COMPRESSION_LEVEL
                )
            hold_commit_lock(ctx, committing)  # until the manifest is written
            commit = writer.commit()
            return finish_stage(plan, ctx, meter, commit, "fused", started, columns=columns)


def counted(frame: pl.LazyFrame, count: Callable[[pl.DataFrame], pl.DataFrame]) -> pl.LazyFrame:
    """`frame` with a counter after it, in the same query (see the module docs for the flags)."""
    return frame.map_batches(
        count, streamable=True, predicate_pushdown=False, projection_pushdown=False, slice_pushdown=False
    )


def read_input(plan: StagePlan, ctx: RunContext) -> pl.LazyFrame:
    """The lazy frame that starts the stage: the CSV files, or what the sink before this stage committed."""
    if plan.source is not None:
        return scan_csv(plan.files, plan.source)
    if plan.parquet_source is not None:
        return scan_parquet_files(plan.files)
    return pl.scan_parquet(committed_files(plan, ctx), glob=False, hive_partitioning=False)
