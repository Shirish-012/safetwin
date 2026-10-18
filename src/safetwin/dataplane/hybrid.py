"""The hybrid path: a stage with a step that DuckDB runs (docs/internals.md).

`transform.sql` and `transform.sort` need all of their input, so DuckDB runs them, on a connection that has
a memory limit and never spills (`spill.py`). The rest of the stage stays where it is fastest. The stage is a
chain of streams of Arrow batches, and nothing in it is collected in Python:

    Polars query ──▶ DuckDB step ──▶ Polars steps ──▶ DuckDB step ──▶ ... ──▶ Parquet writer

- The nodes before the first DuckDB step are one lazy Polars query, the one the fused path would run,
  with a counter after every node. Its batches are the table `input` of the DuckDB step.
- Every DuckDB step has a cursor of its own (a result that is read as it comes can't share a connection with
  the query that reads it). It runs its SQL, and the result is a stream again, counted as it passes.
- The Polars steps after a DuckDB step are applied to one batch at a time, as the batch path does: the steps
  are row by row, so a row comes out the same whichever rows are in its batch.
- The writer pulls from the end of the chain, so a slow disk slows everything before it down, and the rows
  of a node are counted exactly (a node counts what leaves it, before the node after it sees it).

DuckDB reads `input` once. A query that reads it twice (a self-join, a subquery over the same table) is found
in the plan before any data moves, and `input` is then a table that DuckDB makes of the stream (in memory: it
has to fit in the limit). The stream is given to DuckDB as a PyArrow `Scanner`, which can be scanned once:
a scan that nothing planned for is an error ("already scanned"), and not, as with a plain reader, an empty
table that gives a wrong answer without a word.

What goes wrong in DuckDB is not shown: its messages can quote data. The error of a step upstream of DuckDB (a
Polars error in the query before it, say) is raised as it was, as it is on the other paths, and what DuckDB
says about having been given a failing stream is dropped. Running out of memory is turned into a message that
says what to do (`spill.out_of_memory`).

The memory watchdog of the stage (`watchdog.py`) pauses the Polars query before DuckDB at its first counter,
as on the fused path, and what is past that counter goes on into DuckDB. (A stage that reads what an earlier
stage wrote and has no Polars step before DuckDB has no such counter: it is not paused, only stopped.) When
the watchdog stops the stage it interrupts DuckDB (`interrupt()` on the connection and on every cursor), and
the counters raise; the stage then fails with `MemoryLimitReached`. Before the streams are closed the watchdog
is closed, which lets go of a counter that waits: a stream whose query waits in a counter could not be closed.

A DuckDB query that is still running when it is given up (the writer failed, say) must be ended on purpose.
Measured with DuckDB 1.5.6 and PyArrow 25: if it is only dropped, the process can no longer end, because the
thread pool of Arrow waits at exit for work that is never finished. Every stream of the chain has a `close`,
and `run_hybrid_stage` calls them all, last stream first, however the stage ends: the stream that DuckDB reads
is told to stop and is unregistered, and the result of the query is let go of. `test_hybrid_exit.py` runs
stages that fail or give up halfway in a process of their own, and sees that it ends.
"""

import json
import threading
import time
from collections.abc import Generator, Iterator
from contextlib import ExitStack, closing, contextmanager, suppress
from typing import Any

import duckdb
import polars as pl
import pyarrow as pa
import pyarrow.dataset as pa_dataset
import pyarrow.parquet as pq

from safetwin.spec.models import Node

from .batch import BATCH_ROWS, ROW_GROUP_ROWS, RowGroups
from .fused import counted, read_input
from .operators import (
    PARQUET_COMPRESSION,
    PARQUET_COMPRESSION_LEVEL,
    ConfigError,
    SqlStep,
    Step,
    Transform,
    no_such_columns,
)
from .planner import Stage
from .runtime import (
    RunContext,
    StageMeter,
    StagePlan,
    StageResult,
    finish_stage,
    hold_commit_lock,
    prepare_stage,
    refuse_fused_only,
    stage_watchdog,
)
from .spill import SpillSettings, duckdb_session, out_of_memory
from .watchdog import Watchdog, watching
from .writer import CommitWriter, FileCommit

# The stream as DuckDB has it. `input` is a view of it, or a table made from it.
STREAM = "_safetwin_input_stream"

PolarsSteps = list[tuple[Node, Transform]]
Link = tuple[Node, SqlStep, PolarsSteps]  # a DuckDB step, and the Polars steps that follow it


class Stream:
    """Arrow batches on their way from one step to the next: the Arrow `schema` of every batch, and the
    batches, which are read once. `close` gives the stream up before its end; it can be called at any time,
    and more than once.
    """

    def __init__(self, schema: pa.Schema, batches: Generator[pa.RecordBatch, None, None]) -> None:
        self.schema = schema
        self._batches = batches

    def __iter__(self) -> Iterator[pa.RecordBatch]:
        return self._batches

    def close(self) -> None:
        self._batches.close()


def run_hybrid_stage(stage: Stage, ctx: RunContext) -> StageResult:
    """Run the stage, with DuckDB for its SQL steps, commit its file, then write its manifest."""
    started = time.perf_counter()
    plan = prepare_stage(stage, ctx)
    refuse_fused_only(plan, "hybrid")
    head, links = _split(plan.steps)
    settings = _spill_of(ctx) if links else None
    # The commit lock (if the run has one) is taken just before the data file is renamed into place, and
    # `committing` lets go of it once the manifest is written.
    with watching(stage_watchdog(stage, ctx)) as watchdog, ExitStack() as committing:
        meter = StageMeter(
            stage.index, "hybrid", [node.id for node in stage.nodes[:-1]], ctx.on_event, watchdog=watchdog
        )
        stream = _polars_stream(plan, ctx, meter, head)
        if settings is None:  # asked for on a stage with nothing for DuckDB: the types are Arrow's, as ever
            commit = _write(plan, ctx, meter, _polars_batches(stream, [], meter), committing)
        else:
            commit = _run_links(plan, ctx, meter, watchdog, settings, stream, links, committing)
        return finish_stage(plan, ctx, meter, commit, "hybrid", started)


def _run_links(
    plan: StagePlan,
    ctx: RunContext,
    meter: StageMeter,
    watchdog: Watchdog,
    settings: SpillSettings,
    stream: "Stream",
    links: list[Link],
    committing: ExitStack,
) -> FileCommit:
    """Run the DuckDB steps (each with the Polars steps after it) over `stream`, and write the result."""
    # What is entered first is left last: the streams are closed (the last first), then the cursors, and then
    # the connection.
    with duckdb_session(settings) as connection, ExitStack() as cleanup:
        try:
            watchdog.on_stop(connection.interrupt)
            cleanup.callback(stream.close)
            for node, step, tail in links:
                cursor = cleanup.enter_context(closing(connection.cursor()))
                watchdog.on_stop(cursor.interrupt)
                duck = DuckStep(cursor, node, step, stream, meter)
                # Before the query starts: a query that fails while it starts has to be ended too.
                cleanup.callback(duck.close)
                stream = duck.start()
                if tail:
                    stream = _polars_batches(stream, tail, meter)
                    cleanup.callback(stream.close)
            return _write(plan, ctx, meter, stream, committing)
        except BaseException as err:
            watchdog.close()  # lets go of a counter that waits, so that the streams can be closed
            if isinstance(err, duckdb.OutOfMemoryException):
                names = ", ".join(f"{node.id} ({node.operator})" for node, _, _ in links)
                raise out_of_memory(settings, f"the DuckDB steps of this stage ({names})") from None
            raise
        finally:
            watchdog.close()  # no interrupt after this: the cursors and the connection are closed next


def _split(steps: list[tuple[Node, Step]]) -> tuple[PolarsSteps, list[Link]]:
    """The Polars steps before the first DuckDB step, then each DuckDB step with the Polars steps after it."""
    head: PolarsSteps = []
    links: list[Link] = []
    for node, step in steps:
        if isinstance(step, SqlStep):
            links.append((node, step, []))
        elif links:
            links[-1][2].append((node, step))
        else:
            head.append((node, step))
    return head, links


def _spill_of(ctx: RunContext) -> SpillSettings:
    if ctx.spill is None:
        raise ValueError("a stage with a step for DuckDB needs ctx.spill: a run sets it")
    return ctx.spill


def _polars_stream(plan: StagePlan, ctx: RunContext, meter: StageMeter, steps: PolarsSteps) -> Stream:
    """The nodes of the stage up to the first DuckDB step as a stream of Arrow batches.

    It is the query of the fused path with a counter after every node. The query starts when the first batch
    is asked for, runs in Polars' engine for large data, and stops when the stream is closed or dropped. The
    batches are taken from Polars one by one in Python (and not through Arrow's C stream), so that an error of
    the query is the error that Polars raised. `collect_batches` is marked unstable by Polars:
    `pyproject.toml` pins Polars below 2, and the tests of this path would notice a change in it.
    """
    frame = read_input(plan, ctx)
    first = True  # the first counter is at the source's side: only it waits while the stage is paused
    if plan.source is not None:  # the rows that were read
        frame, first = counted(frame, meter.counter(plan.stage.nodes[0].id, source=True)), False
    for node, step in steps:
        frame, first = counted(step(frame), meter.counter(node.id, source=first)), False
    schema = pl.DataFrame(schema=frame.collect_schema()).to_arrow().schema

    def batches() -> Generator[pa.RecordBatch, None, None]:
        for chunk in frame.collect_batches(lazy=True, chunk_size=BATCH_ROWS, engine="streaming"):
            yield from chunk.to_arrow().to_batches()

    return Stream(schema, batches())


class Feed:
    """The rows that flow into a DuckDB step, for DuckDB to read once.

    `scanner()` is what is registered with DuckDB. `failure` keeps what went wrong in the stream, as it was
    raised there, for `_unwrapping`. `stop()` ends the stream at the next batch (DuckDB then finds the end of
    its table, and its query can finish) and waits for the batch that a thread of DuckDB is taking just now:
    when it returns, nothing of DuckDB is inside the source any more, and the source can be closed.
    """

    def __init__(self, source: Stream, label: str) -> None:
        self._source = source
        self.label = label
        self.failure: BaseException | None = None
        self._stopped = False
        self._pulling = threading.Lock()

    def scanner(self) -> Any:
        reader = pa.RecordBatchReader.from_batches(self._source.schema, self._batches())
        return pa_dataset.Scanner.from_batches(reader)  # one scan only: a second one is an error

    def stop(self) -> None:
        self._stopped = True
        with self._pulling:  # waits for the batch that is being taken
            pass

    def _batches(self) -> Iterator[pa.RecordBatch]:
        source = iter(self._source)
        try:
            while True:
                with self._pulling:
                    if self._stopped:
                        return
                    try:
                        batch = next(source)
                    except StopIteration:
                        return
                yield batch
        except GeneratorExit:  # the scan was given up: nothing went wrong
            raise
        except BaseException as err:  # kept for `_unwrapping`, and raised on
            self.failure = err
            raise


@contextmanager
def _unwrapping(feed: Feed) -> Iterator[None]:
    """What DuckDB raises because of the stream it reads becomes what it really was.

    DuckDB turns the exception of a stream into an error of its own, whose message quotes it and whose class
    says nothing about what happened. The original is raised in its place, so that the error of a Polars step
    before a DuckDB step is the one that the other paths would raise. A second scan of the stream is an error
    of the query, and is said so. (Only the text of what DuckDB said is looked at, and none of it is shown.)
    """
    try:
        yield
    except duckdb.Error as err:
        if feed.failure is not None:
            raise feed.failure from None
        if "was already scanned" in str(err):
            raise ConfigError(
                f"{feed.label}: the query reads the table input a second time, which can't be done (the "
                "rows of input come as a stream). Change the query so that it reads input once"
            ) from None
        raise


class DuckStep:
    """The query of a DuckDB step, running over the stream before it: make it, `start` it, and `close` it."""

    def __init__(
        self, cursor: duckdb.DuckDBPyConnection, node: Node, step: SqlStep, source: Stream, meter: StageMeter
    ) -> None:
        self._cursor = cursor
        self._node = node
        self._step = step
        self._source = source
        self._meter = meter
        self._feed = Feed(source, f"{node.id} ({node.operator})")
        self._result: Any = None
        self._rows: Generator[pa.RecordBatch, None, None] | None = None

    def start(self) -> Stream:
        """Run the SQL of the step over the source (the table `input`) and give its rows as a stream.

        A column that the step needs and the source does not have is an error before anything is run. For a
        query that is blocking (a sort, an aggregate) the whole source is read in here.
        """
        names: list[str] = self._source.schema.names
        missing = [name for name in self._step.needs if name not in names]
        if missing:
            raise no_such_columns(self._node, missing, names)
        with _unwrapping(self._feed):
            self._cursor.register(STREAM, self._feed.scanner())
            self._cursor.execute(f"CREATE TEMP VIEW input AS SELECT * FROM {STREAM}")
            if _scans(self._cursor, self._step.sql) > 1:  # `input` is needed more than once: make a table
                self._cursor.execute("DROP VIEW input")
                self._cursor.execute(f"CREATE TEMP TABLE input AS SELECT * FROM {STREAM}")
            self._result = self._cursor.execute(self._step.sql).to_arrow_reader(BATCH_ROWS)
        self._rows = self._counted()
        return Stream(self._result.schema, self._rows)

    def _counted(self) -> Generator[pa.RecordBatch, None, None]:
        with _unwrapping(self._feed):
            for batch in self._result:
                self._meter.check(wait=False)
                self._meter.add_rows(self._node.id, batch.num_rows)
                yield batch

    def close(self) -> None:
        """Give the query up: end the stream that it reads, let go of its result, unregister the stream."""
        self._feed.stop()
        rows, self._rows, self._result = self._rows, None, None
        try:
            if rows is not None:
                rows.close()
        finally:
            with suppress(duckdb.Error):
                self._cursor.unregister(STREAM)


def _scans(cursor: duckdb.DuckDBPyConnection, sql: str) -> int:
    """How many times DuckDB will read the stream for `sql`: the ARROW_SCANs in its plan, found without data.

    If the query can't be planned this says 1, and running it gives the error. If the plan is not in a form
    that is known, it says 2: the stream is then made into a table, which is right whatever the plan was.
    """
    try:
        plan = json.loads(cursor.execute(f"EXPLAIN (FORMAT JSON) {sql}").fetchall()[0][1])
    except duckdb.Error:
        return 1
    except (ValueError, IndexError, TypeError):
        return 2
    return sum(_count_scans(node) for node in plan) if isinstance(plan, list) else 2


def _count_scans(node: Any) -> int:
    if not isinstance(node, dict):
        return 0
    own = 1 if node.get("name") == "ARROW_SCAN" else 0
    return own + sum(_count_scans(child) for child in node.get("children", []))


def _polars_batches(stream: Stream, steps: PolarsSteps, meter: StageMeter) -> Stream:
    """The Polars steps applied to each batch of `stream`, counting the rows that leave each node."""
    empty = pl.DataFrame(stream.schema.empty_table())  # the schema of the result: the steps run on no rows
    for _, step in steps:
        empty = step(empty.lazy()).collect()

    def batches() -> Generator[pa.RecordBatch, None, None]:
        for batch in stream:
            frame = pl.DataFrame(batch)
            for node, step in steps:
                frame = step(frame.lazy()).collect()
                meter.add_rows(node.id, frame.height)
            yield from frame.to_arrow().to_batches()

    return Stream(empty.to_arrow().schema, batches())


def _write(
    plan: StagePlan, ctx: RunContext, meter: StageMeter, stream: Stream, committing: ExitStack
) -> FileCommit:
    """Write the batches of `stream` to the sink's file, in row groups, and commit it. The commit lock is
    taken (on `committing`) just before the rename."""
    with CommitWriter(plan.sink.file, on_progress=meter.set_bytes) as out:
        with pq.ParquetWriter(
            out, stream.schema, compression=PARQUET_COMPRESSION, compression_level=PARQUET_COMPRESSION_LEVEL
        ) as writer:
            groups = RowGroups(writer, ROW_GROUP_ROWS)
            for batch in stream:
                groups.add(pa.Table.from_batches([batch]))
            groups.finish()
        hold_commit_lock(ctx, committing)
        return out.commit()
