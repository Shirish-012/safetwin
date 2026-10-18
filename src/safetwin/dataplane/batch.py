"""The batch-by-batch path: Arrow batches flow through a bounded queue and through one node at a time.

For stages that cannot be one Polars query (nothing needs it yet, but custom Python steps would). A reader
thread feeds PyArrow's incremental CSV reader (or Parquet reader) into a queue that is bounded by the number
of batches and by their bytes, so a slow sink slows the reader down instead of piling data up. The main thread
takes a batch off the queue, applies every step to it with Polars (the very functions the fused path chains
into its query), counts the rows that leave each node, and hands the result to a PyArrow `ParquetWriter`
that collects batches into row groups of about a million rows. The writer is a `CommitWriter`.

The memory watchdog of the stage (`watchdog.py`) pauses the reader: while it is paused the reader waits before
it reads the next batch, and the writer drains the queue. The writer would only move those rows into the row
group it is collecting (up to a million rows), so when it finds the stage paused it writes the rows it holds
as a row group of their own: the file has the same rows in the same order, in more row groups. When the
watchdog stops the stage, the reader and the writer both raise `MemoryLimitReached`.
"""

import threading
import time
from collections import deque
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Final

import polars as pl
import pyarrow as pa
import pyarrow.csv as pacsv
import pyarrow.parquet as pq

from safetwin.spec.models import Node

from .operators import (
    PARQUET_COMPRESSION,
    PARQUET_COMPRESSION_LEVEL,
    CsvSource,
    Transform,
)
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
    refuse_fused_only,
    stage_watchdog,
)
from .watchdog import watching
from .writer import CommitWriter

BATCH_ROWS = 65_536  # a batch is at most this many rows...
BATCH_BYTES = 16 * 1024 * 1024  # ...and at most this many bytes of Arrow data
QUEUE_BATCHES = 4  # the queue holds at most this many batches...
QUEUE_BYTES = 64 * 1024 * 1024  # ...and at most this many bytes
ROW_GROUP_ROWS = 1_000_000
CSV_BLOCK_BYTES = 4 * 1024 * 1024  # how much CSV text PyArrow parses at a time
PAUSE_LOOK_S = 0.25  # a writer that waits for a batch looks this often whether the stage was paused


class _NotYet:
    """What `BatchQueue.get` gives when no batch came in time (None is the end of the stream).

    A value of its own and not an exception, so that it can't be mistaken for an error of the reader (a
    `TimeoutError`, which a network share or a socket can raise, say).
    """


NOT_YET: Final = _NotYet()


class BatchQueue:
    """A queue of Arrow batches with a limit on how many it holds and on how many bytes they add up to.

    `put` waits while the queue is full. A batch that is bigger than the byte limit is let in when the queue
    is empty, so it can never wait forever. `finish` ends the stream (with an error, if the producer failed,
    which `get` then raises), and `cancel` makes every `put` give up: a producer can't outlive its consumer.
    """

    def __init__(self, max_batches: int, max_bytes: int) -> None:
        self._max_batches = max_batches
        self._max_bytes = max_bytes
        self._items: deque[tuple[pa.RecordBatch, int]] = deque()
        self._bytes = 0
        self._finished = False
        self._cancelled = False
        self._error: BaseException | None = None
        self._changed = threading.Condition()

    def put(self, batch: pa.RecordBatch) -> bool:
        """Add a batch, waiting for room. Returns False if the queue was cancelled (the batch is dropped)."""
        size = batch.nbytes
        with self._changed:
            while (
                not self._cancelled
                and self._items
                and (len(self._items) >= self._max_batches or self._bytes + size > self._max_bytes)
            ):
                self._changed.wait()
            if self._cancelled:
                return False
            self._items.append((batch, size))
            self._bytes += size
            self._changed.notify_all()
            return True

    def get(self, timeout: float | None = None) -> pa.RecordBatch | _NotYet | None:
        """The next batch, waiting for one. None at the end. Raises the producer's error, if it had one.

        With `timeout`, gives `NOT_YET` when no batch came in that many seconds.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        with self._changed:
            while not self._items and not self._finished:
                left = None if deadline is None else deadline - time.monotonic()
                if left is not None and left <= 0:
                    return NOT_YET
                self._changed.wait(left)
            if self._items:
                batch, size = self._items.popleft()
                self._bytes -= size
                self._changed.notify_all()
                return batch
            if self._error is not None:
                raise self._error
            return None

    def finish(self, error: BaseException | None = None) -> None:
        with self._changed:
            self._finished = True
            self._error = error
            self._changed.notify_all()

    def cancel(self) -> None:
        with self._changed:
            self._cancelled = True
            self._changed.notify_all()


class RowGroups:
    """Collects tables and writes them as row groups of exactly `size` rows (the last one may be smaller)."""

    def __init__(self, writer: pq.ParquetWriter, size: int) -> None:
        self._writer = writer
        self._size = size
        self._pending: list[pa.Table] = []
        self._rows = 0

    def add(self, table: pa.Table) -> None:
        self._pending.append(table)
        self._rows += table.num_rows
        while self._rows >= self._size:
            whole = pa.concat_tables(self._pending)
            self._writer.write_table(whole.slice(0, self._size), row_group_size=self._size)
            rest = whole.slice(self._size)
            self._pending, self._rows = ([rest] if rest.num_rows else []), rest.num_rows

    def finish(self) -> None:
        if self._rows:
            self._writer.write_table(pa.concat_tables(self._pending), row_group_size=self._size)
            self._pending, self._rows = [], 0


def run_batch_stage(stage: Stage, ctx: RunContext) -> StageResult:
    """Run the stage batch by batch, commit its file, then write its manifest."""
    started = time.perf_counter()
    plan = prepare_stage(stage, ctx)
    refuse_fused_only(plan, "batch")
    steps = polars_steps(plan)
    schema = _output_schema(plan, ctx, steps)
    with watching(stage_watchdog(stage, ctx)) as watchdog:
        meter = StageMeter(
            stage.index, "batch", [node.id for node in stage.nodes[:-1]], ctx.on_event, watchdog=watchdog
        )
        queue = BatchQueue(QUEUE_BATCHES, QUEUE_BYTES)
        reader = threading.Thread(
            target=_read_into, args=(queue, plan, ctx, meter), name="safetwin-reader", daemon=True
        )
        reader.start()
        try:
            # `committing` (the commit lock) is let go when this block ends, before the `finally` below waits
            # for the reader: the lock is never held while a thread is joined.
            with ExitStack() as committing, CommitWriter(plan.sink.file, on_progress=meter.set_bytes) as out:
                with pq.ParquetWriter(
                    out, schema, compression=PARQUET_COMPRESSION, compression_level=PARQUET_COMPRESSION_LEVEL
                ) as writer:
                    groups = RowGroups(writer, ROW_GROUP_ROWS)
                    while True:
                        if meter.paused:  # what the writer holds goes to the file, out of memory
                            groups.finish()
                        batch = queue.get(timeout=PAUSE_LOOK_S)
                        if isinstance(
                            batch, _NotYet
                        ):  # a pause can begin while the queue is empty: look again
                            continue
                        if batch is None:
                            break
                        meter.check(wait=False)  # the writer drains the queue while the stage is paused
                        frame = pl.DataFrame(batch)
                        if plan.source is not None:  # the rows that were read
                            meter.add_rows(stage.nodes[0].id, frame.height)
                        for node, step in steps:
                            frame = step(frame.lazy()).collect()
                            meter.add_rows(node.id, frame.height)
                        groups.add(frame.to_arrow())
                    groups.finish()
                hold_commit_lock(ctx, committing)  # until the manifest is written
                commit = out.commit()
                return finish_stage(plan, ctx, meter, commit, "batch", started)
        finally:
            queue.cancel()
            watchdog.close()  # a reader that waits because the stage is paused must not wait for ever
            reader.join()


def _output_schema(plan: StagePlan, ctx: RunContext, steps: list[tuple[Node, Transform]]) -> pa.Schema:
    """The Arrow schema of what the stage writes, found by running the steps on a frame without rows."""
    if plan.source is not None:
        empty = pl.DataFrame(schema=dict.fromkeys(plan.columns, pl.String))
    else:
        scan = pl.scan_parquet(committed_files(plan, ctx), glob=False, hive_partitioning=False)
        empty = pl.DataFrame(schema=scan.collect_schema())
    for _, step in steps:
        empty = step(empty.lazy()).collect()
    return empty.to_arrow().schema


def _read_into(queue: BatchQueue, plan: StagePlan, ctx: RunContext, meter: StageMeter) -> None:
    """The reader thread: put every batch of the stage's input into the queue, then finish it.

    Before it reads a batch it waits while the watchdog has paused the stage (`meter.check`).
    """
    try:
        batches = (
            _csv_batches(plan.files, plan.source, plan.columns)
            if plan.source is not None
            else _parquet_batches(committed_files(plan, ctx))
        )
        while True:
            meter.check()
            batch = next(batches, None)
            if batch is None:
                break
            for piece in _pieces(batch):
                if not queue.put(piece):
                    return
        queue.finish()
    except BaseException as err:  # handed to the consumer, which raises it
        queue.finish(err)


def _csv_batches(files: list[Path], config: CsvSource, names: list[str]) -> Iterator[pa.RecordBatch]:
    """The rows of the CSV files as batches of text columns, the way Polars reads them on the fused path.

    `names` are the columns, as Polars names them, so both paths agree on the names.
    """
    for path in files:
        with pacsv.open_csv(
            path,
            read_options=pacsv.ReadOptions(
                column_names=names, skip_rows=1 if config.has_header else 0, block_size=CSV_BLOCK_BYTES
            ),
            parse_options=pacsv.ParseOptions(delimiter=config.delimiter, newlines_in_values=True),
            convert_options=pacsv.ConvertOptions(
                column_types=dict.fromkeys(names, pa.string()),
                null_values=[""],  # an empty field is null, a quoted one ("") is an empty string: like Polars
                strings_can_be_null=True,
                quoted_strings_can_be_null=False,
            ),
        ) as reader:
            yield from reader


def _parquet_batches(files: list[Path]) -> Iterator[pa.RecordBatch]:
    for path in files:
        yield from pq.ParquetFile(path).iter_batches(batch_size=BATCH_ROWS)


def _pieces(batch: pa.RecordBatch) -> Iterator[pa.RecordBatch]:
    """`batch` cut (without copying) into pieces of at most BATCH_ROWS rows and BATCH_BYTES bytes."""
    if batch.num_rows == 0:
        return
    count = max(-(-batch.num_rows // BATCH_ROWS), -(-batch.nbytes // BATCH_BYTES))
    size = -(-batch.num_rows // count)
    for start in range(0, batch.num_rows, size):
        yield batch.slice(start, size)
