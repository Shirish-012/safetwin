"""The parts of a stage that run beside the data: counters, progress events, the queue and the row groups."""

import errno
import threading
import time
from itertools import pairwise
from pathlib import Path
from typing import Any

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from safetwin.dataplane import batch, runtime
from safetwin.dataplane.batch import BatchQueue, RowGroups
from safetwin.dataplane.run import run_pipeline_local
from safetwin.dataplane.runtime import ProgressEvent, StageMeter


class Clock:
    """A clock that only moves when the test says so."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def a_meter(events: list[ProgressEvent], clock: Clock, **kwargs: Any) -> StageMeter:
    return StageMeter(2, "fused", ["read", "drop"], events.append, clock=clock, **kwargs)


# --- counting -------------------------------------------------------------------------------------------


def test_rows_are_counted_per_node() -> None:
    meter = StageMeter(0, "fused", ["read", "drop"], None)
    meter.add_rows("read", 10)
    meter.add_rows("drop", 4)
    meter.add_rows("read", 5)
    assert meter.rows == {"read": 15, "drop": 4}
    meter.rows["read"] = 0  # it is a copy
    assert meter.rows["read"] == 15


def test_the_counter_for_map_batches_counts_and_hands_the_frame_on_unchanged() -> None:
    meter = StageMeter(0, "fused", ["read"], None)
    frame = pl.DataFrame({"a": [1, 2, 3]})
    assert meter.counter("read")(frame) is frame
    meter.counter("read")(frame.head(2))
    assert meter.rows == {"read": 5}


def test_counting_from_many_threads_loses_nothing() -> None:
    meter = StageMeter(0, "fused", ["a"], lambda event: None, interval=0)
    frame = pl.DataFrame({"x": [1, 2, 3]})
    count = meter.counter("a")

    def work() -> None:
        for _ in range(5000):
            count(frame)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert meter.rows == {"a": 8 * 5000 * 3}


# --- progress events ---------------------------------------------------------------------------------------


def test_the_first_event_comes_one_interval_after_the_start_and_carries_bytes_and_rows() -> None:
    clock, events = Clock(), []
    meter = a_meter(events, clock)
    meter.add_rows("read", 100)
    clock.now += 0.2
    meter.add_rows("read", 100)
    assert events == []  # a stage that is done sooner reports nothing
    clock.now += 0.06
    meter.set_bytes(4096)
    assert events == [ProgressEvent(2, "fused", 4096, {"read": 200, "drop": 0}, pytest.approx(0.26))]


def test_events_come_at_most_four_times_a_second() -> None:
    clock, events = Clock(), []
    meter = a_meter(events, clock)
    for _ in range(1000):  # 10 seconds, a count every 10 ms
        clock.now += 0.01
        meter.add_rows("read", 1)
        meter.set_bytes(1)
    assert 38 <= len(events) <= 40
    times = [event.elapsed_s for event in events]
    assert all(later - earlier >= 0.25 - 1e-9 for earlier, later in pairwise(times))
    assert [event.rows_per_node["read"] for event in events] == sorted(
        event.rows_per_node["read"] for event in events
    )


def test_the_interval_can_be_changed_and_an_event_is_a_snapshot() -> None:
    clock, events = Clock(), []
    meter = a_meter(events, clock, interval=1.0)
    clock.now += 1
    meter.add_rows("read", 1)
    clock.now += 0.9
    meter.add_rows("read", 1)
    clock.now += 0.1
    meter.add_rows("read", 1)
    assert [event.rows_per_node["read"] for event in events] == [1, 3]
    meter.add_rows("read", 10)
    assert events[0].rows_per_node["read"] == 1  # later counts do not change an event that was sent


def test_two_events_are_never_sent_at_once() -> None:
    inside, most, lock = 0, 0, threading.Lock()

    def slow(event: ProgressEvent) -> None:
        nonlocal inside, most
        with lock:
            inside += 1
            most = max(most, inside)
        time.sleep(0.001)
        with lock:
            inside -= 1

    meter = StageMeter(0, "fused", ["a"], slow, interval=0)
    threads = [
        threading.Thread(target=lambda: [meter.add_rows("a", 1) for _ in range(100)]) for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert most == 1
    assert meter.rows == {"a": 400}


@pytest.mark.parametrize("path", ["fused", "batch"])
def test_a_run_reports_progress_with_bytes_and_rows(
    nodes: Any, data: Any, sockets: Any, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runtime, "EVENT_INTERVAL_S", 0.0)  # every change is reported
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(5000))
    events: list[ProgressEvent] = []
    result = run_pipeline_local(nodes.messy(), sockets.folders, force_path=path, on_event=events.append)  # type: ignore[arg-type]
    final = result.stages[0]
    assert events
    assert {(event.stage, event.path) for event in events} == {(0, path)}
    ids = ["read", "has_id", "tidy", "dates", "numbers", "shout", "keep"]
    assert all(list(event.rows_per_node) == ids for event in events)  # every node but the sink, in order
    assert events[-1].bytes_written > 0
    assert events[-1].bytes_written <= final.files[0].bytes
    for earlier, later in pairwise(events):  # progress only moves forward
        assert later.bytes_written >= earlier.bytes_written
        assert later.elapsed_s >= earlier.elapsed_s
        for node_id in ids:
            assert later.rows_per_node[node_id] >= earlier.rows_per_node[node_id]
    assert all(
        count <= final.rows_per_node[node_id]
        for event in events
        for node_id, count in event.rows_per_node.items()
    )


def test_a_run_without_a_listener_just_runs(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(100))
    assert run_pipeline_local(nodes.messy(), sockets.folders).stages[0].rows_per_node["read"] == 100


# --- the queue ---------------------------------------------------------------------------------------------


def a_batch(rows: int = 10, width: int = 100) -> pa.RecordBatch:
    return pa.record_batch([pa.array(["x" * width] * rows)], names=["a"])


def test_the_queue_hands_batches_on_in_order_and_ends() -> None:
    queue = BatchQueue(10, 1 << 30)
    batches = [a_batch(n) for n in (1, 2, 3)]
    for one in batches:
        assert queue.put(one)
    queue.finish()
    assert [queue.get() for _ in range(3)] == batches
    assert queue.get() is None
    assert queue.get() is None  # and stays ended


def test_get_with_a_timeout_gives_up_when_no_batch_comes_and_otherwise_works_as_before() -> None:
    queue = BatchQueue(10, 1 << 30)
    started = time.monotonic()
    assert queue.get(timeout=0.05) is batch.NOT_YET  # a value, not an exception a reader could raise too
    assert 0.04 <= time.monotonic() - started < 5
    one = a_batch(1)
    queue.put(one)
    assert queue.get(timeout=0.05) == one
    queue.finish()
    assert queue.get(timeout=0.05) is None


def test_put_waits_while_the_queue_holds_as_many_batches_as_it_may() -> None:
    queue = BatchQueue(2, 1 << 30)
    queue.put(a_batch())
    queue.put(a_batch())
    third = threading.Thread(target=queue.put, args=(a_batch(),))
    third.start()
    third.join(timeout=0.2)
    assert third.is_alive()  # waiting for room
    assert queue.get() is not None
    third.join(timeout=10)
    assert not third.is_alive()


def test_put_waits_while_the_batches_in_the_queue_add_up_to_as_many_bytes_as_it_may() -> None:
    size = a_batch().nbytes
    queue = BatchQueue(100, int(size * 2.5))  # room for two batches and a half
    queue.put(a_batch())
    queue.put(a_batch())
    third = threading.Thread(target=queue.put, args=(a_batch(),))
    third.start()
    third.join(timeout=0.2)
    assert third.is_alive()
    queue.get()
    third.join(timeout=10)
    assert not third.is_alive()


def test_a_batch_bigger_than_the_byte_limit_gets_in_when_the_queue_is_empty() -> None:
    queue = BatchQueue(10, 10)
    big = a_batch(1000)
    assert big.nbytes > 10
    assert queue.put(big)  # would wait forever if it needed the room to be there first
    assert queue.get() is big


def test_cancel_frees_a_producer_that_is_waiting_and_makes_put_give_up() -> None:
    queue = BatchQueue(1, 1 << 30)
    queue.put(a_batch())
    results: list[bool] = []
    waiting = threading.Thread(target=lambda: results.append(queue.put(a_batch())))
    waiting.start()
    waiting.join(timeout=0.2)
    assert waiting.is_alive()
    queue.cancel()
    waiting.join(timeout=10)
    assert results == [False]
    assert queue.put(a_batch()) is False


def test_get_waits_for_a_batch_and_raises_the_error_of_the_producer() -> None:
    queue = BatchQueue(10, 1 << 30)
    outcome: list[Any] = []

    def consume() -> None:
        try:
            outcome.append(queue.get())
            outcome.append(queue.get())
        except ValueError as err:
            outcome.append(err)

    consumer = threading.Thread(target=consume)
    consumer.start()
    consumer.join(timeout=0.2)
    assert consumer.is_alive()  # nothing to take yet
    first = a_batch()
    queue.put(first)
    queue.finish(ValueError("the reader failed"))
    consumer.join(timeout=10)
    assert outcome[0] is first
    assert isinstance(outcome[1], ValueError)
    assert str(outcome[1]) == "the reader failed"  # batches that were in the queue come first, then the error


def test_pieces_of_a_batch_are_small_and_add_up_to_the_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    big = pa.record_batch([pa.array(range(150_000))], names=["n"])
    pieces = list(batch._pieces(big))
    assert [piece.num_rows for piece in pieces] == [50_000] * 3  # the fewest pieces of at most 65,536 rows
    assert pa.Table.from_batches(pieces).equals(pa.Table.from_batches([big]))
    monkeypatch.setattr(batch, "BATCH_BYTES", 400_000)
    by_bytes = list(
        batch._pieces(big)
    )  # 1.2 MB of numbers: at least 3 pieces of 400 KB, and they are cut by rows
    assert len(by_bytes) == 3
    assert max(piece.nbytes for piece in by_bytes) <= 400_000
    assert list(batch._pieces(pa.record_batch([pa.array([], pa.int64())], names=["n"]))) == []
    assert len(list(batch._pieces(pa.record_batch([pa.array([1])], names=["n"])))) == 1


# --- row groups --------------------------------------------------------------------------------------------


def test_row_groups_are_of_the_size_asked_for_and_the_last_one_holds_the_rest(tmp_path: Path) -> None:
    path = tmp_path / "x.parquet"
    with pq.ParquetWriter(path, pa.schema([("n", pa.int64())])) as writer:
        groups = RowGroups(writer, 1000)
        for start in range(0, 3500, 300):  # tables of 300 rows, and a last one of 200
            groups.add(pa.table({"n": list(range(start, min(start + 300, 3500)))}))
        groups.finish()
    file = pq.ParquetFile(path)
    assert [file.metadata.row_group(i).num_rows for i in range(file.metadata.num_row_groups)] == [
        1000,
        1000,
        1000,
        500,
    ]
    assert pq.read_table(path)["n"].to_pylist() == list(range(3500))  # in order, nothing lost or repeated


def test_one_big_table_is_split_into_row_groups_and_an_exact_multiple_leaves_no_small_one(
    tmp_path: Path,
) -> None:
    path = tmp_path / "x.parquet"
    with pq.ParquetWriter(path, pa.schema([("n", pa.int64())])) as writer:
        groups = RowGroups(writer, 100)
        groups.add(pa.table({"n": list(range(300))}))
        groups.finish()
    assert [pq.ParquetFile(path).metadata.row_group(i).num_rows for i in range(3)] == [100, 100, 100]
    assert pq.ParquetFile(path).metadata.num_row_groups == 3


def test_no_rows_no_row_group(tmp_path: Path) -> None:
    path = tmp_path / "x.parquet"
    with pq.ParquetWriter(path, pa.schema([("n", pa.int64())])) as writer:
        RowGroups(writer, 100).finish()
    assert pq.ParquetFile(path).metadata.num_row_groups == 0


def test_the_documented_sizes() -> None:
    assert batch.ROW_GROUP_ROWS == 1_000_000
    assert batch.BATCH_ROWS == 65_536
    assert batch.BATCH_BYTES == 16 * 1024 * 1024
    assert runtime.EVENT_INTERVAL_S == 0.25


@pytest.mark.parametrize(
    "error",
    [OSError(errno.ETIMEDOUT, "timed out"), TimeoutError()],
    ids=["an OSError with ETIMEDOUT", "a bare TimeoutError"],
)
def test_a_reader_that_fails_with_a_timeout_fails_the_batch_stage_and_does_not_hang(
    nodes: Any, data: Any, sockets: Any, monkeypatch: pytest.MonkeyPatch, error: OSError
) -> None:
    # The writer polls the queue for "nothing yet": a TimeoutError of the reader (a network share, a socket)
    # must fail the stage, not be taken for that.
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(300))
    real = batch._csv_batches

    def failing(*args: Any) -> Any:
        yield next(real(*args))
        raise error

    monkeypatch.setattr(batch, "_csv_batches", failing)
    raised: list[BaseException] = []

    def run() -> None:
        try:
            run_pipeline_local(nodes.messy(), sockets.folders, force_path="batch")
        except BaseException as err:
            raised.append(err)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(30)
    assert not thread.is_alive(), "the batch stage hung on the reader's TimeoutError"
    assert raised == [error]
    assert isinstance(error, TimeoutError)  # what Python makes of ETIMEDOUT, too
    assert sockets.written() == []
    names = {thread.name for thread in threading.enumerate()}
    assert not names & {"safetwin-reader", "safetwin-watchdog"}
