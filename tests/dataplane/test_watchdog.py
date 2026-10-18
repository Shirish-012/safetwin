"""The memory watchdog of a stage: its states, its thread, and how each path obeys it (docs/internals.md).

The tests of the paths drive the watchdog with a fake sampler: the stage's memory is whatever the test says,
and the test says it when the rows that have reached a node pass a threshold, so the stage is paused or
stopped in the middle of its data. Each of them runs the stage on a thread of its own, with a time limit: a
stage that never ends is a deadlock, and fails the test instead of hanging it.
"""

import logging
import mmap
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import polars as pl
import pytest

from safetwin import memory
from safetwin.dataplane import batch, fused, hybrid, runtime, watchdog
from safetwin.dataplane.run import RunResult, run_pipeline_local
from safetwin.dataplane.runtime import ProgressEvent
from safetwin.dataplane.watchdog import (
    MAX_PAUSE_S,
    PAUSE_AT,
    RESUME_BELOW,
    MemoryLimitReached,
    Watchdog,
    process_memory_sampler,
    watching,
)

SHARE = 1_000_000_000  # enough for DuckDB to sort the rows of the tests below in 80% of it
BASE = 500_000_000  # the memory of the process when the stage starts
WHAT = "the stage of read (source.csv), ordered (transform.sort), write (sink.parquet)"
SECONDS = 60  # a stage here takes well under a second: one that runs for this long is stuck


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def at(share: float) -> int:
    """The memory of the process when the stage has grown to `share` of SHARE."""
    return BASE + int(share * SHARE)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def dog(clock: Clock) -> Watchdog:
    """A watchdog that is not started: the test hands it samples with `observe`. The first is the baseline."""
    made = Watchdog(SHARE, WHAT, sampler=lambda: BASE, clock=clock)
    assert made.observe(BASE) == "running"
    return made


# --- the states ---------------------------------------------------------------------------------------------


def test_the_thresholds_are_90_and_80_percent_and_a_pause_lasts_at_most_30_seconds() -> None:
    assert (PAUSE_AT, RESUME_BELOW, MAX_PAUSE_S) == (0.9, 0.8, 30.0)


def test_a_stage_is_paused_at_90_percent_and_runs_again_below_80(dog: Watchdog) -> None:
    assert dog.observe(at(0.89)) == "running"
    assert dog.observe(at(0.90)) == "paused"
    assert dog.observe(at(0.85)) == "paused"  # between the two: it stays as it was
    assert dog.observe(at(0.80)) == "paused"
    assert dog.observe(at(0.79)) == "running"
    assert dog.observe(at(0.85)) == "running"
    assert dog.observe(at(0.95)) == "paused"
    assert dog.pauses == 2


@pytest.mark.parametrize("before", [0.0, 0.95])
def test_100_percent_stops_the_stage_whether_it_ran_or_was_paused_and_stopped_is_final(
    dog: Watchdog, before: float
) -> None:
    dog.observe(at(before))
    assert dog.observe(at(1.0)) == "stopped"
    assert dog.observe(at(0.0)) == "stopped"
    assert dog.state == "stopped"


def test_a_pause_that_lasts_too_long_stops_the_stage(dog: Watchdog, clock: Clock) -> None:
    assert dog.observe(at(0.92)) == "paused"
    clock.now += MAX_PAUSE_S - 0.1
    assert dog.observe(at(0.92)) == "paused"
    clock.now += 0.1
    assert dog.observe(at(0.92)) == "stopped"


def test_a_pause_that_ends_in_time_starts_its_clock_again_next_time(dog: Watchdog, clock: Clock) -> None:
    dog.observe(at(0.92))
    clock.now += MAX_PAUSE_S - 1
    assert dog.observe(at(0.5)) == "running"
    assert dog.observe(at(0.92)) == "paused"
    clock.now += MAX_PAUSE_S - 1
    assert dog.observe(at(0.92)) == "paused"


def test_the_memory_of_the_stage_is_the_growth_over_the_baseline(dog: Watchdog) -> None:
    dog.observe(at(0.3))
    assert dog.memory_bytes == 300_000_000
    dog.observe(at(0.5))
    dog.observe(BASE - 1000)  # the process can shrink below where it started: the stage is at 0
    assert dog.memory_bytes == 0
    assert dog.peak_bytes == 500_000_000


def test_a_share_must_be_at_least_one_byte() -> None:
    with pytest.raises(ValueError, match="at least one byte"):
        Watchdog(0, WHAT)


# --- check, close and the hooks ----------------------------------------------------------------------------


def test_check_raises_a_clear_error_once_the_stage_is_stopped(dog: Watchdog) -> None:
    dog.check()  # running: nothing happens
    dog.observe(at(1.2))
    with pytest.raises(MemoryLimitReached) as stopped:
        dog.check()
    assert str(stopped.value) == (
        f"{WHAT} used more memory than it may (the limit is 1.0 GB), so it was stopped. Raise the memory "
        "limit (--memory-limit), or add a filter before the heavy step or select fewer columns so that less "
        "data reaches it."
    )
    with pytest.raises(MemoryLimitReached):
        dog.check(wait=False)


def test_the_limit_in_the_message_is_written_as_the_other_sizes_are() -> None:
    assert "(the limit is 4.3 GB)" in str(Watchdog(4_300_000_000, WHAT).error())


def wait_until(condition: Callable[[], bool], seconds: float = SECONDS) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "waited too long"
        time.sleep(0.002)


def test_check_waits_while_the_stage_is_paused_and_goes_on_when_it_runs_again(dog: Watchdog) -> None:
    dog.observe(at(0.95))
    passed = threading.Event()
    waiter = threading.Thread(target=lambda: (dog.check(), passed.set()), daemon=True)
    waiter.start()
    time.sleep(0.1)
    assert not passed.is_set()
    dog.check(wait=False)  # the writer of the batch path does not wait
    dog.observe(at(0.5))
    waiter.join(SECONDS)
    assert passed.is_set()


def test_a_check_that_waits_raises_when_the_stage_is_stopped(dog: Watchdog) -> None:
    dog.observe(at(0.95))
    raised: list[BaseException] = []

    def wait() -> None:
        try:
            dog.check()
        except MemoryLimitReached as err:
            raised.append(err)

    waiter = threading.Thread(target=wait, daemon=True)
    waiter.start()
    time.sleep(0.05)
    dog.observe(at(1.0))
    waiter.join(SECONDS)
    assert [type(err) for err in raised] == [MemoryLimitReached]


def test_close_lets_go_of_a_check_that_waits(dog: Watchdog) -> None:
    dog.observe(at(0.95))
    waiter = threading.Thread(target=dog.check, daemon=True)
    waiter.start()
    time.sleep(0.05)
    dog.close()
    waiter.join(SECONDS)
    assert not waiter.is_alive()
    dog.close()  # twice is fine


def test_the_hooks_are_called_once_when_the_stage_is_stopped_and_what_they_raise_is_ignored(
    dog: Watchdog,
) -> None:
    called: list[str] = []

    def broken() -> None:
        called.append("broken")
        raise RuntimeError("the connection is closed already")

    dog.on_stop(broken)
    dog.on_stop(lambda: called.append("interrupt"))
    dog.observe(at(0.95))
    assert called == []
    dog.observe(at(1.0))
    dog.observe(at(1.5))
    assert called == ["broken", "interrupt"]
    dog.on_stop(lambda: called.append("late"))  # a hook that comes after the stop is called at once
    assert called == ["broken", "interrupt", "late"]


# --- the thread ---------------------------------------------------------------------------------------------


class Memory:
    """A fake sampler: the baseline is BASE, and then the stage is at `level` of SHARE."""

    def __init__(self) -> None:
        self.level = 0.0
        self.calls = 0
        self._first = True

    def __call__(self) -> int:
        self.calls += 1
        if self._first:  # the baseline
            self._first = False
            return BASE
        return at(self.level)


def dog_threads() -> list[threading.Thread]:
    return [thread for thread in threading.enumerate() if thread.name == "safetwin-watchdog"]


@pytest.fixture
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    """A sample every 2 ms, and a progress event for every count (the fake samplers follow the counts)."""
    monkeypatch.setattr(watchdog, "INTERVAL_S", 0.002)
    monkeypatch.setattr(runtime, "EVENT_INTERVAL_S", 0.0)


def test_the_thread_samples_until_it_is_closed_and_is_gone_then(fast: None) -> None:
    memory = Memory()
    dog = Watchdog(SHARE, WHAT, sampler=memory)
    with watching(dog):
        assert dog_threads()
        memory.level = 0.95
        wait_until(lambda: dog.state == "paused")
        memory.level = 0.2
        wait_until(lambda: dog.state == "running")
    assert dog_threads() == []
    calls = memory.calls
    time.sleep(0.02)
    assert memory.calls == calls  # no sample after the end


def test_the_first_sample_is_taken_before_the_stage_moves_any_data() -> None:
    memory = Memory()
    memory.level = 0.95
    dog = Watchdog(SHARE, WHAT, sampler=memory)
    with watching(dog):
        assert dog.state == "paused"
        assert memory.calls == 2  # the baseline, then the first sample
        dog.close()


class Failing:
    """A sampler that gives the baseline, then `level` of SHARE for `good` samples, and then fails."""

    def __init__(self, level: float, good: int = 1) -> None:
        self._samples = iter([BASE] + [at(level)] * good)

    def __call__(self) -> int:
        return next(self._samples)  # raises StopIteration when they are used up, which is an Exception


@pytest.mark.parametrize("level", [0.0, 0.95], ids=["running", "paused"])
def test_a_sampler_that_fails_ends_the_thread_and_the_stage_goes_on(fast: None, level: float) -> None:
    dog = Watchdog(SHARE, WHAT, sampler=Failing(level))
    with watching(dog):
        assert dog.state == ("paused" if level else "running")  # the first sample, taken by start
        returned = threading.Event()
        waiter = threading.Thread(target=lambda: (dog.check(), returned.set()), daemon=True)
        waiter.start()
        assert returned.wait(10), "check kept waiting for a watchdog that is gone"
        wait_until(lambda: dog_threads() == [], 10)
        dog.check()
    assert dog.state == "running"  # nobody is left to end a pause, so none is kept


def test_a_pause_is_not_kept_when_the_thread_could_not_start(monkeypatch: pytest.MonkeyPatch) -> None:
    def cannot_start(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    memory = Memory()
    memory.level = 0.95
    dog = Watchdog(SHARE, WHAT, sampler=memory)
    monkeypatch.setattr(watchdog.threading.Thread, "start", cannot_start)
    with pytest.raises(RuntimeError, match="can't start new thread"):
        dog.start()
    monkeypatch.undo()
    dog.check()  # returns at once
    assert dog.state == "running"


@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)  # the thread dies, on purpose
def test_a_pause_is_not_kept_when_the_thread_ends_for_another_reason(fast: None) -> None:
    calls = [0]

    def clock() -> float:  # the first sample (in start) is fine; the thread's first one raises
        calls[0] += 1
        if calls[0] > 1:
            raise ValueError("a bug in the watchdog")
        return 0.0

    memory = Memory()
    memory.level = 0.95
    dog = Watchdog(SHARE, WHAT, sampler=memory, clock=clock)
    with watching(dog):
        returned = threading.Event()
        threading.Thread(target=lambda: (dog.check(), returned.set()), daemon=True).start()
        assert returned.wait(10)
    assert dog.state == "running"


@pytest.mark.parametrize("path", ["fused", "batch", "hybrid"])
def test_a_stage_that_is_paused_when_the_sampler_fails_finishes(
    nodes: Any, sockets: Any, reference: dict[str, Any], fast: None, path: str
) -> None:
    sockets.inbox.rmdir()
    sockets.inbox.symlink_to(reference["inbox"])
    run = Background(
        lambda: run_pipeline_local(
            pipeline(nodes, path),
            sockets.folders,
            force_path=path,  # type: ignore[arg-type]
            memory_sampler=Failing(0.95, good=3),  # paused from the start, then the sampler fails
            memory_limit_bytes=SHARE,
        )
    )
    run.join()  # within the time limit
    assert run.error is None, repr(run.error)
    assert run.result is not None
    assert run.result.stages[0].rows_per_node["write"] == ROWS
    assert dog_threads() == []


def test_the_thread_is_gone_after_a_stage_that_failed_and_the_error_is_raised_as_it_was(fast: None) -> None:
    dog = Watchdog(SHARE, WHAT, sampler=Memory())
    with pytest.raises(KeyError), watching(dog):
        raise KeyError("a failure of the stage")
    assert dog_threads() == []


def test_the_error_of_a_stage_that_the_watchdog_stopped_is_memory_limit_reached(fast: None) -> None:
    memory = Memory()
    dog = Watchdog(SHARE, WHAT, sampler=memory)

    def stage() -> None:
        with watching(dog):
            memory.level = 1.0
            wait_until(lambda: dog.state == "stopped")
            raise RuntimeError("Interrupted: what DuckDB says, which can quote CANARY-7f3a9c data")

    with pytest.raises(MemoryLimitReached) as stopped:
        stage()
    assert stopped.value.__suppress_context__
    assert "CANARY" not in str(stopped.value)
    assert dog_threads() == []


def test_an_interrupt_from_the_keyboard_is_raised_as_it_is_even_after_a_stop(fast: None) -> None:
    memory = Memory()
    memory.level = 1.0
    with pytest.raises(KeyboardInterrupt), watching(Watchdog(SHARE, WHAT, sampler=memory)):
        raise KeyboardInterrupt


@pytest.mark.parametrize(
    ("value", "interval"),
    [
        (None, 0.1),
        ("0.005", 0.005),
        ("1", 1.0),
        ("0", 0.1),
        ("5", 0.1),
        ("-1", 0.1),
        ("fast", 0.1),
        ("", 0.1),
    ],
)
def test_only_a_test_can_make_the_watchdog_sample_more_often_and_only_that(
    monkeypatch: pytest.MonkeyPatch, value: str | None, interval: float
) -> None:
    assert watchdog.TEST_INTERVAL_ENV == "SAFETWIN_TEST_WATCHDOG_INTERVAL_S"
    if value is None:
        monkeypatch.delenv(watchdog.TEST_INTERVAL_ENV, raising=False)
    else:
        monkeypatch.setenv(watchdog.TEST_INTERVAL_ENV, value)
    assert Watchdog(SHARE, WHAT)._interval == interval
    assert Watchdog(SHARE, WHAT, interval=0.5)._interval == 0.5  # what the code asks for wins


# --- the memory of the process -----------------------------------------------------------------------------


def incompressible_memory(size: int) -> mmap.mmap:
    """`size` bytes of new anonymous memory with every page written with random bytes.

    Random, because a page filled with one repeated byte is easy for the macOS memory compressor to shrink,
    and then the footprint grows by less than what was touched. A mapping of its own, because memory from
    malloc may reuse what an earlier allocation freed and the allocator kept: then it adds less than its size.
    Private, as the memory of a query is: `mmap(-1, ...)` alone is shared, and on Linux the sampler leaves out
    shared pages (they are what mapped files take).
    """
    block = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
    chunk = 1 << 20
    for start in range(0, size, chunk):
        block[start : start + chunk] = os.urandom(min(chunk, size - start))
    return block


ATTEMPTS = 3  # under memory pressure (a full test run) macOS can swap fresh pages out at once: measure again


def test_the_sampler_of_the_process_sees_memory_that_is_used() -> None:
    sample = process_memory_sampler()
    grown = 0
    for _ in range(ATTEMPTS):
        before = sample()
        with incompressible_memory(200_000_000):
            grown = sample() - before
        if grown >= 150_000_000:
            break
    assert grown >= 150_000_000, f"{grown:,}"


@pytest.mark.skipif(sys.platform != "darwin", reason="phys_footprint is a macOS measure")
def test_on_macos_the_pages_of_a_mapped_file_do_not_count_but_they_do_in_rss(tmp_path: Path) -> None:
    import psutil

    # While every page of a 400 MB mapped file is read, rss counts the clean pages of the file and the
    # footprint (what the watchdog samples) does not. The control is the same amount of anonymous,
    # incompressible memory, which the footprint does count, so the bounds are relative to what this machine
    # measures right now and hold under memory pressure:
    # - rss: macOS takes clean pages of a file back whenever memory is short, so a peak of rss can stay far
    #   below the file's size. What each 25 MB chunk adds to rss while it is being read is counted instead.
    # - footprint: its peak while the file is read must stay a small part of what the control adds.
    path = tmp_path / "mapped.bin"
    size = 400_000_000
    with path.open("wb") as file:
        file.truncate(size)
    process = psutil.Process()
    sample = process_memory_sampler()

    def measure() -> tuple[int, int, int]:
        footprint = sample()
        footprint_grown = rss_added = total = 0
        step = 25_000_000
        with path.open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            for start in range(0, size, step):  # read every page, and look after every 25 MB
                rss_before = process.memory_info().rss
                total += sum(mapped[offset] for offset in range(start, start + step, mmap.PAGESIZE))
                rss_added += max(0, process.memory_info().rss - rss_before)
                footprint_grown = max(footprint_grown, sample() - footprint)
        assert total == 0
        before = sample()
        with incompressible_memory(size):  # the control
            anonymous_grown = sample() - before
        return footprint_grown, anonymous_grown, rss_added

    for _ in range(ATTEMPTS):
        footprint_grown, anonymous_grown, rss_added = measure()
        if anonymous_grown >= 0.75 * size and rss_added >= 0.5 * size:
            break
    measured = f"footprint +{footprint_grown:,} (control +{anonymous_grown:,}), rss added {rss_added:,}"
    assert anonymous_grown >= 0.75 * size, measured  # the footprint counts anonymous memory...
    assert rss_added >= 0.5 * size, measured  # rss counts the clean pages of the file as they are read...
    assert footprint_grown < 0.15 * anonymous_grown, measured  # ...and the footprint does not count them


def test_on_macos_a_footprint_that_can_not_be_read_falls_back_to_rss_and_says_so_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def no_libproc(*args: object, **kwargs: object) -> None:
        raise OSError("no libproc")

    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(memory.ctypes, "CDLL", no_libproc)
    monkeypatch.setattr(watchdog, "_warned_rss", False)
    caplog.set_level(logging.WARNING, logger="safetwin.dataplane.watchdog")
    first, second = process_memory_sampler(), process_memory_sampler()
    import psutil

    rss = psutil.Process().memory_info().rss
    assert abs(first() - rss) < 50_000_000  # rss it is
    assert abs(second() - rss) < 50_000_000
    assert [record.getMessage() for record in caplog.records] == ["memory footprint unavailable; using rss"]
    assert caplog.records[0].levelno == logging.WARNING


# --- the paths ----------------------------------------------------------------------------------------------

ROWS = 1_000_000


def write_rows(folder: Path, rows: int = ROWS) -> None:
    """`rows` rows of id, name, city and amount; every id is there and different."""
    with (folder / "rows.csv").open("w", encoding="utf-8") as file:
        file.write("id,name,city,amount\n")
        for start in range(0, rows, 100_000):
            file.write(
                "".join(
                    f"{n},  name {n % 97} ,city {n % 13},{n % 1000}.5\n"
                    for n in range(start, min(start + 100_000, rows))
                )
            )


def pipeline(nodes: Any, path: str) -> Any:
    """read → trim → (on the hybrid path, a sort) → write. `tidy` is the step whose count drives the tests."""
    steps = [nodes.read(), nodes.step("tidy", "transform.trim", "read", columns=["name"])]
    if path == "hybrid":
        steps.append(
            nodes.step("ordered", "transform.sort", "tidy", by=[{"column": "id", "descending": True}])
        )
    return nodes.pipeline(*steps, nodes.write("write", steps[-1]["id"]))


@dataclass
class Trigger:
    """A progress listener that sets the fake memory to `level` once `node` has counted `rows` rows.

    It then waits (in the thread that counted, which goes on to `check` next) until the watchdog has taken
    a sample and left the state "running": a stage can pass a million rows in 30 ms, and the pause or the
    stop must come in the middle of them, not after the end.
    """

    memory: Memory
    made: list[Watchdog]
    node: str
    rows: int
    level: float
    latest: dict[str, int] = field(default_factory=dict)
    latest_bytes: int = 0
    at_fire: dict[str, int] = field(default_factory=dict)  # the counts when it fired
    bytes_at_fire: int = 0
    fired: bool = False

    def __call__(self, event: ProgressEvent) -> None:
        self.latest = dict(event.rows_per_node)
        self.latest_bytes = event.bytes_written
        if not self.fired and event.rows_per_node.get(self.node, 0) >= self.rows:
            self.fired = True
            self.at_fire, self.bytes_at_fire = dict(event.rows_per_node), event.bytes_written
            self.memory.level = self.level
            wait_until(lambda: self.made[-1].state != "running", 10)


class Background:
    """A run on a thread of its own, so that a run that never ends fails the test instead of hanging it."""

    def __init__(self, work: Callable[[], RunResult]) -> None:
        self.result: RunResult | None = None
        self.error: BaseException | None = None
        self._work = work
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            self.result = self._work()
        except BaseException as err:
            self.error = err

    def join(self) -> None:
        self.thread.join(SECONDS)
        if self.thread.is_alive():
            pytest.fail(f"the stage did not end in {SECONDS} s: it is stuck (a deadlock?)")


@pytest.fixture
def made(monkeypatch: pytest.MonkeyPatch) -> list[Watchdog]:
    """The watchdogs that the stages made, in order."""
    found: list[Watchdog] = []
    for module in (fused, batch, hybrid):
        real = module.stage_watchdog

        def spy(stage: Any, ctx: Any, real: Callable[..., Watchdog] = real) -> Watchdog:
            dog = real(stage, ctx)
            found.append(dog)
            return dog

        monkeypatch.setattr(module, "stage_watchdog", spy)
    return found


@pytest.fixture(scope="module")
def reference(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """The input, and what each path writes from it when nothing pauses it."""
    root = tmp_path_factory.mktemp("watchdog")
    inbox = root / "in"
    inbox.mkdir()
    write_rows(inbox)
    return {"inbox": inbox, "root": root, "outputs": {}}


def reference_output(reference: dict[str, Any], nodes: Any, path: str) -> pl.DataFrame:
    outputs: dict[str, pl.DataFrame] = reference["outputs"]
    if path not in outputs:
        outbox = reference["root"] / f"out-{path}"
        outbox.mkdir()
        result = run_pipeline_local(
            pipeline(nodes, path), {"inbox": reference["inbox"], "outbox": outbox}, force_path=path
        )  # type: ignore[arg-type]
        outputs[path] = pl.read_parquet([file.path for file in result.stages[0].files])
    return outputs[path]


PATHS = ["fused", "batch", "hybrid"]


@pytest.mark.parametrize("path", PATHS)
def test_a_stage_that_is_paused_in_the_middle_drains_waits_and_then_finishes_with_every_row(
    nodes: Any, sockets: Any, reference: dict[str, Any], made: list[Watchdog], fast: None, path: str
) -> None:
    expected = reference_output(reference, nodes, path)
    made.clear()  # the watchdog of the reference run
    sockets.inbox.rmdir()
    sockets.inbox.symlink_to(reference["inbox"])
    memory = Memory()
    trigger = Trigger(memory, made, "read", 100_000, 0.95)  # the source's counter
    run = Background(
        lambda: run_pipeline_local(
            pipeline(nodes, path),
            sockets.folders,
            force_path=path,  # type: ignore[arg-type]
            on_event=trigger,
            memory_sampler=memory,
            memory_limit_bytes=SHARE,
        )
    )
    wait_until(lambda: bool(made) and made[0].state == "paused")
    time.sleep(0.4)  # what was in flight when the pause came drains to the sink
    held, held_bytes = trigger.latest, trigger.latest_bytes
    time.sleep(0.4)
    assert (trigger.latest, trigger.latest_bytes) == (held, held_bytes)  # then nothing moves...
    assert held["read"] < ROWS  # ...in the middle of the data: the source waits
    # What had passed the source when the pause came went on: every row that was read reached `tidy`.
    assert held["tidy"] == held["read"]
    assert held["tidy"] >= trigger.at_fire["tidy"]
    if path == "batch":  # the writer drained the queue, and wrote the rows it held as a row group
        assert held["read"] > trigger.at_fire["read"]
        assert held_bytes > trigger.bytes_at_fire
    assert run.thread.is_alive()
    assert not [name for name in sockets.written() if name.endswith(".parquet")]  # nothing is committed
    memory.level = 0.5
    run.join()
    assert run.error is None, repr(run.error)
    assert run.result is not None
    (stage,) = run.result.stages
    assert stage.rows_per_node == {
        "read": ROWS,
        "tidy": ROWS,
        **({"ordered": ROWS} if path == "hybrid" else {}),
        "write": ROWS,
    }
    written = pl.read_parquet([file.path for file in stage.files])
    if path == "hybrid":
        assert written.equals(expected)  # sorted, so in the same order
    else:
        assert written.sort("id").equals(expected.sort("id"))
    assert made[0].pauses == 1
    assert made[0].state == "running"
    assert dog_threads() == []


STOPS = {
    "fused": ("fused", "tidy", 100_000),
    "batch": ("batch", "tidy", 100_000),
    "hybrid, in the Polars query": ("hybrid", "tidy", 100_000),
    "hybrid, while DuckDB sorts": ("hybrid", "read", ROWS),
    "hybrid, while DuckDB hands its rows on": ("hybrid", "ordered", 1),
}


@pytest.mark.parametrize("case", STOPS)
def test_a_stage_that_reaches_its_share_stops_with_a_clear_error_and_leaves_nothing(
    nodes: Any, sockets: Any, reference: dict[str, Any], made: list[Watchdog], fast: None, case: str
) -> None:
    path, node, rows = STOPS[case]
    sockets.inbox.rmdir()
    sockets.inbox.symlink_to(reference["inbox"])
    memory = Memory()
    trigger = Trigger(memory, made, node, rows, 1.0)
    run = Background(
        lambda: run_pipeline_local(
            pipeline(nodes, path),
            sockets.folders,
            force_path=path,  # type: ignore[arg-type]
            on_event=trigger,
            memory_sampler=memory,
            memory_limit_bytes=SHARE,
        )
    )
    run.join()
    assert trigger.fired, repr(run.error)
    assert isinstance(run.error, MemoryLimitReached), repr(run.error)
    names = "read (source.csv), tidy (transform.trim), "
    names += "ordered (transform.sort), write (sink.parquet)" if path == "hybrid" else "write (sink.parquet)"
    assert str(run.error).startswith(
        f"the stage of {names} used more memory than it may (the limit is 1.0 GB)"
    )
    assert sockets.written() == []  # no file, no temporary file, no manifest
    assert made[0].state == "stopped"
    assert dog_threads() == []


def test_progress_events_carry_the_memory_of_the_stage(
    nodes: Any, data: Any, sockets: Any, fast: None
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(2000))
    memory = Memory()
    memory.level = 0.25
    events: list[ProgressEvent] = []
    run_pipeline_local(
        nodes.messy(),
        sockets.folders,
        on_event=events.append,
        memory_sampler=memory,
        memory_limit_bytes=SHARE,
    )
    assert events
    assert {event.memory_bytes for event in events} == {250_000_000}


def test_a_run_without_a_fake_sampler_measures_real_memory(
    nodes: Any, data: Any, sockets: Any, fast: None
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(5000))
    events: list[ProgressEvent] = []
    result = run_pipeline_local(nodes.messy(), sockets.folders, on_event=events.append, force_path="batch")
    assert result.stages[0].rows_per_node["read"] == 5000
    assert events
    assert all(isinstance(event.memory_bytes, int) and event.memory_bytes >= 0 for event in events)
    assert dog_threads() == []


@pytest.mark.parametrize("moment", ["just after the file is made", "before the with block starts"])
@pytest.mark.parametrize("path", PATHS)
def test_an_interrupt_at_the_worst_moment_of_a_writer_leaves_no_temporary_file(
    nodes: Any, data: Any, sockets: Any, monkeypatch: pytest.MonkeyPatch, path: str, moment: str
) -> None:
    # Ctrl-C can raise KeyboardInterrupt right after `os.open` made the temporary file and before the writer
    # knows it, or after the writer is made and before its `with` block: the run removes it by its name.
    from safetwin.dataplane import writer

    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(500))
    if moment == "just after the file is made":
        real_open = writer.os.open

        def open_then_interrupt(name: Any, flags: int, mode: int = 0o777) -> int:
            fd = real_open(name, flags, mode)
            if ".parquet.tmp-" in str(name):
                raise KeyboardInterrupt
            return fd

        monkeypatch.setattr(writer.os, "open", open_then_interrupt)
    else:

        def enter_then_interrupt(self: Any) -> Any:
            raise KeyboardInterrupt

        monkeypatch.setattr(writer.CommitWriter, "__enter__", enter_then_interrupt)
    pipeline = nodes.pipeline(
        nodes.read(),
        nodes.step("tidy", "transform.trim", "read", columns=["name"]),
        *([nodes.step("ordered", "transform.sort", "tidy", by=["id"])] if path == "hybrid" else []),
        nodes.write("write", "ordered" if path == "hybrid" else "tidy"),
    )
    with pytest.raises(KeyboardInterrupt):
        run_pipeline_local(pipeline, sockets.folders, force_path=path)  # type: ignore[arg-type]
    monkeypatch.undo()
    assert sockets.written() == []
    assert dog_threads() == []


@pytest.mark.parametrize("path", PATHS)
def test_an_interrupt_right_after_the_data_file_is_renamed_leaves_no_data_file_and_no_manifest(
    nodes: Any, data: Any, sockets: Any, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    # Between the rename of the data file and the `try` of `finish_stage`, which would remove it: the run
    # removes a data file of this stage that no manifest of the run lists.
    from safetwin.dataplane import writer

    real_commit = writer.CommitWriter.commit

    def commit_then_interrupt(self: Any) -> Any:
        done = real_commit(self)
        if done.path.suffix == ".parquet":
            raise KeyboardInterrupt
        return done

    monkeypatch.setattr(writer.CommitWriter, "commit", commit_then_interrupt)
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(500))
    pipeline = nodes.pipeline(
        nodes.read(),
        nodes.step("tidy", "transform.trim", "read", columns=["name"]),
        *([nodes.step("ordered", "transform.sort", "tidy", by=["id"])] if path == "hybrid" else []),
        nodes.write("write", "ordered" if path == "hybrid" else "tidy"),
    )
    with pytest.raises(KeyboardInterrupt):
        run_pipeline_local(pipeline, sockets.folders, force_path=path)  # type: ignore[arg-type]
    assert sockets.written() == []  # no data file, no manifest, no temporary file


def test_a_data_file_that_was_there_before_the_stage_is_never_removed(
    nodes: Any, data: Any, sockets: Any
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(50))
    first = run_pipeline_local(nodes.copy(), sockets.folders, run_id="r-same")
    first.stages[0].manifest.unlink()  # the data file of the earlier run, with no manifest any more
    with pytest.raises(FileExistsError):
        run_pipeline_local(nodes.copy(), sockets.folders, run_id="r-same")
    assert sockets.written() == ["data/part-00000-r-same.parquet"]


def test_only_a_data_file_of_this_run_that_no_manifest_lists_is_removed(
    nodes: Any, data: Any, sockets: Any
) -> None:
    from safetwin.dataplane import run
    from safetwin.dataplane.operators import SinkPlan

    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(50))
    result = run_pipeline_local(nodes.copy(), sockets.folders, run_id="r-kept")
    (stage,) = result.stages
    file = stage.files[0].path
    sink = SinkPlan(file, stage.manifest.parent.parent, file.name, "data", "socket://local-outbox/data")
    run._remove_uncommitted(sink, "r-kept")
    assert file.exists()  # its manifest lists it
    stage.manifest.unlink()
    file.rename(file.with_name("moved.parquet"))
    file.symlink_to(file.with_name("moved.parquet"))
    run._remove_uncommitted(sink, "r-kept")
    assert file.is_symlink()  # a link is not followed, nor removed
    file.unlink()
    file.with_name("moved.parquet").rename(file)
    run._remove_uncommitted(sink, "r-kept")
    assert not file.exists()  # no manifest lists it: removed
    run._remove_uncommitted(sink, "r-kept")  # nothing there: nothing happens


# --- real memory --------------------------------------------------------------------------------------------

REAL = """
import sys
from pathlib import Path
from safetwin.dataplane import watchdog
from safetwin.dataplane.run import run_pipeline_local
from safetwin.dataplane.watchdog import MemoryLimitReached
from safetwin.spec import Pipeline

watchdog.INTERVAL_S = 0.005  # the stage is over in about 0.1 s: a sample every 100 ms could miss it
root = Path(sys.argv[1])
pipeline = Pipeline.model_validate({
    "apiVersion": "safetwin/v1", "kind": "Pipeline", "metadata": {"name": "real"},
    "spec": {"sockets": {"inbox": "socket://inbox", "outbox": "socket://outbox"},
             "nodes": [
                 {"id": "read", "operator": "source.csv", "socket": "inbox", "config": {"path": "*.csv"}},
                 {"id": "write", "operator": "sink.parquet", "inputs": ["read"], "socket": "outbox",
                  "config": {"path": "out/"}}]}})
try:
    run_pipeline_local(pipeline, {"inbox": root / "in", "outbox": root / "out"}, force_path="batch",
                       memory_limit_bytes=int(sys.argv[2]))
except MemoryLimitReached as err:
    print("stopped:", err, flush=True)
else:
    print("finished", flush=True)
"""


def test_a_stage_that_really_grows_past_a_small_share_is_stopped_cleanly(tmp_path: Path) -> None:
    # The batch path keeps the rows of a row group (a million) until it writes them: 400,000 wide rows are
    # about 120 MB of Arrow data, far more than a share of 40 MB. A process of its own, so that the memory
    # that other tests left to the allocators does not hide the growth.
    (tmp_path / "in").mkdir()
    (tmp_path / "out").mkdir()
    with (tmp_path / "in" / "wide.csv").open("w", encoding="utf-8") as file:
        file.write("id,name\n")
        file.write("".join(f"{n},{n:07d}-{'x' * 290}\n" for n in range(400_000)))
    done = subprocess.run(
        [sys.executable, "-c", REAL, str(tmp_path), "40000000"],
        capture_output=True,
        text=True,
        timeout=SECONDS,
        check=False,
        env={"PATH": "/usr/bin:/bin", "SAFETWIN_HOME": str(tmp_path / "home")},
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.startswith(
        "stopped: the stage of read (source.csv), write (sink.parquet) used more memory than it may "
        "(the limit is 40 MB)"
    ), done.stdout
    assert [path for path in (tmp_path / "out").rglob("*") if path.is_file()] == []  # nothing half-written
    assert "x" * 20 not in done.stdout + done.stderr
    os.remove(tmp_path / "in" / "wide.csv")
