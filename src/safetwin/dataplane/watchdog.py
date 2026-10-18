"""The memory watchdog of a stage: a soft limit on the memory a stage may use (docs/internals.md).

Python can't cap its own allocations, so a thread samples the memory of the process while the stage runs. The
stage's memory is how much it has grown since the stage started (the baseline is taken then), so that Python
and the libraries it imported do not count against the stage's share. Locally one stage runs at a time, and
its share is the memory limit of the run (`--memory-limit`, a quarter of the memory by default); T5 will split
the limit between worker processes, which is why the share is a parameter. DuckDB gets 80% of the share
(`spill.SpillSettings.duckdb_memory_bytes`), so that its own clear `OutOfMemory` normally comes first.

The states, with the share as 100%:

    running ──(≥ 90%)──▶ paused ──(< 80%)──▶ running        any state ──(≥ 100%)──▶ stopped

- **paused**: the sources of the stage wait (backpressure) and what is already in flight drains to the sink.
  A stage that stays paused for `max_pause_s` (30 s) without getting back under 80% is stopped as well: the
  memory is held by something that is not draining (a sort in DuckDB that waits for the rest of its input,
  say), and waiting longer would only hang the run.
- **stopped**: the stage fails with `MemoryLimitReached`, whose message names the nodes and the share and
  says what to do. It is final.

A stage never waits for a watchdog that is gone: if the thread ends without being closed (its sampler failed,
or it could not start), a pause is let go and the stage goes on unwatched; `check` waits in slices of 0.25 s
and looks each time whether the thread is still there.

How each path obeys:

- **fused**: the query passes a counter after every node (`StageMeter.counter`, a `map_batches` function).
  Every counter raises when the stage is stopped; only the first one, at the source's side, waits while it is
  paused, so the source stops and what has passed it goes on to the sink. Measured with Polars 1.44: the
  threads of Polars' engine can all wait inside `map_batches`, and the query goes on when they are let
  go, with every row (`test_watchdog.py` pauses a real query in the middle, sees the rows that were past the
  source reach the next node, resumes it, with a time limit). Nothing deadlocks, because the waiting releases
  the GIL and the thread that lets them go is the watchdog's, not one of Polars'.
- **batch**: the reader thread waits before it reads the next batch, and the writer drains the bounded queue.
  It also writes the rows of the row group it is collecting (up to a million) as a row group of their own, so
  that they leave memory: the file has the same rows in the same order, in more row groups. The writer and
  the reader raise when stopped.
- **hybrid**: the Polars query before DuckDB obeys as the fused path does, and what has passed its first
  counter goes on into DuckDB. A sort in DuckDB holds its rows until its input ends, so a pause does not
  free them (the 30 s limit then stops the stage). When the stage is stopped the watchdog also calls
  `interrupt()` on the DuckDB connection of the stage and on each of its cursors, so that a sort that is
  running in DuckDB ends at once. A stage that reads what an earlier stage wrote and has no Polars step
  before DuckDB (and a fused stage that reads it and has no step) has no counter to wait in: it is only
  stopped, never paused.

Whatever the stage was doing when it was stopped fails with some error of its own (Polars raises what the
counter raised; DuckDB says it was interrupted): `watching` turns any error of a stopped stage into
`MemoryLimitReached`, and the paths' own cleanup leaves nothing behind (no file, no temporary file, no
manifest).

**What "memory" is.** Measured on an Apple M4 (macOS, 16 GB) with Polars 1.44, a fused CSV → filter + trim →
Parquet run, sampled every 20 ms (the growth is over the memory at the start of the run):

    input                      rss growth   uss growth   phys_footprint growth
    409 MB CSV, 8M rows          777 MB       814 MB        408 MB
    1.56 GB CSV, 30M rows       1983 MB      2006 MB        477 MB

rss and uss count the pages of the input file that Polars maps into memory: they grow with the file, though
those pages are clean and the system takes them back whenever it needs to. `phys_footprint` (what Activity
Monitor calls "Memory") counts what the process really holds and stays bounded. One sample costs about 1 µs
for rss and phys_footprint and 0.3 ms for uss when the process is idle, and about 50 µs, 250 µs and 2.4 ms
while all ten cores run the query. So on macOS the watchdog samples `phys_footprint` (from `proc_pid_rusage`,
through ctypes: psutil does not expose it); elsewhere it samples rss less the shared pages on Linux and rss on
other systems. The memory that the allocators of Polars and Arrow keep after one stage, to use again, is in
the baseline of the next: the growth of a later stage can be less than what it uses, never more.

Spike B (`test_perf.py`, `SAFETWIN_BIG_GB=4`), the same fused run on a 3.96 GB CSV of 79M rows: 10.5 s (7.5M
rows/s), a peak stage memory (phys_footprint growth) of 282 MB, and a peak RSS of 3.6 GB. Polars' engine keeps
the memory bounded; rss would have stopped that stage under any share below 3.5 GB.

Limits. A sample every 100 ms can miss a stage that is over sooner (a tenth of a second can be 300 MB). And
Ctrl-C while a fused or hybrid stage is paused takes effect only when the pause ends (at most `max_pause_s`):
Polars, told to stop, waits for its threads, which wait in the counters. The batch path ends at once.
"""

import logging
import os
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from typing import Final, Literal

from safetwin.memory import Sampler as Sampler  # the type the stages pass in; re-exported
from safetwin.memory import footprint_sampler, resident_sampler

from .spill import format_size

_log = logging.getLogger(__name__)

State = Literal["running", "paused", "stopped"]

INTERVAL_S = 0.1  # a sample every 100 ms
# For tests only: a test that runs `safetwin` in a process of its own (tests/leak) sets this to sample more
# often, so that a stage that is over in a tenth of a second is still watched. It changes how often the memory
# is sampled and nothing else; a value that is not a number from 0.001 to 1 is ignored.
TEST_INTERVAL_ENV: Final = "SAFETWIN_TEST_WATCHDOG_INTERVAL_S"
PAUSE_AT: Final = 0.90  # of the share
RESUME_BELOW: Final = 0.80
MAX_PAUSE_S = 30.0
WAIT_SLICE_S = 0.25  # a stage that waits looks this often whether the thread of the watchdog is still there


class MemoryLimitReached(RuntimeError):
    """A stage used more than its share of memory and was stopped. The message is safe to show.

    It names the nodes of the stage and the share, never data and never what a library said.
    """


def memory_limit_reached(share_bytes: int, what: str) -> MemoryLimitReached:
    """The error for `what` (such as "the stage of read (source.csv), ...") that reached its share."""
    return MemoryLimitReached(
        f"{what} used more memory than it may (the limit is {format_size(share_bytes)}), so it was stopped. "
        "Raise the memory limit (--memory-limit), or add a filter before the heavy step or select fewer "
        "columns so that less data reaches it."
    )


_warned_rss = False


def process_memory_sampler() -> Sampler:
    """The sampler of the memory of this process that the module docs explain (see `safetwin.memory`).

    On macOS, if the footprint can't be read, it says so once (a warning of the logger of this module, with no
    data in it) and samples rss, which also counts the pages of a mapped input file.
    """
    global _warned_rss
    footprint = footprint_sampler()
    if footprint is not None:
        return footprint
    if sys.platform == "darwin" and not _warned_rss:
        _warned_rss = True
        _log.warning("memory footprint unavailable; using rss")
    return resident_sampler()


class Watchdog:
    """Samples the memory of a stage on a thread of its own and says whether the stage may go on.

    `share_bytes` is what the stage may grow by; `what` names the stage for the error. `sampler` gives the
    memory of the process (`process_memory_sampler()` if it is None): tests drive the watchdog with one of
    their own. `start` takes the baseline and starts the thread (a daemon), `close` ends it and lets go of
    every thread that waits; use `watching` so that it ends however the stage ends.

    `check` is what the stage calls: it waits while the watchdog is paused and raises `MemoryLimitReached`
    once it is stopped. `observe` is one step of the state machine, for a sample of the process memory; the
    thread calls it, and tests can call it without a thread.
    """

    def __init__(
        self,
        share_bytes: int,
        what: str,
        *,
        sampler: Sampler | None = None,
        interval: float | None = None,
        max_pause_s: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if share_bytes < 1:
            raise ValueError("the share must be at least one byte")
        self.share_bytes = share_bytes
        self._what = what
        self._sampler = sampler
        self._interval = _default_interval() if interval is None else interval
        self._max_pause_s = MAX_PAUSE_S if max_pause_s is None else max_pause_s
        self._clock = clock
        self._state: State = "running"
        self._baseline: int | None = None
        self._memory = 0
        self._peak = 0
        self._paused_since = 0.0
        self.pauses = 0  # how many times the stage was paused
        self._closed = False
        self._started = False
        self._gone = False  # the thread ended without being closed (its sampler failed, say)
        self._hooks: list[Callable[[], object]] = []
        self._changed = threading.Condition()
        self._thread: threading.Thread | None = None

    @property
    def state(self) -> State:
        with self._changed:
            return self._state

    @property
    def memory_bytes(self) -> int:
        """The stage's memory at the last sample: what the process has grown by since the start (≥ 0)."""
        with self._changed:
            return self._memory

    @property
    def peak_bytes(self) -> int:
        """The most the stage's memory was at any sample."""
        with self._changed:
            return self._peak

    def start(self) -> None:
        """Take the baseline and a first sample, then sample on a thread every `interval` seconds.

        The first sample is taken here, before the stage moves any data, so that a test's sampler that says
        "paused" from the start is obeyed from the first batch.
        """
        if self._sampler is None:
            self._sampler = process_memory_sampler()
        self._started = True  # from now on `check` waits only while a thread is there to end the wait
        self._baseline = self._sampler()
        self.observe(self._sampler())
        thread = threading.Thread(target=self._run, name="safetwin-watchdog", daemon=True)
        with self._changed:
            self._thread = thread
        try:
            thread.start()
        except BaseException:
            self._give_up()
            raise

    def close(self) -> None:
        """Stop sampling and let go of every thread that waits in `check`. Can be called more than once."""
        with self._changed:
            self._closed = True
            self._changed.notify_all()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join()

    def on_stop(self, hook: Callable[[], object]) -> None:
        """Call `hook` (from the thread of the watchdog) when the stage is stopped; at once if it is already.

        What the hook raises is ignored: it is called to end work that may have ended already.
        """
        with self._changed:
            stopped = self._state == "stopped"
            if not stopped:
                self._hooks.append(hook)
        if stopped:
            _call(hook)

    def check(self, *, wait: bool = True) -> None:
        """Wait while the stage is paused (unless `wait` is false), and raise `MemoryLimitReached` if it is
        stopped. Returns at once once the watchdog is closed.

        A started watchdog whose thread is gone (its sampler failed, or it could not start) has nobody left to
        end a pause, so then the stage is not kept waiting: the wait is done in slices, and each slice looks.
        """
        with self._changed:
            while wait and self._state == "paused" and not self._closed and not self._orphaned():
                self._changed.wait(WAIT_SLICE_S)
            if self._state == "stopped":
                raise self.error()

    def _orphaned(self) -> bool:  # the lock is held
        if not self._started:
            return False  # driven by `observe` alone (tests): whoever calls observe ends the pause
        return self._gone or self._thread is None or not self._thread.is_alive()

    def _give_up(self) -> None:
        """The thread is gone, or never came: no pause can end any more, so none is kept."""
        with self._changed:
            self._gone = True
            if self._state == "paused":
                self._state = "running"
            self._changed.notify_all()

    def error(self) -> MemoryLimitReached:
        return memory_limit_reached(self.share_bytes, self._what)

    def observe(self, total: int) -> State:
        """Take a sample (the memory of the process, in bytes) and move to the state that it calls for."""
        hooks: list[Callable[[], object]] = []
        with self._changed:
            if self._baseline is None:
                self._baseline = total
            self._memory = max(0, total - self._baseline)
            self._peak = max(self._peak, self._memory)
            share = self._memory / self.share_bytes
            before = self._state
            now = self._clock()
            if before == "stopped":
                return before
            if share >= 1.0 or (before == "paused" and now - self._paused_since >= self._max_pause_s):
                self._state = "stopped"
                hooks, self._hooks = self._hooks, []
            elif before == "running" and share >= PAUSE_AT:
                self._state = "paused"
                self._paused_since = now
                self.pauses += 1
            elif before == "paused" and share < RESUME_BELOW:
                self._state = "running"
            if self._state != before:
                self._changed.notify_all()
            state = self._state
        for hook in hooks:
            _call(hook)
        return state

    def _run(self) -> None:
        try:
            self._sample_until_closed()
        finally:  # however the thread ends, a stage that is paused must not wait for it
            self._give_up()

    def _sample_until_closed(self) -> None:
        sampler = self._sampler
        assert sampler is not None
        while True:
            with self._changed:
                if self._closed or self._state == "stopped":
                    return
                self._changed.wait(self._interval)
                if self._closed:
                    return
            try:
                total = sampler()
            except Exception:  # the memory can't be read here: the stage goes on without a watchdog
                return
            self.observe(total)


def _default_interval() -> float:
    """INTERVAL_S, unless a test asked for another one with `TEST_INTERVAL_ENV`."""
    try:
        configured = float(os.environ.get(TEST_INTERVAL_ENV, ""))
    except ValueError:
        return INTERVAL_S
    return configured if 0.001 <= configured <= 1.0 else INTERVAL_S


def _call(hook: Callable[[], object]) -> None:
    with suppress(Exception):
        hook()


@contextmanager
def watching(watchdog: Watchdog) -> Iterator[Watchdog]:
    """Start `watchdog`, and close it when the block ends, however it ends.

    An error of a stage that the watchdog stopped is raised as `MemoryLimitReached` (what the stage raised
    because it was stopped says nothing more, and can quote data). `KeyboardInterrupt` is raised as it is.
    """
    watchdog.start()
    try:
        yield watchdog
    except Exception as err:
        watchdog.close()
        if watchdog.state == "stopped" and not isinstance(err, MemoryLimitReached):
            raise watchdog.error() from None
        raise
    finally:
        watchdog.close()
