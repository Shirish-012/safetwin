"""The settings of the executor. Standard library only.

`ExecutorSettings.from_defaults()` reads the module's values when it is called, so a test that runs the engine
in a process of its own can change one of them before the engine starts.
"""

from dataclasses import dataclass
from typing import Final

MAX_STAGE_WORKERS: Final = 2  # stage workers that run at once, (docs/internals.md)
WARM_WORKER_S: Final = 60.0  # how long an idle, started worker is kept after a stage ends
CANCEL_GRACE_S: Final = 5.0  # after SIGINT, how long a worker may take to end before it gets SIGKILL
MAX_RUNS_KEPT: Final = 100  # finished runs kept in memory (the metadata database keeps all of them)
MAX_QUEUED_RUNS: Final = 32  # runs that may wait for a free stage worker; more are refused
# How long a new worker may take to import its libraries and say it is ready: about 3 s on the first start,
# and 3-16 s on the first launch after an install, while macOS checks the new files.
WORKER_START_TIMEOUT_S: Final = 60.0
STAGE_EXIT_TIMEOUT_S: Final = 10.0  # after its stage, how long a worker may take to end before SIGKILL
PROGRESS_INTERVAL_S: Final = 0.25  # stage.progress events: at most four a second for each stage
MAX_MESSAGE_BYTES: Final = 1 << 20  # one protocol message (a line of JSON) from a worker
STDERR_BUFFER_BYTES: Final = 64 * 1024  # the last bytes of a worker's stderr, kept in memory only
HISTORY_RUNS_DAYS: Final = 90  # runs that ended longer ago are deleted from the history (docs/internals.md)
PRUNE_INTERVAL_S: Final = 24 * 3600.0  # the history is pruned when the engine starts, then this often


@dataclass(frozen=True)
class ExecutorSettings:
    """The limits of one executor. `memory_limit_bytes` is the engine's global memory limit."""

    memory_limit_bytes: int
    max_stage_workers: int = MAX_STAGE_WORKERS
    warm_worker_s: float = WARM_WORKER_S
    cancel_grace_s: float = CANCEL_GRACE_S
    max_runs_kept: int = MAX_RUNS_KEPT
    max_queued_runs: int = MAX_QUEUED_RUNS
    worker_start_timeout_s: float = WORKER_START_TIMEOUT_S
    stage_exit_timeout_s: float = STAGE_EXIT_TIMEOUT_S
    progress_interval_s: float = PROGRESS_INTERVAL_S

    def __post_init__(self) -> None:
        if self.memory_limit_bytes < 1:
            raise ValueError("the memory limit must be at least one byte")
        if self.max_stage_workers < 1:
            raise ValueError("at least one stage worker must be allowed")

    @property
    def worker_share_bytes(self) -> int:
        """What each running stage worker may use: the global limit split between the most that run."""
        return max(1, self.memory_limit_bytes // self.max_stage_workers)

    def share_for(self, requested_bytes: int | None) -> int:
        """The share of a run that asked for `requested_bytes` (None: no request). A request can only make it
        smaller: the share of a worker is the most any stage gets, so the workers stay within the limit."""
        share = self.worker_share_bytes
        return share if requested_bytes is None else max(1, min(requested_bytes, share))

    @classmethod
    def from_defaults(cls, memory_limit_bytes: int) -> "ExecutorSettings":
        """The settings with this module's values as they are now."""
        return cls(
            memory_limit_bytes=memory_limit_bytes,
            max_stage_workers=MAX_STAGE_WORKERS,
            warm_worker_s=WARM_WORKER_S,
            cancel_grace_s=CANCEL_GRACE_S,
            max_runs_kept=MAX_RUNS_KEPT,
            max_queued_runs=MAX_QUEUED_RUNS,
            worker_start_timeout_s=WORKER_START_TIMEOUT_S,
            stage_exit_timeout_s=STAGE_EXIT_TIMEOUT_S,
            progress_interval_s=PROGRESS_INTERVAL_S,
        )


@dataclass(frozen=True)
class HistorySettings:
    """How long the history of the runs is kept, and how often what is older is deleted."""

    runs_days: int = HISTORY_RUNS_DAYS
    prune_interval_s: float = PRUNE_INTERVAL_S

    @classmethod
    def from_defaults(cls) -> "HistorySettings":
        """The settings with this module's values as they are now."""
        return cls(runs_days=HISTORY_RUNS_DAYS, prune_interval_s=PRUNE_INTERVAL_S)
