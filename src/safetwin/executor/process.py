"""A stage worker as the control plane sees it: the child process, its pipes and its temporary folder.

`WorkerProcess` starts `worker_command()` with an explicit argv and environment: the engine's environment,
with TMPDIR, TMP, TEMP and POLARS_TEMP_DIR set to the worker's private folder (`tmp.make_worker_tmp`), and its
working folder there too. The worker gets a session of its own (`start_new_session`), so a Ctrl-C in the
terminal of an engine that runs in the foreground reaches the engine only, which then cancels its runs.

- stdin and stdout carry the protocol (`protocol.py`), one JSON message per line. A line longer than
  `MAX_MESSAGE_BYTES` or a message that does not fit is a `ProtocolError`.
- stderr is read on a thread of its own into a bounded buffer (the last `STDERR_BUFFER_BYTES`), which is never
  printed, logged or written anywhere, and is dropped when the worker ends: a library's message there could
  quote data. When a worker ends badly, what is reported is its exit code or its signal, nothing else.
- `finish` waits for the worker to end (SIGKILL after a timeout), closes the pipes and deletes the folder,
  however the worker ended (it may have been killed with SIGKILL, by the user or the system).

Standard library and pydantic only.
"""

import os
import secrets
import select
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path

from .protocol import (
    Failed,
    PlanDone,
    PlanJob,
    Progress,
    ProtocolError,
    Ready,
    StageDone,
    StageJob,
    decode_worker_message,
    encode,
)
from .settings import CANCEL_GRACE_S, MAX_MESSAGE_BYTES, STDERR_BUFFER_BYTES
from .tmp import make_worker_tmp, remove_tree, remove_worker_files, write_worker_pid

GRACE_ENV = "SAFETWIN_WORKER_CANCEL_GRACE_S"  # how long an orphaned worker waits after SIGINT (`worker.py`)

WorkerMessage = Ready | PlanDone | Progress | StageDone | Failed
TEMP_VARIABLES = ("TMPDIR", "TMP", "TEMP", "POLARS_TEMP_DIR")


def worker_command() -> list[str]:
    """How a stage worker is started: this Python with the worker module, or, in a frozen build (whose
    executable is the engine itself), the executable with the `worker` command."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "worker"]
    return [sys.executable, "-m", "safetwin.executor.worker"]


def worker_environment(tmp: Path, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment of a worker: `base` (the engine's), with the temporary folders set to `tmp`."""
    env = dict(os.environ if base is None else base)
    for name in TEMP_VARIABLES:
        env[name] = str(tmp)
    return env


def new_worker_id() -> str:
    return f"w{secrets.token_hex(4)}"


class WorkerStopped(Exception):
    """The worker ended (or closed its pipes) before it said what it was asked. `exit` is its exit code or
    signal, as `describe_exit` says it, once it is known."""

    def __init__(self, exit: str | None) -> None:
        self.exit = exit
        super().__init__(f"the stage worker stopped ({exit})" if exit else "the stage worker stopped")


def describe_exit(returncode: int | None) -> str | None:
    """`signal 9` or `exit code 1`; None while the process runs."""
    if returncode is None:
        return None
    return f"signal {-returncode}" if returncode < 0 else f"exit code {returncode}"


class WorkerProcess:
    """One stage worker. Made by the executor, which uses it from one thread at a time; `interrupt` and
    `kill` may come from any thread."""

    def __init__(
        self,
        home: Path,
        *,
        command: Sequence[str] | None = None,
        env: Mapping[str, str] | None = None,
        grace_s: float = CANCEL_GRACE_S,
    ) -> None:
        self.home = home
        self.worker_id = new_worker_id()
        self.tmp = make_worker_tmp(home, self.worker_id)
        self.started = time.monotonic()
        try:
            self.process = subprocess.Popen(
                list(command or worker_command()),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**worker_environment(self.tmp, env), GRACE_ENV: f"{grace_s:g}"},
                cwd=self.tmp,
                start_new_session=True,
                close_fds=True,
            )
        except BaseException:
            remove_tree(self.tmp)
            raise
        with suppress(OSError):  # without it, a later engine just doesn't know the folder's worker still runs
            write_worker_pid(home, self.worker_id, self.process.pid)
        self._buffer = b""
        self._stderr = bytearray()
        self._stderr_lock = threading.Lock()
        self._ready: Ready | None = None
        self._finished = False
        self._finish_lock = threading.Lock()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, name="safetwin-worker-stderr", daemon=True
        )
        self._stderr_thread.start()

    @property
    def pid(self) -> int:
        return self.process.pid

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    @property
    def ready(self) -> Ready | None:
        """The ready message, once `wait_ready` has read it."""
        return self._ready

    def exit_description(self) -> str | None:
        return describe_exit(self.process.poll())

    def stderr_bytes(self) -> int:
        """How many bytes of stderr are held (for tests: the bytes themselves are never handed out)."""
        with self._stderr_lock:
            return len(self._stderr)

    # --- the protocol ---------------------------------------------------------------------------------------

    def wait_ready(self, timeout: float) -> Ready:
        """Wait until the worker has imported its libraries. Raises `WorkerStopped`, `TimeoutError` or
        `ProtocolError`."""
        if self._ready is not None:
            return self._ready
        message = self.receive(timeout)
        if not isinstance(message, Ready):
            raise ProtocolError("the stage worker did not start as it should")
        self._ready = message
        return message

    def send(self, job: PlanJob | StageJob) -> None:
        """Send a job. Raises `WorkerStopped` if the worker is gone (the job was not delivered), and
        `ProtocolError` for a job longer than `MAX_MESSAGE_BYTES`."""
        data = encode(job)
        if len(data) > MAX_MESSAGE_BYTES:
            raise ProtocolError("the job is too large for the protocol")
        stdin = self.process.stdin
        if stdin is None or stdin.closed:
            raise WorkerStopped(self.exit_description())
        try:
            stdin.write(data)
            stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            raise WorkerStopped(self.exit_description()) from None

    def receive(self, timeout: float | None = None) -> WorkerMessage:
        """The next message of the worker (`protocol.decode_worker_message`).

        Raises `WorkerStopped` at the end of its stdout (it ended, or is ending), `TimeoutError` if no whole
        message came within `timeout` seconds (None: wait as long as it takes), and `ProtocolError` for a
        line that is too long or a message that does not fit.
        """
        stdout = self.process.stdout
        if stdout is None:
            raise WorkerStopped(self.exit_description())
        fd = stdout.fileno()
        deadline = None if timeout is None else time.monotonic() + timeout
        while b"\n" not in self._buffer:
            if len(self._buffer) > MAX_MESSAGE_BYTES:
                raise ProtocolError("a message from the stage worker is too long")
            remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                raise TimeoutError("the stage worker said nothing in time")
            chunk = os.read(fd, 65536)
            if not chunk:
                self._buffer = b""
                with suppress(subprocess.TimeoutExpired):
                    self.process.wait(timeout=1.0)  # a process that closed its stdout is usually ending
                raise WorkerStopped(self.exit_description())
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        if len(line) > MAX_MESSAGE_BYTES:
            raise ProtocolError("a message from the stage worker is too long")
        return decode_worker_message(line)

    # --- ending it ------------------------------------------------------------------------------------------

    def close_stdin(self) -> None:
        """Tell the worker there is nothing more for it: it ends when it has read everything."""
        stdin = self.process.stdin
        if stdin is not None:
            with suppress(OSError, ValueError):
                stdin.close()

    def interrupt(self) -> None:
        """SIGINT: the worker cancels what it does and ends."""
        self._signal(signal.SIGINT)

    def kill(self) -> None:
        """SIGKILL, if it still runs."""
        self._signal(signal.SIGKILL)

    def _signal(self, signum: signal.Signals) -> None:
        if self.process.poll() is None:
            with suppress(ProcessLookupError, OSError):
                self.process.send_signal(signum)

    def finish(self, timeout: float) -> str:
        """Wait for the worker to end (SIGKILL after `timeout` seconds), close its pipes, drop its stderr and
        delete its folder. Returns how it ended (`describe_exit`). Can be called more than once."""
        with self._finish_lock:
            self.close_stdin()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.kill()
                self.process.wait()
            if not self._finished:
                self._finished = True
                self._stderr_thread.join(timeout=5.0)
                for pipe in (self.process.stdout, self.process.stderr):
                    if pipe is not None:
                        with suppress(OSError):
                            pipe.close()
                with self._stderr_lock:
                    self._stderr.clear()
                remove_worker_files(self.home, self.worker_id)
            return describe_exit(self.process.returncode) or "exit code 0"

    def _drain_stderr(self) -> None:
        """Keep the last bytes of stderr in memory, so the worker never blocks on a full pipe."""
        stderr = self.process.stderr
        if stderr is None:
            return
        with suppress(OSError, ValueError):
            fd = stderr.fileno()
            while chunk := os.read(fd, 65536):
                with self._stderr_lock:
                    self._stderr += chunk
                    if len(self._stderr) > STDERR_BUFFER_BYTES:
                        del self._stderr[: len(self._stderr) - STDERR_BUFFER_BYTES]
