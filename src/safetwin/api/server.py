"""The engine process: it binds 127.0.0.1, writes the connection file and serves the control API with uvicorn.

`run_engine` does it all, in this order:

1. Takes the instance lock (`connection.InstanceLock`). If another engine holds it, or the connection file
   names an engine that is alive and answers `GET /v1/status` with its token, it raises `AlreadyRunning`.
   A connection file left by an engine that is gone is replaced.
2. Deletes the temporary folders of stage workers that an engine which did not stop cleanly left in
   `$SAFETWIN_HOME/tmp/` (it holds the lock; a folder whose worker still runs is kept, and deleted two grace
   periods later, by when that worker has ended: `executor.tmp`, `executor.worker`). Opens the metadata
   database (`$SAFETWIN_HOME/metadata.db`) with sqlite3, has the maintenance child migrate it if its schema is
   behind (and prune it when a prune is due, then once a day), and marks the runs that a dead engine left
   unfinished as interrupted (`executor.history`). The control plane never imports SQLAlchemy or Alembic:
   only that child does (`metadata.maintain`). Starts the executor, which
   runs pipelines in stage workers (`safetwin.executor`) with the engine's memory limit (`--memory-limit`;
   a quarter of the memory by default) and keeps their history in the database.
3. Binds a socket to 127.0.0.1 port 0 itself and starts listening, so the port is known (and connections
   wait in the backlog) before the connection file is written. Never 0.0.0.0 or ::.
4. Makes a session token: 32 random bytes (`secrets.token_bytes`), as URL-safe base64.
5. Writes the connection file (mode 0600, atomically) and serves on the socket until it is told to stop:
   `POST /v1/shutdown`, SIGTERM or SIGINT (a second SIGINT stops at once, without waiting for connections).
6. Stopping: every run is cancelled and every stage worker ends (their folders are deleted), WebSocket
   clients get the last events and `shutting_down` and are closed, no connection is accepted any more, open
   requests may finish (5 s at most), and the connection file is removed if it still holds this engine.

Availability. A connection gets `HEAD_TIMEOUT_S` (5 s) to send a request head and the body
`settings.BODY_TIMEOUT_S` (10 s) to arrive, and up to `settings.MAX_CONNECTIONS` (1024) connections may be
open at once; the engine raises its soft file-descriptor limit to `settings.FD_SOFT_LIMIT` (4096) so that it
does not run out of descriptors first (macOS starts processes with 256). Where the limit can't be raised that
far (a lower hard limit), the connections allowed are the soft limit less `FD_RESERVE` (128, for the engine's
own files, pipes to its workers and the like), but never fewer than `MIN_CONNECTIONS` (64)
(`connection_limit`). So hundreds of idle or trickling
connections don't stop the app's requests. What remains: a local process can still open more connections
than the limit, again and again, or use up file descriptors, and the API then answers 503 or nothing until it
stops. That is an availability problem only (the token still guards every request), and one that a loopback
TCP port can't fully prevent: any local process may connect to it.

Logging: one line when the engine starts and one when it stops, on stderr, never with the token. uvicorn's
access log is off (it records client addresses and paths), its error log shows warnings and errors only, and
no log line carries a traceback or the text of an exception: only its type.

The control plane never imports Polars, PyArrow or DuckDB (docs/internals.md): those load only in stage
workers. `engine/tests/api/test_engine_process.py` checks it in a real process.

Run it as `python -m safetwin.api.server [--dev-origin ORIGIN] [--memory-limit SIZE]`, or `safetwin engine
start`.
"""

import argparse
import asyncio
import base64
import logging
import os
import resource
import secrets
import signal
import socket
import sqlite3
import sys
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType

import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol, RequestResponseCycle
from uvicorn.protocols.websockets.websockets_sansio_impl import WebSocketsSansIOProtocol

from safetwin.executor.executor import Executor
from safetwin.executor.history import DbRunStore, metadata_path
from safetwin.executor.settings import ExecutorSettings
from safetwin.executor.tmp import remove_stale
from safetwin.memory import default_memory_limit, parse_size
from safetwin.metadata.lite import MaintenanceFailed
from safetwin.paths import safetwin_home

from .app import create_app, engine_version
from .client import EngineError, get_status
from .connection import (
    ConnectionFileError,
    ConnectionInfo,
    InstanceLock,
    connection_path,
    ensure_home,
    pid_alive,
    read_connection_file,
    remove_connection_file,
    write_connection_file,
)
from .events import Hub
from .settings import FD_SOFT_LIMIT, HEARTBEAT_S, MAX_CONNECTIONS, MAX_WS_MESSAGE_BYTES, allowed_origins

_log = logging.getLogger("safetwin.api.server")  # not __name__: that is __main__ under python -m

HOST = "127.0.0.1"
GRACEFUL_TIMEOUT_S = 5  # how long open requests may take to finish when the engine stops
HEAD_TIMEOUT_S = 5.0  # how long a connection may take to send a whole request head
STATUS_CHECK_TIMEOUT_S = 2.0  # how long the single-instance check waits for an engine that may be running
FD_RESERVE = 128  # file descriptors kept for the engine itself when its soft limit is low
MIN_CONNECTIONS = 64  # the fewest connections allowed at once, however low the limit of descriptors


class AlreadyRunning(Exception):
    """Another engine is running. The message names its pid when it is known."""

    def __init__(self, pid: int | None) -> None:
        self.pid = pid
        super().__init__(
            f"the engine is already running (pid {pid})"
            if pid is not None
            else "the engine is already running, or another one is starting"
        )


def new_token() -> str:
    """A session token: 256 random bits as URL-safe base64, without padding (43 characters)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def running_engine(path: Path) -> ConnectionInfo | None:
    """The engine that the connection file at `path` names, if it is alive and answers with its token.

    A missing, damaged or unsafe file, a pid that is gone, or an engine that does not answer: None (stale).
    """
    try:
        info = read_connection_file(path)
    except ConnectionFileError:
        return None
    if info is None or not pid_alive(info.pid):
        return None
    try:
        status = get_status(info, timeout=STATUS_CHECK_TIMEOUT_S)
    except EngineError:
        return None
    return info if status.pid == info.pid else None


class EngineH11Protocol(H11Protocol):
    """uvicorn's HTTP/1.1 protocol, with a time limit on each request head.

    uvicorn starts no timer before a connection's first response, and any byte it receives stops its
    keep-alive timer, so a connection that sends a request head a byte at a time would hold one of the
    `MAX_CONNECTIONS` slots for as long as it likes (enough of them, and the app would only get 503). Here a
    connection is closed if no new request head has arrived `HEAD_TIMEOUT_S` after it opened or after its
    last response. A connection that became a WebSocket is not touched. The body has a limit of its own in the
    guard (`settings.BODY_TIMEOUT_S`).
    """

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        self._arm_head_timer(None)

    def on_response_complete(self) -> None:
        # The cycle that has just completed is taken before uvicorn's own step: that step goes straight on to
        # a pipelined request that is already buffered, and makes its cycle the current one.
        completed = self.cycle
        super().on_response_complete()
        self._arm_head_timer(completed)

    def _arm_head_timer(self, cycle: RequestResponseCycle | None) -> None:
        self.loop.call_later(HEAD_TIMEOUT_S, self._head_timeout, cycle)

    def _head_timeout(self, cycle: RequestResponseCycle | None) -> None:
        """Close the connection if no request has started since the timer was armed (with `cycle` current)
        and nothing is being served: a request that is being received or answered is never cut off."""
        transport = self.transport
        idle = self.cycle is cycle and (cycle is None or cycle.response_complete)
        if idle and not transport.is_closing() and transport.get_protocol() is self:
            transport.close()


class EngineServer(uvicorn.Server):
    """uvicorn's server, with the engine's way of stopping.

    `run_engine` installs the signal handlers itself, so uvicorn's (which raise the signal again once the
    server has stopped, and so would end the process with it instead of exit status 0) are not used. Before
    uvicorn closes the connections, every WebSocket client gets `shutting_down`.
    """

    def __init__(self, config: uvicorn.Config, hub: Hub, executor: Executor | None = None) -> None:
        super().__init__(config)
        self.hub = hub
        self.executor = executor
        self.stop_reason: str | None = None

    def request_stop(self, reason: str) -> None:
        if self.stop_reason is None:
            self.stop_reason = reason
        self.should_exit = True

    @contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield

    async def shutdown(self, sockets: list[socket.socket] | None = None) -> None:
        if self.executor is not None:  # first, so that the events of the runs it cancels still go out
            await asyncio.to_thread(self.executor.shutdown)
            await asyncio.sleep(0)  # let the events that were handed over reach the clients' queues
        await self.hub.close_all()
        await super().shutdown(sockets=sockets)


def run_engine(
    *,
    dev_origins: Sequence[str] = (),
    home: Path | None = None,
    on_ready: Callable[[ConnectionInfo], object] | None = None,
    heartbeat_s: float = HEARTBEAT_S,
    memory_limit_bytes: int | None = None,
) -> None:
    """Run the engine until it is told to stop, as the module docs say. Returns when it has stopped.

    `dev_origins` are the browser origins it allows (none by default; such as Vite's dev server). `home` is
    the folder of the app (`safetwin_home()` if None). `on_ready` is called with the connection info once the
    connection file is written. `memory_limit_bytes` is the engine's memory limit, split between the stage
    workers that run at once (a quarter of the physical memory if None). Raises `AlreadyRunning`,
    `ConnectionFileError` (the folder of the app or the lock file is not safe to use), `ValueError` for a
    bad dev origin or memory limit, and `MaintenanceFailed` or `sqlite3.Error` if the metadata database can't
    be opened or migrated.
    """
    if memory_limit_bytes is not None and memory_limit_bytes < 1:
        raise ValueError("the memory limit must be at least one byte")
    origins = allowed_origins(tuple(dev_origins))
    home = safetwin_home() if home is None else home
    ensure_home(home)
    path = connection_path(home)
    with InstanceLock(home) as lock:
        if not lock.acquire():
            found = running_engine(path)
            raise AlreadyRunning(found.pid if found is not None else None)
        if (found := running_engine(path)) is not None:  # an engine that does not take the lock
            raise AlreadyRunning(found.pid)
        connections = connection_limit(raise_fd_limit())
        settings = ExecutorSettings.from_defaults(
            default_memory_limit() if memory_limit_bytes is None else memory_limit_bytes
        )
        _, kept = remove_stale(home)
        # A worker of a dead engine that still runs ends by itself within two grace periods (one, unless a
        # commit was under way: `executor.worker`): try again then.
        retry = threading.Timer(
            2 * settings.cancel_grace_s + 5.0, remove_stale, args=(home,), kwargs={"only": kept}
        )
        retry.daemon = True
        if kept:
            retry.start()
        try:
            with (
                _interrupt_on_sigterm()
            ):  # the maintenance child may run here: it must not outlive the engine
                store = DbRunStore.open(metadata_path(home), max_runs=settings.max_runs_kept)
                try:
                    store.start()
                except BaseException:
                    store.close()
                    raise
            try:
                executor = Executor(home, settings, store=store)
                listener = bind_loopback()
                try:
                    executor.start()
                    _serve(listener, path, origins, on_ready, heartbeat_s, executor, connections)
                finally:
                    listener.close()
                    executor.shutdown()
            finally:
                store.close()
        finally:
            # Never after the lock is let go: cancelled, and waited for if it is running just now.
            retry.cancel()
            if retry.is_alive():
                retry.join()


def raise_fd_limit(target: int = FD_SOFT_LIMIT) -> int:
    """Raise the soft limit of open file descriptors to `target` (the hard limit if that is lower).

    It is never lowered. Returns the soft limit after (as it was, if it can't be changed here).
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = target if hard == resource.RLIM_INFINITY else min(hard, target)
    if soft == resource.RLIM_INFINITY or soft >= wanted:
        return soft
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    except (ValueError, OSError):  # not allowed here: the engine runs with what it has
        return soft
    return wanted


def connection_limit(soft_fd_limit: int) -> int:
    """How many connections uvicorn may hold at once with this soft limit of file descriptors (after
    `raise_fd_limit`): `MAX_CONNECTIONS`, or fewer if the descriptors would run out first (`FD_RESERVE` are
    kept for the engine), but at least `MIN_CONNECTIONS`."""
    if soft_fd_limit == resource.RLIM_INFINITY:
        return MAX_CONNECTIONS
    return max(MIN_CONNECTIONS, min(MAX_CONNECTIONS, soft_fd_limit - FD_RESERVE))


def bind_loopback() -> socket.socket:
    """A TCP socket bound to 127.0.0.1 on a port the system picks, listening."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind((HOST, 0))
        listener.listen(1024)  # the system may cap it (somaxconn); uvicorn accepts at once anyway
    except BaseException:
        listener.close()
        raise
    return listener


def _serve(
    listener: socket.socket,
    path: Path,
    origins: tuple[str, ...],
    on_ready: Callable[[ConnectionInfo], object] | None,
    heartbeat_s: float,
    executor: Executor,
    connections: int,
) -> None:
    port = int(listener.getsockname()[1])
    token = new_token()
    info = ConnectionInfo(
        version=engine_version(),
        pid=os.getpid(),
        port=port,
        token=token,
        started_at=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )
    hub = Hub()
    stop: list[Callable[[str], None]] = []  # the server's request_stop, once it exists
    app = create_app(
        token,
        port,
        origins,
        on_shutdown=lambda: stop[0]("requested"),
        heartbeat_s=heartbeat_s,
        hub=hub,
        executor=executor,
    )
    del token
    config = uvicorn.Config(
        app,
        host=HOST,
        port=port,
        http=EngineH11Protocol,
        ws=WebSocketsSansIOProtocol,
        loop="none",  # asyncio.run below
        lifespan="off",
        log_config=None,
        access_log=False,
        proxy_headers=False,  # no X-Forwarded-For: the peer is always this machine
        server_header=False,
        ws_max_size=MAX_WS_MESSAGE_BYTES,
        ws_per_message_deflate=False,
        limit_concurrency=connections,
        timeout_graceful_shutdown=GRACEFUL_TIMEOUT_S,
    )
    server = EngineServer(config, hub, executor)
    stop.append(server.request_stop)
    with _stop_on_signals(server):
        write_connection_file(path, info)
        try:
            _log.info("engine started on %s:%d (pid %d)", HOST, port, info.pid)
            if on_ready is not None:
                on_ready(info)
            asyncio.run(server.serve(sockets=[listener]))
        finally:
            remove_connection_file(path, info)
    _log.info("engine stopped (%s)", server.stop_reason or "server ended")


@contextmanager
def _interrupt_on_sigterm() -> Iterator[None]:
    """While the engine starts, SIGTERM raises `KeyboardInterrupt` (as Ctrl-C does) instead of ending the
    process at once, so that what is under way is cleaned up (the maintenance child is killed) and the lock is
    let go. The handler that was there is put back after."""
    if threading.current_thread() is not threading.main_thread():  # signals reach the main thread only
        yield
        return

    def interrupt(signum: int, frame: FrameType | None) -> None:
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@contextmanager
def _stop_on_signals(server: EngineServer) -> Iterator[None]:
    """SIGTERM and SIGINT stop the server gracefully; a second SIGINT stops it at once."""
    if threading.current_thread() is not threading.main_thread():  # signals reach the main thread only
        yield
        return

    def handle(signum: int, frame: FrameType | None) -> None:
        if server.should_exit and signum == signal.SIGINT:
            server.force_exit = True
        server.request_stop(signal.Signals(signum).name)

    previous = {sig: signal.signal(sig, handle) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


class _NoDetail(logging.Filter):
    """Drops tracebacks and stacks from log records: an exception is shown by its type only."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info:
            kind = record.exc_info[0].__name__ if record.exc_info[0] is not None else "error"
            record.msg = f"{record.getMessage()} ({kind})"
            record.args = None
            record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def configure_logging() -> None:
    """Log the engine's lines and every library's warnings to stderr, without detail; no access log.

    The filtered handler is on the root logger as well, so a logger nobody configured (fastapi, websockets,
    opentelemetry, ...) reaches it instead of Python's last-resort handler, which would print tracebacks.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s safetwin-engine %(levelname)s %(message)s"))
    handler.addFilter(_NoDetail())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.WARNING)
    for name, level in (
        ("safetwin", logging.INFO),
        ("uvicorn", logging.WARNING),
        ("asyncio", logging.WARNING),
    ):
        logger = logging.getLogger(name)
        logger.handlers = [handler]
        logger.setLevel(level)
        logger.propagate = False
    access = logging.getLogger("uvicorn.access")
    access.handlers = []
    access.propagate = False
    access.disabled = True


def ready_line(info: ConnectionInfo) -> str:
    """What `safetwin engine start` prints once the engine runs. Never the token."""
    return f"engine running on {HOST}:{info.port} (pid {info.pid})"


def main(argv: Sequence[str] | None = None) -> int:
    """`python -m safetwin.api.server`: run the engine in the foreground. The exit status."""
    parser = argparse.ArgumentParser(prog="safetwin-engine", description="Run the safetwin engine.")
    parser.add_argument(
        "--dev-origin", action="append", default=[], metavar="ORIGIN", help="Also allow this browser origin."
    )
    parser.add_argument(
        "--memory-limit",
        metavar="SIZE",
        help="The engine's memory limit, such as 4GB, split between the stage workers that run at once. "
        "Default: a quarter of the memory of this machine.",
    )
    options = parser.parse_args(argv)
    try:
        allowed_origins(tuple(options.dev_origin))
    except ValueError as err:
        parser.error(f"--dev-origin: {err}")
    try:
        memory_limit = None if options.memory_limit is None else parse_size(options.memory_limit)
    except ValueError as err:
        parser.error(f"--memory-limit: {err}")
    configure_logging()
    try:
        run_engine(
            dev_origins=options.dev_origin,
            on_ready=lambda info: print(ready_line(info), flush=True),
            memory_limit_bytes=memory_limit,
        )
    except (AlreadyRunning, ConnectionFileError, OSError, MaintenanceFailed, sqlite3.Error) as err:
        print(f"ERROR {start_error(err)}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:  # Ctrl-C or SIGTERM while it started: it cleaned up, and says so in one line
        print("ERROR the engine was stopped while it started", file=sys.stderr)
        return 130
    return 0


def start_error(
    err: AlreadyRunning | ConnectionFileError | OSError | MaintenanceFailed | sqlite3.Error,
) -> str:
    """Why the engine could not start, in one line (an OSError by its reason and file, not its free text; a
    database error by its type)."""
    if isinstance(err, AlreadyRunning | ConnectionFileError | MaintenanceFailed):
        return str(err)
    if isinstance(err, sqlite3.Error):
        return f"the engine could not open its metadata database ({type(err).__name__})"
    reason = os.strerror(err.errno) if err.errno else type(err).__name__
    return f"the engine could not start: {reason}" + (f": {err.filename}" if err.filename else "")


if __name__ == "__main__":
    sys.exit(main())
