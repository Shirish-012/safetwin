"""The engine in a process of its own, served by uvicorn: what the ASGI tests can't see.

- The control plane never imports Polars, PyArrow or DuckDB (docs/internals.md), nor SQLAlchemy or Alembic
  (only the metadata database's maintenance child does: `metadata.maintain`), after startup (which migrates
  a new database in that child), after `/v1/validate`, after a whole run through `/v1/runs` (its stage
  workers load the data libraries, not the engine), after reading the run back from the history, and after a
  prune of the history (in that child too).
- The checks hold over real HTTP and a real WebSocket, and uvicorn caps the size of a WebSocket message.
- SIGTERM and SIGINT stop it with exit status 0, `shutting_down` reaches the WebSocket clients, and the
  connection file is removed.
- The log has the start and stop lines and nothing else: no token, no path, no client address.
"""

import http.client
import json
import os
import re
import resource
import select
import signal
import socket
import sqlite3
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from pathlib import Path

import pytest
from websockets.exceptions import ConnectionClosed
from websockets.sync.client import ClientConnection, connect

from safetwin.api.connection import ConnectionInfo, connection_path, read_connection_file
from safetwin.api.settings import FD_SOFT_LIMIT, MAX_CONNECTIONS

REPO = Path(__file__).resolve().parents[2]
HEAVY = ("polars", "pyarrow", "duckdb", "sqlalchemy", "alembic")
SECONDS = 30

# Runs the engine as `python -m safetwin.api.server` does. An import finder placed first refuses Polars,
# PyArrow and DuckDB (an import of one fails where it happens) and records every attempt. Once the engine is
# ready, and once it has stopped, the driver prints the heavy modules that are loaded, the attempts, and the
# OpenTelemetry SDK modules that are loaded (none: FastAPI's telemetry is off and the SDK is not installed).
DRIVER = """
import json, resource, sys

HEAVY = {heavy!r}
attempts = []

class RefuseHeavy:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in HEAVY:
            attempts.append(name)
            raise ImportError("the control plane imported " + name)
        return None

sys.meta_path.insert(0, RefuseHeavy())

from safetwin.api import server

def report(when):
    return json.dumps({{
        "when": when,
        "loaded": sorted(name for name in sys.modules if name.split(".")[0] in HEAVY),
        "attempts": attempts,
        "otel_sdk": sorted(name for name in sys.modules if name.startswith("opentelemetry.sdk")),
        "nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
        "limit_concurrency": limits[-1] if limits else None,
    }})

from safetwin.executor import settings
settings.PRUNE_INTERVAL_S = {prune_interval}
server.HEAD_TIMEOUT_S = {head_timeout}
server.MAX_CONNECTIONS = {max_connections}
limits = []
connection_limit = server.connection_limit
server.connection_limit = lambda soft: limits.append(connection_limit(soft)) or limits[-1]
if {fd_limit}:
    resource.setrlimit(resource.RLIMIT_NOFILE, ({fd_limit}, {fd_limit}))
server.configure_logging()
server.run_engine(
    dev_origins=[{dev_origin!r}], heartbeat_s=0.2, on_ready=lambda info: print(report("ready"), flush=True)
)
print(report("stopped"), flush=True)
"""
CLEAN = {"loaded": [], "attempts": [], "otel_sdk": []}
DEV_ORIGIN = "http://localhost:5173"  # the one browser origin the engine of these tests allows


@dataclass
class Engine:
    process: subprocess.Popen[str]
    info: ConnectionInfo
    ready: dict[str, object]

    def request(
        self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.info.port, timeout=10)
        try:
            connection.request(method, path, body=body, headers=self.auth() if headers is None else headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.info.token}"}

    def websocket(self, **options: object) -> ClientConnection:
        return connect(f"ws://127.0.0.1:{self.info.port}/v1/events", open_timeout=5, **options)  # type: ignore[arg-type]

    def stop(self, how: signal.Signals | None = None) -> tuple[str, str]:
        """Stop it (POST /v1/shutdown, or a signal) and return what it printed."""
        if how is None:
            assert self.request("POST", "/v1/shutdown")[0] == 202
        else:
            self.process.send_signal(how)
        try:
            return self.process.communicate(timeout=SECONDS)
        except subprocess.TimeoutExpired:
            self.process.kill()
            pytest.fail("the engine did not stop")


@pytest.fixture
def engine(request: pytest.FixtureRequest, tmp_path: Path, safetwin_home: Path) -> Iterator[Engine]:
    """The engine in a process of its own. Parametrize it (indirect) with a dict to change its settings:
    `head_timeout` (seconds, instead of 5) and `max_connections` (instead of `settings.MAX_CONNECTIONS`)."""
    script = tmp_path / "driver.py"
    options = {
        "head_timeout": 5.0,
        "max_connections": MAX_CONNECTIONS,
        "fd_limit": 0,
        "prune_interval": 86400.0,
        **getattr(request, "param", {}),
    }
    script.write_text(DRIVER.format(heavy=HEAVY, dev_origin=DEV_ORIGIN, **options))
    process = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "SAFETWIN_HOME": str(safetwin_home)},
    )
    try:
        assert process.stdout is not None
        line = process.stdout.readline()
        assert line, process.stderr.read() if process.stderr else ""
        found = read_connection_file(connection_path(safetwin_home))
        assert found is not None
        yield Engine(process, found, json.loads(line))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        for pipe in (process.stdout, process.stderr):
            if pipe is not None:
                pipe.close()


def received_until_closed(ws: ClientConnection) -> tuple[list[dict[str, object]], int | None]:
    """The events a socket gets until the server closes it, and the close code."""
    messages = []
    while True:
        try:
            messages.append(json.loads(ws.recv(timeout=5)))
        except ConnectionClosed as closed:
            return messages, closed.rcvd.code if closed.rcvd is not None else None


CSV_CLEAN = (REPO / "tests" / "fixtures" / "csv-clean.yaml").read_text()
INVALID = {
    "unknown_operator": CSV_CLEAN.replace("transform.filter", "transform.nope"),
    "extra_forbidden": CSV_CLEAN.replace("  sockets:", "  mode: batch\n  sockets:"),
    "yaml_error": CSV_CLEAN.replace("columns: [name, city]", "columns: [name, city"),
    # transform.sql with a config that is wrong for it (its config is checked when the stage runs, but the
    # node must still not pull DuckDB in to be validated)
    "sql_config": CSV_CLEAN.replace("operator: transform.filter", "operator: transform.sql").replace(
        'expr: "id IS NOT NULL"', "sql: 42\n        nope: [1]"
    ),
}


def prunes(home: Path) -> int:
    """How many times the history was pruned: its audit events."""
    connection = sqlite3.connect(home / "metadata.db")
    try:
        return int(
            connection.execute(
                "SELECT count(*) FROM audit_events WHERE action = 'retention.prune'"
            ).fetchone()[0]
        )
    finally:
        connection.close()


@pytest.mark.parametrize("engine", [{"prune_interval": 1.0}], indirect=True)
def test_the_control_plane_never_loads_polars_pyarrow_or_duckdb(
    engine: Engine, tmp_path: Path, safetwin_home: Path
) -> None:
    assert {key: engine.ready[key] for key in CLEAN} == CLEAN
    for example in sorted((REPO / "tests" / "fixtures").glob("*.yaml")):
        status, body = engine.request("POST", "/v1/validate", example.read_bytes())
        assert status == 200
        assert json.loads(body)["valid"] is True, example
    for code, text in INVALID.items():
        status, body = engine.request("POST", "/v1/validate", text.encode())
        assert status == 200, code
        answer = json.loads(body)
        if code != "sql_config":
            assert answer["valid"] is False, code
            assert code in {problem["code"] for problem in answer["problems"]}, answer
    assert engine.request("GET", "/v1/status")[0] == 200
    with engine.websocket() as ws:
        ws.send(engine.info.token)
        assert json.loads(ws.recv(timeout=5))["type"] == "hello"
        assert json.loads(ws.recv(timeout=5))["type"] == "heartbeat"
        # A whole run, in a stage worker (which loads them all), with its events.
        inbox, outbox = tmp_path / "in", tmp_path / "out"
        inbox.mkdir()
        outbox.mkdir()
        (inbox / "people.csv").write_text("id,name,city\n1, a ,x\n,b,y\n3,c , z\n")
        request = {"pipeline_yaml": CSV_CLEAN, "sockets": {"inbox": str(inbox), "outbox": str(outbox)}}
        status, body = engine.request(
            "POST",
            "/v1/runs",
            json.dumps(request).encode(),
            headers={**engine.auth(), "Content-Type": "application/json"},
        )
        assert status == 202, body
        run_id = json.loads(body)["run_id"]
        while (event := json.loads(ws.recv(timeout=SECONDS)))["type"] not in ("run.finished", "run.failed"):
            pass
        assert event["type"] == "run.finished"
        assert event["data"]["run_id"] == run_id
    status, body = engine.request("GET", f"/v1/runs/{run_id}")
    assert json.loads(body)["stages"][0]["rows_per_node"]["write_parquet"] == 2
    # The history (the metadata database, with SQLAlchemy) is read without them too.
    status, body = engine.request("GET", "/v1/runs?state=succeeded&limit=5")
    assert status == 200
    assert [run["run_id"] for run in json.loads(body)["runs"]] == [run_id]
    # A prune of the history, a second after the one at the start (the interval is 1 s here).
    deadline = time.monotonic() + SECONDS
    while prunes(safetwin_home) < 2:
        assert time.monotonic() < deadline, "the history was not pruned again"
        time.sleep(0.05)
    out, _ = engine.stop()
    stopped = json.loads(out.splitlines()[-1])
    assert stopped["when"] == "stopped"
    assert {key: stopped[key] for key in CLEAN} == CLEAN


def test_unconfigured_loggers_print_no_traceback_and_no_exception_text(tmp_path: Path) -> None:
    script = (
        "import logging\n"
        "from safetwin.api.server import configure_logging\n"
        "configure_logging()\n"
        "for name in ('fastapi', 'websockets.server', 'opentelemetry', 'some.library'):\n"
        "    try:\n"
        "        raise ValueError('CANARY-in-an-exception')\n"
        "    except ValueError:\n"
        "        logging.getLogger(name).exception('a library failed')\n"
        "logging.getLogger('some.library').info('quiet')\n"
    )
    done = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=SECONDS, check=False
    )
    assert done.returncode == 0, done.stderr
    lines = done.stderr.splitlines()
    assert len(lines) == 4, done.stderr
    assert all(line.endswith("ERROR a library failed (ValueError)") for line in lines)
    assert "Traceback" not in done.stderr
    assert "CANARY" not in done.stderr


def test_the_checks_hold_over_real_http(engine: Engine) -> None:
    port = engine.info.port
    assert engine.request("GET", "/v1/status")[0] == 200
    assert engine.request("GET", "/v1/status", headers={})[0] == 401
    assert engine.request("GET", "/v1/status", headers={**engine.auth(), "Host": "evil.com"}) == (
        400,
        b'{"error": "bad_host"}',
    )
    assert (
        engine.request("GET", "/v1/status", headers={**engine.auth(), "Host": f"localhost:{port}"})[0] == 200
    )
    assert (
        engine.request("GET", "/v1/status", headers={**engine.auth(), "Origin": "https://evil.com"})[0] == 403
    )
    status, _ = engine.request("POST", "/v1/validate", b"x" * (1024 * 1024 + 1))
    assert status == 413
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:  # an HTTP/1.0 request has no Host
        raw.sendall(f"GET /v1/status HTTP/1.0\r\nAuthorization: Bearer {engine.info.token}\r\n\r\n".encode())
        assert raw.recv(100).startswith(b"HTTP/1.1 400")


def test_a_real_websocket_gets_hello_heartbeats_and_shutting_down(engine: Engine) -> None:
    with engine.websocket() as ws:
        ws.send(engine.info.token)
        hello = json.loads(ws.recv(timeout=5))
        assert hello["type"] == "hello"
        assert hello["data"]["pid"] == engine.info.pid
        assert json.loads(ws.recv(timeout=5))["type"] == "heartbeat"
        engine.stop(signal.SIGTERM)
        messages, code = received_until_closed(ws)
        assert code == 1001
        assert messages[-1]["type"] == "shutting_down"
    assert engine.process.returncode == 0


def test_a_real_websocket_is_refused_for_a_bad_origin_or_token_and_its_messages_are_capped(
    engine: Engine,
) -> None:
    from websockets.exceptions import InvalidStatus

    with pytest.raises(InvalidStatus) as refused, engine.websocket(origin="https://evil.com"):
        pass
    assert refused.value.response.status_code == 403
    with engine.websocket() as ws:
        ws.send("not the token")
        assert received_until_closed(ws) == ([], 1008)
    with engine.websocket(origin=DEV_ORIGIN) as ws:
        ws.send(engine.info.token)
        assert json.loads(ws.recv(timeout=5))["type"] == "hello"
        ws.send("x" * 10_000)  # over the 4 KiB a client may send
        assert received_until_closed(ws)[1] == 1009


@pytest.mark.parametrize("how", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_stops_the_engine_with_status_0_and_removes_the_connection_file(
    engine: Engine, safetwin_home: Path, how: signal.Signals
) -> None:
    path = connection_path(safetwin_home)
    assert path.exists()
    _, err = engine.stop(how)
    assert engine.process.returncode == 0
    assert not path.exists()
    lines = err.splitlines()
    assert len(lines) == 2, err
    assert lines[0].endswith(f"INFO engine started on 127.0.0.1:{engine.info.port} (pid {engine.info.pid})")
    assert lines[1].endswith(f"INFO engine stopped ({how.name})")


def test_the_log_holds_no_token_no_path_and_no_client_address(engine: Engine) -> None:
    token = engine.info.token
    engine.request("GET", f"/v1/status?token={token}", headers={})  # a token in a URL is refused, not logged
    engine.request("GET", "/v1/nowhere")
    engine.request("POST", "/v1/validate", b"x" * (1024 * 1024 + 1))
    with engine.websocket() as ws:
        ws.send("wrong")
        time.sleep(0.2)
    out, err = engine.stop()
    assert token not in out + err
    assert "/v1/" not in err
    assert "127.0.0.1:" not in err.replace(f"engine started on 127.0.0.1:{engine.info.port}", "")
    assert len(err.splitlines()) == 2, err


@pytest.mark.parametrize("engine", [{"head_timeout": 0.5}], indirect=True)
def test_connections_that_trickle_a_request_head_are_closed(engine: Engine) -> None:
    port = engine.info.port
    with engine.websocket() as ws:  # a WebSocket outlives the head timeout of the connection it came from
        ws.send(engine.info.token)
        assert json.loads(ws.recv(timeout=5))["type"] == "hello"
        slow = open_connections(port, 70, trickle=True)
        try:
            for _ in range(8):  # a byte every 0.2 s keeps uvicorn's own keep-alive timer from firing
                time.sleep(0.2)
                trickle(slow)
            assert still_open(slow) == 0  # all closed by the 0.5 s head timeout
        finally:
            close_all(slow)
        assert json.loads(ws.recv(timeout=5))["type"] == "heartbeat"  # the WebSocket is still open


@pytest.fixture
def many_descriptors() -> Iterator[None]:
    """Room in this process for the hundreds of sockets of a test (macOS starts it with 256)."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = 2048 if hard == resource.RLIM_INFINITY else min(hard, 2048)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, wanted), hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def open_connections(port: int, count: int, *, trickle: bool = False) -> list[socket.socket]:
    """`count` connections to the engine that send nothing, or (`trickle`) only the start of a request head.

    They are opened 20 at a time, so that the system's listen queue (128 on macOS) never overflows: what is
    measured is the engine's limit, not the backlog.
    """
    opened: list[socket.socket] = []
    for start in range(0, count, 20):
        opened += [
            socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(min(20, count - start))
        ]
        time.sleep(0.02)
    if trickle:
        for raw in opened:
            raw.sendall(f"GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nX-Slow: ".encode())
    return opened


def trickle(connections: list[socket.socket]) -> None:
    for raw in connections:
        with suppress(OSError):
            raw.sendall(b"x")


def still_open(connections: list[socket.socket]) -> int:
    """How many of `connections` the engine has not closed, looked at all at once (in 0.1 s)."""
    readable, _, _ = select.select(connections, [], [], 0.1)
    closed = 0
    for raw in readable:  # readable: closed (b"" or a reset), or an answer
        raw.setblocking(False)
        try:
            closed += raw.recv(100) == b""
        except BlockingIOError:
            pass
        except OSError:
            closed += 1
    return len(connections) - closed


def close_all(connections: list[socket.socket]) -> None:
    for raw in connections:
        raw.close()


def status_while_crowded(engine: Engine) -> tuple[int, float, int]:
    """With 200 silent and 20 trickling connections open, an authenticated status request: its status, how
    long it took, and how many of the 220 were still open after it."""
    crowd = open_connections(engine.info.port, 200) + open_connections(engine.info.port, 20, trickle=True)
    try:
        time.sleep(0.5)  # uvicorn has accepted them all by now, so they count against its limit
        trickle(crowd[200:])
        started = time.monotonic()
        status = engine.request("GET", "/v1/status")[0]
        took = time.monotonic() - started
        return status, took, still_open(crowd)
    finally:
        close_all(crowd)


def test_the_connections_allowed_fit_in_the_file_descriptors() -> None:
    from safetwin.api.server import FD_RESERVE, MIN_CONNECTIONS, connection_limit

    assert connection_limit(FD_SOFT_LIMIT) == MAX_CONNECTIONS  # 4096: the full 1024
    assert connection_limit(resource.RLIM_INFINITY) == MAX_CONNECTIONS
    assert connection_limit(1024) == 1024 - FD_RESERVE
    assert connection_limit(256) == 128  # macOS's default, when it can't be raised
    assert connection_limit(150) == MIN_CONNECTIONS  # the floor that keeps the engine usable
    assert connection_limit(10) == MIN_CONNECTIONS


@pytest.mark.parametrize("engine", [{"fd_limit": 256}], indirect=True)
def test_an_engine_whose_descriptors_can_not_be_raised_allows_fewer_connections_and_still_serves(
    engine: Engine,
) -> None:
    assert engine.ready["nofile"] == [256, 256]
    assert engine.ready["limit_concurrency"] == 128
    assert engine.request("GET", "/v1/status")[0] == 200
    with engine.websocket() as ws:
        ws.send(engine.info.token)
        assert json.loads(ws.recv(timeout=5))["type"] == "hello"


def test_the_engine_raises_a_low_file_descriptor_limit() -> None:
    probe = (
        "import resource; from safetwin.api.server import raise_fd_limit;"
        "print(raise_fd_limit(), *resource.getrlimit(resource.RLIMIT_NOFILE))"
    )

    def start_at_256() -> None:
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))

    done = subprocess.run(
        [sys.executable, "-c", probe],
        preexec_fn=start_at_256,
        capture_output=True,
        text=True,
        timeout=SECONDS,
        check=True,
    )
    returned, soft, hard = (int(part) for part in done.stdout.split())
    expected = FD_SOFT_LIMIT if hard == resource.RLIM_INFINITY else min(hard, FD_SOFT_LIMIT)
    assert returned == soft == expected


def test_hundreds_of_idle_or_trickling_connections_do_not_starve_the_app(
    engine: Engine, many_descriptors: None
) -> None:
    soft, hard = engine.ready["nofile"]  # type: ignore[misc]
    assert soft >= (FD_SOFT_LIMIT if hard == resource.RLIM_INFINITY else min(hard, FD_SOFT_LIMIT))
    status, took, open_after = status_while_crowded(engine)
    assert open_after == 220  # they were all still open while the request ran (the head timeout is 5 s)
    assert status == 200
    assert took < 1.0


@pytest.mark.parametrize("engine", [{"max_connections": 64}], indirect=True)
def test_the_crowd_test_does_catch_a_limit_that_is_too_low(engine: Engine, many_descriptors: None) -> None:
    status, _, open_after = status_while_crowded(engine)
    assert open_after == 220
    assert status == 503  # with the old limit of 64, the app's request was refused


@pytest.mark.parametrize("engine", [{"head_timeout": 0.5}], indirect=True)
def test_a_pipelined_request_with_a_slow_body_is_not_cut_off_by_the_head_timeout(engine: Engine) -> None:
    port, token = engine.info.port, engine.info.token
    body = CSV_CLEAN.encode()
    first = f"GET /v1/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\n\r\n"
    second = (
        f"POST /v1/validate HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\n"
        f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
        # Both heads at once: the second is buffered when the first response completes. Its body then takes
        # 1.5 s, three times the head timeout and well within the body timeout.
        raw.sendall(first.encode() + second.encode() + body[:10])
        rest = body[10:]
        step = len(rest) // 15 + 1
        with suppress(OSError):  # a connection cut off mid-body is what the assertion below reports
            for start in range(0, len(rest), step):
                time.sleep(0.1)
                raw.sendall(rest[start : start + step])
        received = b""
        with suppress(OSError):
            while chunk := raw.recv(65536):
                received += chunk
    assert re.findall(rb"HTTP/1\.1 (\d{3})", received) == [b"200", b"200"], received[:300]
    assert b'"valid":true' in received


def test_a_flood_of_token_less_websockets_can_not_keep_the_app_off_the_event_stream(engine: Engine) -> None:
    import threading

    stop = threading.Event()
    opened = 0

    def flood() -> None:  # a local process that keeps reopening sockets and never sends a token
        nonlocal opened
        held: list[ExitStack] = []
        while not stop.is_set():
            stack = ExitStack()
            try:
                stack.enter_context(engine.websocket())
                held.append(stack)
                opened += 1
            except Exception:
                stack.close()
            if len(held) > 8:
                held.pop(0).close()
            time.sleep(0.02)
        for stack in held:
            stack.close()

    attacker = threading.Thread(target=flood, daemon=True)
    attacker.start()
    try:
        deadline = time.monotonic() + 30
        while opened < 20 and time.monotonic() < deadline:  # the flood is under way, however slow the machine
            time.sleep(0.05)
        for _ in range(5):
            with engine.websocket() as ws:
                ws.send(engine.info.token)
                assert json.loads(ws.recv(timeout=2))["type"] == "hello"
            time.sleep(0.2)
    finally:
        stop.set()
        attacker.join(10)
    assert opened > 20  # the flood really ran alongside


# --- the start: the maintenance child and the retry of stale folders never outlive the lock -----------------

SLOW_MIGRATION = """
import sys
from safetwin.metadata import lite

def slow():  # a first-start migration that takes a minute, and says its pid
    script = "import os, sys, time; open(sys.argv[2] + '.pid', 'w').write(str(os.getpid())); time.sleep(60)"
    return [sys.executable, "-c", script]

lite.maintain_command = slow
from safetwin.api import server
sys.exit(server.main([]))
"""


@pytest.mark.parametrize("how", [signal.SIGTERM, signal.SIGINT])
def test_an_engine_stopped_while_it_migrates_leaves_no_child(
    tmp_path: Path, safetwin_home: Path, how: signal.Signals
) -> None:
    script = tmp_path / "slow_driver.py"
    script.write_text(SLOW_MIGRATION)
    engine = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "SAFETWIN_HOME": str(safetwin_home)},
    )
    pid_file = safetwin_home / "metadata.db.pid"
    try:
        deadline = time.monotonic() + SECONDS
        while not (pid_file.exists() and pid_file.read_text()):
            assert engine.poll() is None, "the engine ended"
            assert time.monotonic() < deadline, "the child never started"
            time.sleep(0.01)
        engine.send_signal(how)
        _, err = engine.communicate(timeout=SECONDS)
    finally:
        if engine.poll() is None:
            engine.kill()
            engine.wait()
    assert engine.returncode == 130
    assert err.strip().splitlines()[-1] == "ERROR the engine was stopped while it started"
    with pytest.raises(ProcessLookupError):  # the child was killed and reaped before the engine ended
        os.kill(int(pid_file.read_text()), 0)
    assert not (safetwin_home / "engine.json").exists()


@pytest.mark.parametrize("fails", ["open", "start"])
def test_the_retry_of_stale_folders_is_cancelled_when_the_store_does_not_open(
    safetwin_home: Path, monkeypatch: pytest.MonkeyPatch, fails: str
) -> None:
    import threading

    from safetwin.api import server
    from safetwin.metadata.lite import MaintenanceFailed

    timers: list[threading.Timer] = []

    class Recorded(threading.Timer):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]
            timers.append(self)

    def broken(*args: object, **kwargs: object) -> None:
        raise MaintenanceFailed("the maintenance of the metadata database failed (exit code 1)")

    monkeypatch.setattr(server.threading, "Timer", Recorded)
    monkeypatch.setattr(server, "remove_stale", lambda home, only=None: (0, ["w0123456789"]))  # one is kept
    if fails == "open":
        monkeypatch.setattr(server.DbRunStore, "open", broken)
    else:
        monkeypatch.setattr(server.DbRunStore, "start", broken)
    with pytest.raises(MaintenanceFailed):
        server.run_engine(home=safetwin_home)
    (retry,) = timers
    assert retry.finished.is_set()  # cancelled: it never runs remove_stale once the lock is let go
    assert not retry.is_alive()
