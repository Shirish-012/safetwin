"""`safetwin engine start`, `status` and `stop`, as real processes with a folder of the app of the test's own.

Every engine that a test starts is stopped at the end of it, whatever happens.
"""

import hashlib
import http.client
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from safetwin.api.connection import ConnectionInfo, pid_alive, read_connection_file, write_connection_file
from safetwin.cli import main
from safetwin.cli.main import app

SAFETWIN = Path(sys.executable).parent / "safetwin"
SECONDS = 30
READY = re.compile(r"^engine running on 127\.0\.0\.1:(\d+) \(pid (\d+)\)\n$")
runner = CliRunner()


class Engines:
    """Runs `safetwin engine ...` with SAFETWIN_HOME set to the test's folder, and stops what it started."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.file = home / "engine.json"
        self.foreground: list[subprocess.Popen[str]] = []

    def env(self) -> dict[str, str]:
        return {**os.environ, "SAFETWIN_HOME": str(self.home)}

    def safetwin(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(SAFETWIN), "engine", *args],
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=SECONDS + 15,
            check=False,
        )

    def start(self, *options: str) -> ConnectionInfo:
        """`safetwin engine start --background`; the connection info of the engine it started."""
        done = self.safetwin("start", "--background", *options)
        assert done.returncode == 0, done.stderr
        match = READY.match(done.stdout)
        assert match is not None, done.stdout
        info = self.info()
        assert (info.port, info.pid) == (int(match[1]), int(match[2]))
        assert info.token not in done.stdout + done.stderr
        return info

    def start_in_foreground(self) -> tuple[subprocess.Popen[str], str]:
        process = subprocess.Popen(
            [str(SAFETWIN), "engine", "start"],
            env=self.env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.foreground.append(process)
        assert process.stdout is not None
        return process, process.stdout.readline()

    def info(self) -> ConnectionInfo:
        info = read_connection_file(self.file)
        assert info is not None
        return info

    def cleanup(self) -> None:
        for process in self.foreground:
            if process.poll() is None:
                process.kill()
                process.wait()
        try:
            info = read_connection_file(self.file)
        except Exception:
            return
        if info is not None and pid_alive(info.pid):
            os.kill(info.pid, signal.SIGKILL)


@pytest.fixture
def engines(safetwin_home: Path) -> Iterator[Engines]:
    made = Engines(safetwin_home)
    try:
        yield made
    finally:
        made.cleanup()


def wait_until_gone(pid: int) -> None:
    deadline = time.monotonic() + SECONDS
    while pid_alive(pid):
        assert time.monotonic() < deadline, f"pid {pid} is still running"
        time.sleep(0.02)


def dead_pid() -> int:
    ended = subprocess.Popen([sys.executable, "-c", "pass"])
    ended.wait()
    return ended.pid


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def plain(output: str) -> str:
    """The output as one line of words: no styling, no box that Typer draws round an error, no line breaks."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", re.sub(r"\x1b\[[0-9;]*m", "", output)).split())


def get(info: ConnectionInfo, path: str, headers: dict[str, str]) -> int:
    connection = http.client.HTTPConnection("127.0.0.1", info.port, timeout=10)
    try:
        connection.request("GET", path, headers=headers)
        return connection.getresponse().status
    finally:
        connection.close()


# --- the life of an engine ----------------------------------------------------------------------------------


def test_start_in_the_background_then_status_then_stop(engines: Engines, safetwin_home: Path) -> None:
    assert not safetwin_home.exists()
    info = engines.start()
    assert stat.S_IMODE(safetwin_home.stat().st_mode) == 0o700
    assert stat.S_IMODE(engines.file.stat().st_mode) == 0o600
    assert pid_alive(info.pid)

    status = engines.safetwin("status")
    assert status.returncode == 0, status.stderr
    lines = status.stdout.splitlines()
    assert lines[0] == f"engine running on 127.0.0.1:{info.port} (pid {info.pid})"
    assert lines[1] == f"version: {version('safetwin')}"
    assert re.fullmatch(r"started: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ, up \d+s", lines[2]), lines[2]
    assert re.fullmatch(r"memory: [\d,.]+ MB \((phys_footprint|rss)\)", lines[3]), lines[3]
    assert info.token not in status.stdout + status.stderr

    stopped = engines.safetwin("stop")
    assert stopped.returncode == 0, stopped.stderr
    assert stopped.stdout == "stopped\n"
    assert not pid_alive(info.pid)
    assert not engines.file.exists()
    assert info.token not in stopped.stdout + stopped.stderr

    after = engines.safetwin("status")
    assert (after.returncode, after.stdout) == (1, "the engine is not running\n")


def test_status_and_stop_say_when_no_engine_runs(engines: Engines) -> None:
    for command in ("status", "stop"):
        done = engines.safetwin(command)
        assert (done.returncode, done.stdout) == (1, "the engine is not running\n")


def test_a_second_start_is_refused(engines: Engines) -> None:
    info = engines.start()
    for options in (["--background"], []):
        done = engines.safetwin("start", *options)
        assert done.returncode == 1
        assert done.stderr.splitlines()[-1] == f"ERROR the engine is already running (pid {info.pid})"
    assert engines.info() == info


def test_a_foreground_start_prints_one_line_and_sigterm_stops_it_with_status_0(engines: Engines) -> None:
    process, line = engines.start_in_foreground()
    match = READY.match(line)
    assert match is not None, line
    info = engines.info()
    assert int(match[2]) == info.pid == process.pid
    assert engines.safetwin("status").returncode == 0
    process.send_signal(signal.SIGTERM)
    out, err = process.communicate(timeout=SECONDS)
    assert process.returncode == 0
    assert out == ""  # the one line was read already
    assert info.token not in line + out + err
    assert not engines.file.exists()


def test_sigterm_to_a_background_engine_removes_the_connection_file(engines: Engines) -> None:
    info = engines.start()
    os.kill(info.pid, signal.SIGTERM)
    wait_until_gone(info.pid)
    assert not engines.file.exists()


@pytest.mark.parametrize("alive", [False, True], ids=["dead-pid", "pid-that-is-not-an-engine"])
def test_a_stale_connection_file_is_replaced(engines: Engines, safetwin_home: Path, alive: bool) -> None:
    stale = ConnectionInfo(
        version="0.0.1",
        pid=os.getpid() if alive else dead_pid(),
        port=free_port(),
        token="stale-token-0123456789abcdef",
        started_at="2026-10-01T00:00:00Z",
    )
    write_connection_file(engines.file, stale)
    status = engines.safetwin("status")
    assert status.returncode == 1
    if alive:
        assert status.stdout.startswith("the engine is not running (nothing answers on 127.0.0.1:")
    else:
        assert status.stdout == (
            f"the engine is not running (its pid {stale.pid} is gone: the connection file is stale)\n"
        )
    info = engines.start()
    assert info.pid != stale.pid
    assert info.token != stale.token
    assert engines.safetwin("stop").returncode == 0


@pytest.fixture
def listener() -> Iterator[tuple[int, list[str]]]:
    """A server on a port that may once have been the engine's: its port, and the Authorization headers of
    the requests it got."""
    import http.server
    import threading

    seen: list[str] = []

    class Record(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._answer()

        def do_POST(self) -> None:
            self._answer()

        def _answer(self) -> None:
            seen.append(self.headers.get("Authorization", ""))
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Record)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1]), seen
    finally:
        server.shutdown()
        server.server_close()


def test_status_and_stop_never_send_the_token_for_a_pid_that_is_gone(
    engines: Engines, listener: tuple[int, list[str]]
) -> None:
    port, seen = listener
    stale = ConnectionInfo("0.0.1", dead_pid(), port, "stale-token-0123456789abcdef", "2026-10-01T00:00:00Z")
    write_connection_file(engines.file, stale)
    for command in ("status", "stop"):
        done = engines.safetwin(command)
        assert done.returncode == 1
        assert done.stdout == (
            f"the engine is not running (its pid {stale.pid} is gone: the connection file is stale)\n"
        )
    assert seen == []  # nothing reached the program that now has the port


def test_an_unsafe_folder_of_the_app_is_refused_by_start(engines: Engines, tmp_path: Path) -> None:
    real = tmp_path / "real-home"
    real.mkdir(mode=0o700)
    engines.home.symlink_to(real)  # SAFETWIN_HOME is a link
    for options in (["--background"], []):
        done = engines.safetwin("start", *options)
        assert done.returncode == 1
        assert "is not safe to use: it must be a folder of yours (not a link)" in done.stderr
    assert list(real.iterdir()) == []


def test_a_safetwin_home_that_others_may_use_is_refused_not_changed(engines: Engines) -> None:
    engines.home.mkdir()
    os.chmod(engines.home, 0o755)
    for options in (["--background"], []):
        done = engines.safetwin("start", *options)
        assert done.returncode == 1
        assert done.stderr == (
            f"ERROR the folder of the app {engines.home} (SAFETWIN_HOME) can be used by other users: run "
            "chmod 700 on it, or set SAFETWIN_HOME to another folder\n"
        )
    assert stat.S_IMODE(engines.home.stat().st_mode) == 0o755  # the user's folder is left as it was
    assert list(engines.home.iterdir()) == []


def test_a_safetwin_home_that_safetwin_makes_is_0700(engines: Engines) -> None:
    assert not engines.home.exists()
    engines.start()
    assert stat.S_IMODE(engines.home.stat().st_mode) == 0o700
    assert engines.safetwin("stop").returncode == 0


@pytest.mark.skipif(sys.platform != "darwin", reason="the default folder of the app is a macOS path here")
def test_the_default_folder_of_the_app_is_set_to_0700(tmp_path: Path) -> None:
    home = tmp_path / "user"
    default = home / "Library" / "Application Support" / "safetwin"
    default.mkdir(parents=True)
    os.chmod(default, 0o755)
    env = {key: value for key, value in os.environ.items() if key != "SAFETWIN_HOME"}
    env["HOME"] = str(home)
    started = subprocess.run(
        [str(SAFETWIN), "engine", "start", "--background"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    try:
        assert started.returncode == 0, started.stderr
        assert stat.S_IMODE(default.stat().st_mode) == 0o700
    finally:
        stopped = subprocess.run(
            [str(SAFETWIN), "engine", "stop"], env=env, capture_output=True, text=True, timeout=60
        )
        info = read_connection_file(default / "engine.json")
        if info is not None and pid_alive(info.pid):
            os.kill(info.pid, signal.SIGKILL)
    assert stopped.returncode == 0, stopped.stderr


def test_an_engine_answering_with_another_token_is_reported(engines: Engines) -> None:
    info = engines.start()
    write_connection_file(
        engines.file,
        ConnectionInfo(info.version, info.pid, info.port, "another-token-0123456789", info.started_at),
    )
    done = engines.safetwin("status")
    assert done.returncode == 1
    assert done.stderr == (
        f"ERROR the engine on 127.0.0.1:{info.port} refused the token of the connection file (is another "
        "program on that port?)\n"
    )
    os.kill(info.pid, signal.SIGTERM)
    wait_until_gone(info.pid)


# --- the connection file must be trustworthy ----------------------------------------------------------------


def test_status_and_stop_refuse_a_connection_file_that_others_can_read(engines: Engines) -> None:
    info = engines.start()
    os.chmod(engines.file, 0o644)
    for command in ("status", "stop"):
        done = engines.safetwin(command)
        assert done.returncode == 1
        assert (
            "is not safe to use: it must be a file of yours that only you can read and write" in done.stderr
        )
        assert info.token not in done.stdout + done.stderr
    assert pid_alive(info.pid)  # stop refused to act on it
    os.chmod(engines.file, 0o600)
    assert engines.safetwin("stop").returncode == 0


def test_status_refuses_a_connection_file_of_another_user(
    safetwin_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_connection_file(
        safetwin_home / "engine.json",
        ConnectionInfo("0.0.1", os.getpid(), free_port(), "a-token-0123456789abcdef", "2026-10-01T00:00:00Z"),
    )
    monkeypatch.setattr(os, "getuid", lambda: 4242)  # the file belongs to someone else now
    result = runner.invoke(app, ["engine", "status"])
    assert result.exit_code == 1
    assert "is not safe to use" in result.output


# --- options ------------------------------------------------------------------------------------------------


def test_a_dev_origin_is_allowed_and_others_are_not(engines: Engines) -> None:
    info = engines.start("--dev-origin", "http://localhost:5173")
    auth = {"Authorization": f"Bearer {info.token}"}
    assert get(info, "/v1/status", {**auth, "Origin": "http://localhost:5173"}) == 200
    assert get(info, "/v1/status", auth) == 200  # no Origin: the CLI
    assert get(info, "/v1/status", {**auth, "Origin": "http://localhost:5174"}) == 403


@pytest.mark.parametrize("origin", ["localhost:5173", "http://localhost:5173/app", "*"])
def test_a_bad_dev_origin_is_a_usage_error(engines: Engines, origin: str) -> None:
    for options in (["--background"], []):
        done = engines.safetwin("start", *options, "--dev-origin", origin)
        assert done.returncode == 2
        assert "an origin is a scheme, a host and an optional port" in plain(done.stderr)
    assert not engines.file.exists()


def test_the_cli_never_loads_fastapi_for_status_or_stop(engines: Engines) -> None:
    engines.start()
    probe = (
        "import sys; from typer.testing import CliRunner; from safetwin.cli.main import app;"
        "result = CliRunner().invoke(app, ['engine', 'status']); assert result.exit_code == 0, result.output;"
        "import json; print(json.dumps(sorted(m for m in sys.modules if m.split('.')[0] in "
        "('fastapi', 'uvicorn', 'starlette', 'polars', 'pyarrow', 'duckdb'))))"
    )
    done = subprocess.run(
        [sys.executable, "-c", probe],
        env=engines.env(),
        capture_output=True,
        text=True,
        timeout=SECONDS,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == []
    assert engines.safetwin("stop").returncode == 0


# --- safetwin run and safetwin runs -------------------------------------------------------------------------

PIPELINE = """\
apiVersion: safetwin/v1
kind: Pipeline
metadata:
  name: people
spec:
  sockets:
    inbox: socket://local-inbox
    outbox: socket://local-outbox
  nodes:
    - {id: read_csv, operator: source.csv, socket: inbox, config: {path: "*.csv"}}
    - {id: keep, operator: transform.filter, inputs: [read_csv], config: {expr: "id IS NOT NULL"}}
    - {id: write, operator: sink.parquet, inputs: [keep], socket: outbox, config: {path: out/}}
"""
NEEDS_ENGINE = (
    "the engine is not running: start it with `safetwin engine start --background`, "
    "or use `safetwin run-local`"
)


class RunFolders:
    def __init__(self, root: Path, rows: int) -> None:
        self.inbox, self.outbox = root / "in", root / "out"
        self.inbox.mkdir()
        self.outbox.mkdir()
        with (self.inbox / "people.csv").open("w") as file:
            file.write("id,name\n")
            for start in range(0, rows, 100_000):
                file.write(
                    "".join(
                        f"{'' if n % 10 == 0 else n},name {n}\n"
                        for n in range(start, min(rows, start + 100_000))
                    )
                )
        self.pipeline = root / "people.yaml"
        self.pipeline.write_text(PIPELINE)

    def args(self, *more: str) -> list[str]:
        return [
            str(self.pipeline),
            "--socket",
            f"inbox={self.inbox}",
            "--socket",
            f"outbox={self.outbox}",
            *more,
        ]

    def written(self) -> list[str]:
        return sorted(str(p.relative_to(self.outbox)) for p in self.outbox.rglob("*") if p.is_file())


def safetwin_run(engines: Engines, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SAFETWIN), *args],
        env=engines.env(),
        capture_output=True,
        text=True,
        timeout=SECONDS * 2,
        check=False,
    )


def test_safetwin_run_without_an_engine_says_how_to_start_one(engines: Engines, tmp_path: Path) -> None:
    folders = RunFolders(tmp_path, 10)
    done = safetwin_run(engines, "run", *folders.args())
    assert done.returncode == 1
    assert done.stderr.strip() == NEEDS_ENGINE
    assert safetwin_run(engines, "runs", "show", "r12345678").stderr.strip() == NEEDS_ENGINE


def test_safetwin_run_prints_the_same_report_as_run_local(engines: Engines, tmp_path: Path) -> None:
    folders = RunFolders(tmp_path, 20_000)
    engines.start()
    done = safetwin_run(engines, "run", *folders.args())
    assert done.returncode == 0, done.stderr
    out = done.stdout.splitlines()
    match = re.fullmatch(r"run (r[0-9a-f]{8}) of people: 1 stage\(s\)", out[0])
    assert match is not None, done.stdout
    run_id = match[1]
    assert out[1].startswith("stage 1: fused, ")
    assert out[2:5] == [
        "  read_csv  source.csv        20,000",
        "  keep      transform.filter  20,000 → 18,000",
        "  write     sink.parquet      18,000 → 18,000",
    ]
    parquet = folders.outbox.resolve() / "out" / f"part-00000-{run_id}.parquet"
    assert out[5] == f"  wrote {parquet}"
    digest = hashlib.sha256(parquet.read_bytes()).hexdigest()
    assert out[6] == f"        {parquet.stat().st_size:,} bytes, sha256 {digest}"
    assert out[7].startswith(f"  manifest {folders.outbox.resolve() / 'out' / '_manifest'}/run=")
    local = runner.invoke(app, ["run-local", *folders.args()])
    assert local.exit_code == 0
    assert [line for line in local.stdout.splitlines() if line.startswith("  ") and "wrote" not in line
            and "manifest" not in line and "bytes" not in line] == out[2:5]  # fmt: skip
    shown = safetwin_run(engines, "runs", "show", run_id)
    assert shown.returncode == 0
    assert shown.stdout.splitlines() == out
    assert safetwin_run(engines, "runs", "cancel", run_id).stderr.strip() == "ERROR the run has ended already"
    assert (
        safetwin_run(engines, "runs", "show", "rnothere").stderr.strip()
        == "ERROR the engine has no run with that id"
    )


def test_safetwin_run_reports_a_failure_in_one_line(engines: Engines, tmp_path: Path) -> None:
    folders = RunFolders(tmp_path, 100)
    folders.pipeline.write_text(PIPELINE.replace('"id IS NOT NULL"', '"CAST(name AS INT) > 0"'))
    engines.start()
    done = safetwin_run(engines, "run", *folders.args())
    assert done.returncode == 1
    assert done.stdout == ""
    assert done.stderr.splitlines()[-1].startswith("ERROR the run failed with ")
    assert "(its message can quote data, so it is not shown)" in done.stderr
    assert len([line for line in done.stderr.splitlines() if line.startswith("ERROR")]) == 1
    assert "name 1" not in done.stderr
    assert folders.written() == []
    missing = safetwin_run(engines, "run", str(folders.pipeline), "--socket", f"inbox={folders.inbox}")
    assert missing.returncode == 1
    assert missing.stderr.strip() == (
        "ERROR write (sink.parquet): socket 'outbox' has no folder (folders were given for: inbox)"
    )


def test_ctrl_c_cancels_the_run_in_the_engine_and_exits_with_130(engines: Engines, tmp_path: Path) -> None:
    folders = RunFolders(tmp_path, 3_000_000)
    info = engines.start()
    process = subprocess.Popen(
        [str(SAFETWIN), "run", *folders.args()],
        env=engines.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
    )
    deadline = time.monotonic() + SECONDS
    while not any(".tmp-" in name for name in folders.written()):
        assert process.poll() is None, "the run ended before it could be interrupted"
        assert time.monotonic() < deadline
        time.sleep(0.002)
    process.send_signal(signal.SIGINT)
    out, err = process.communicate(timeout=SECONDS)
    assert process.returncode == 130, err
    assert err.splitlines()[-1] == "ERROR the run was cancelled: the stage that was running wrote nothing"
    assert out == ""
    assert folders.written() == []
    status = json.loads(get_json(info, "/v1/runs"))
    assert [run["state"] for run in status["runs"]] == ["cancelled"]
    assert list((engines.home / "tmp").iterdir()) == []


# --- the history: safetwin runs list and show, across restarts ----------------------------------------------


def test_the_history_outlives_the_engine_and_runs_list_and_show_read_it(
    engines: Engines, tmp_path: Path
) -> None:
    folders = RunFolders(tmp_path, 20_000)
    engines.start()
    done = safetwin_run(engines, "run", *folders.args())
    assert done.returncode == 0, done.stderr
    out = done.stdout.splitlines()
    match = re.fullmatch(r"run (r[0-9a-f]{8}) of people: 1 stage\(s\)", out[0])
    assert match is not None
    run_id = match[1]
    assert engines.safetwin("stop").returncode == 0
    engines.start()
    shown = safetwin_run(engines, "runs", "show", run_id)
    assert shown.returncode == 0, shown.stderr
    # The same report, from the database: only the way the stage ran is not kept.
    duration = re.fullmatch(r"stage 1: fused, ([0-9.]+ s)", out[1])
    assert duration is not None
    assert shown.stdout.splitlines() == [out[0], f"stage 1: {duration[1]}", *out[2:]]
    parquet = folders.outbox.resolve() / "out" / f"part-00000-{run_id}.parquet"
    digest = hashlib.sha256(parquet.read_bytes()).hexdigest()
    assert f"        {parquet.stat().st_size:,} bytes, sha256 {digest}" in shown.stdout.splitlines()
    listed = safetwin_run(engines, "runs", "list")
    assert listed.returncode == 0, listed.stderr
    header, row = listed.stdout.splitlines()
    assert header.split() == ["RUN", "PIPELINE", "STATE", "STARTED", "(UTC)", "DURATION", "ROWS", "BYTES"]
    cells = row.split()
    assert cells[:3] == [run_id, "people", "succeeded"]
    assert cells[-2:] == ["18,000", f"{parquet.stat().st_size:,}"]
    assert re.fullmatch(r"[0-9.]+s", cells[-3])
    filtered = safetwin_run(
        engines, "runs", "list", "--state", "failed", "--pipeline", "people", "--limit", "5"
    )
    assert filtered.stdout.strip() == "no runs"
    assert safetwin_run(engines, "runs", "list", "--limit", "0").returncode == 2
    assert safetwin_run(engines, "runs", "list", "--state", "nope").returncode == 2
    refused = safetwin_run(engines, "runs", "list", "--pipeline", "Not A Slug")
    assert refused.returncode == 1
    assert refused.stderr.strip() == "ERROR the engine refused the request (pipeline)"


def test_runs_list_without_an_engine_says_how_to_start_one(engines: Engines) -> None:
    done = safetwin_run(engines, "runs", "list")
    assert done.returncode == 1
    assert done.stderr.strip() == NEEDS_ENGINE


def test_a_run_of_an_engine_that_was_killed_is_interrupted_after_a_restart(
    engines: Engines, tmp_path: Path
) -> None:
    from safetwin.api.client import call_json

    folders = RunFolders(tmp_path, 3_000_000)
    info = engines.start()
    request = {
        "pipeline_path": str(folders.pipeline),
        "sockets": {"inbox": str(folders.inbox), "outbox": str(folders.outbox)},
    }
    status, answer = call_json(info, "POST", "/v1/runs", request)
    assert status == 202
    run_id = answer["run_id"]
    deadline = time.monotonic() + SECONDS
    while not any(".tmp-" in name for name in folders.written()):
        assert time.monotonic() < deadline, "the stage never started writing"
        time.sleep(0.002)
    os.kill(info.pid, signal.SIGKILL)
    wait_until_gone(info.pid)
    engines.start()  # it replaces the connection file the killed one left
    listed = safetwin_run(engines, "runs", "list", "--state", "interrupted")
    assert listed.returncode == 0, listed.stderr
    assert listed.stdout.splitlines()[1].split()[:3] == [run_id, "people", "interrupted"]
    shown = safetwin_run(engines, "runs", "show", run_id)
    assert shown.returncode == 0, shown.stderr
    assert shown.stdout.splitlines() == [
        f"run {run_id} of people: interrupted",
        "stage 1: interrupted",
        "error_class: EngineStopped",
        "error: the run was interrupted: the engine stopped before the run ended",
    ]


def get_json(info: ConnectionInfo, path: str) -> str:
    connection = http.client.HTTPConnection("127.0.0.1", info.port, timeout=10)
    try:
        connection.request("GET", path, headers={"Authorization": f"Bearer {info.token}"})
        return connection.getresponse().read().decode()
    finally:
        connection.close()


# --- Ctrl-C: what safetwin run reports, whatever the run did ------------------------------------------------

INFO = ConnectionInfo("0.0.1", 1, 1, "t" * 43, "2026-10-02T00:00:00Z")


def record(state: str, **more: Any) -> dict[str, Any]:
    return {
        "run_id": "r1234abcd",
        "pipeline": "people",
        "state": state,
        "error_class": None,
        "error": None,
        "stages": [
            {
                "index": 0,
                "node_ids": ["read_csv", "write"],
                "operators": ["source.csv", "sink.parquet"],
                "path": "fused",
                "state": state,
                "duration_s": 0.5,
                "rows_per_node": {"read_csv": 3, "write": 3},
                "files": [{"path": "/out/part.parquet", "bytes": 10, "sha256": "a" * 64}],
                "manifest": "/out/_manifest/run.json",
            }
        ],
        **more,
    }


def cancel_outcome(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: int | Exception,
    states: list[Any],
) -> tuple[int, str, str, list[str]]:
    """Run `_cancel_and_exit` against a fake engine: the cancel answers `status` (or raises it), and each
    look at the run gives the next of `states` (a record, None, or an error)."""
    import typer

    from safetwin.api import client
    from safetwin.cli import main

    cancelled: list[str] = []

    def cancel_run(info: ConnectionInfo, run_id: str, **_: Any) -> tuple[int, Any]:
        cancelled.append(run_id)
        if isinstance(status, Exception):
            raise status
        return status, None

    def get_run(info: ConnectionInfo, run_id: str, **_: Any) -> Any:
        found = states.pop(0) if len(states) > 1 else states[0]
        if isinstance(found, Exception):
            raise found
        return found

    monkeypatch.setattr(client, "cancel_run", cancel_run)
    monkeypatch.setattr(client, "get_run", get_run)
    monkeypatch.setattr(main, "CANCEL_WAIT_S", 0.5)
    with pytest.raises(typer.Exit) as ended:
        main._cancel_and_exit(INFO, "r1234abcd")
    out, err = capsys.readouterr()
    return ended.value.exit_code, out, err, cancelled


def test_ctrl_c_reports_a_cancelled_run_with_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err, cancelled = cancel_outcome(
        monkeypatch, capsys, 202, [record("running"), record("cancelled")]
    )
    assert (code, out) == (130, "")
    assert err.strip() == "ERROR the run was cancelled: the stage that was running wrote nothing"
    assert cancelled == ["r1234abcd"]


def test_ctrl_c_that_races_the_end_of_the_run_reports_its_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err, _ = cancel_outcome(monkeypatch, capsys, 202, [record("succeeded")])
    assert (code, err) == (0, "")
    assert out.splitlines()[0] == "run r1234abcd of people: 1 stage(s)"
    assert "  wrote /out/part.parquet" in out.splitlines()


def test_ctrl_c_after_the_run_ended_409_reports_how_it_ended(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    failed = record("failed", error_class="ComputeError")
    code, out, err, _ = cancel_outcome(monkeypatch, capsys, 409, [failed])
    assert (code, out) == (1, "")
    assert err.strip() == (
        "ERROR the run failed with ComputeError (its message can quote data, so it is not shown)"
    )


@pytest.mark.parametrize(
    ("status", "states"),
    [
        ("unreachable", ["error"]),  # the engine can't be reached
        (202, ["error"]),  # it took the cancel, then went away
        (202, [None]),  # it no longer knows the run
        (202, [record("running")]),  # the run does not end in time
        (404, [record("running")]),
    ],
    ids=["unreachable", "gone-after-cancel", "forgotten", "timeout", "404"],
)
def test_ctrl_c_whose_cancel_can_not_be_confirmed_says_so(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], status: Any, states: list[Any]
) -> None:
    from safetwin.api.client import EngineNotRunning

    down = EngineNotRunning("nothing answers on 127.0.0.1:1")
    code, out, err, _ = cancel_outcome(
        monkeypatch,
        capsys,
        down if status == "unreachable" else status,
        [down if state == "error" else state for state in states],
    )
    assert (code, out) == (1, "")
    assert err.strip() == "ERROR the cancel could not be confirmed: check `safetwin runs show r1234abcd`"


ACCEPTED_THEN_CANCELLED = "ERROR the run was cancelled: the stage that was running wrote nothing"
NOT_STARTED = "ERROR interrupted before the engine accepted the run: no run was started"
MAY_HAVE_STARTED = (
    "ERROR interrupted before the engine answered: the engine may have accepted the run: check "
    "`safetwin runs show` or `GET /v1/runs`"
)


@pytest.mark.parametrize(
    ("ctrl_c_at", "answer_at", "answer", "expected", "cancelled"),
    [
        ([0.1], 0.5, (202, {"run_id": "r1234abcd", "state": "queued"}), ACCEPTED_THEN_CANCELLED, True),
        ([0.1, 0.3], 0.6, (202, {"run_id": "r1234abcd", "state": "queued"}), ACCEPTED_THEN_CANCELLED, True),
        ([0.1], 0.4, (422, {"error": "invalid_request", "problems": []}), NOT_STARTED, False),
        ([0.1], 0.4, "not-running", NOT_STARTED, False),
        ([0.1], 0.4, "reset", MAY_HAVE_STARTED, False),
        ([0.1], 0.4, "bug", MAY_HAVE_STARTED, False),
        ([0.1], 3.0, (202, {"run_id": "r1234abcd", "state": "queued"}), MAY_HAVE_STARTED, False),
    ],
    ids=["accepted", "second-ctrl-c", "refused", "nothing-listening", "reset", "bug", "no-answer-in-time"],
)
def test_ctrl_c_during_the_request_that_submits_the_run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    ctrl_c_at: list[float],
    answer_at: float,
    answer: Any,
    expected: str,
    cancelled: bool,
) -> None:
    import threading

    import typer

    from safetwin.api import client
    from safetwin.cli import main

    cancels: list[str] = []

    def call_json(
        info: ConnectionInfo, method: str, path: str, body: Any = None, **_: Any
    ) -> tuple[int, Any]:
        time.sleep(answer_at)  # the answer comes after the Ctrl-C
        if answer == "not-running":
            raise client.EngineNotRunning("nothing answers on 127.0.0.1:1")
        if answer == "reset":
            raise client.EngineError("could not talk to the engine on 127.0.0.1:1: Connection reset by peer")
        if answer == "bug":
            raise IndexError("CANARY-in-a-bug")
        return answer  # type: ignore[no-any-return]

    def cancel_run(info: ConnectionInfo, run_id: str, **_: Any) -> tuple[int, Any]:
        cancels.append(run_id)
        return 202, None

    monkeypatch.setattr(client, "call_json", call_json)
    monkeypatch.setattr(client, "cancel_run", cancel_run)
    monkeypatch.setattr(client, "get_run", lambda info, run_id, **_: record("cancelled"))
    monkeypatch.setattr(main, "SUBMIT_WAIT_S", 1.0)
    for at in ctrl_c_at:
        threading.Timer(at, lambda: os.kill(os.getpid(), signal.SIGINT)).start()
    with pytest.raises(typer.Exit) as ended:
        main._submit(INFO, {"pipeline_yaml": "x"})
    out, err = capsys.readouterr()
    assert ended.value.exit_code == 130
    assert err.strip() == expected
    assert cancels == (["r1234abcd"] if cancelled else [])
    assert "Aborted" not in out + err
    assert "CANARY" not in out + err


def test_an_unexpected_error_of_the_submit_request_is_one_safe_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import typer

    from safetwin.api import client
    from safetwin.cli import main

    def call_json(*args: Any, **kwargs: Any) -> tuple[int, Any]:
        raise IndexError("CANARY-in-a-bug")

    monkeypatch.setattr(client, "call_json", call_json)
    with pytest.raises(typer.Exit) as ended:
        main._submit(INFO, {"pipeline_yaml": "x"})
    out, err = capsys.readouterr()
    assert ended.value.exit_code == 1
    assert (out, err.strip()) == ("", "ERROR the request to the engine failed (IndexError)")
    monkeypatch.setattr(client, "call_json", lambda *args, **kwargs: (202, {"state": "queued"}))
    with pytest.raises(typer.Exit) as ended:
        main._submit(INFO, {"pipeline_yaml": "x"})
    assert ended.value.exit_code == 1
    assert capsys.readouterr().err.strip() == "ERROR the engine accepted the run but did not say its id"


# --- safetwin runs list --before: paging past a full page --------------------------------------------------


def a_summary(run_id: str) -> dict[str, object]:
    return {"run_id": run_id, "pipeline": "people", "state": "succeeded", "started_at": None, "totals": {}}


@pytest.fixture
def fake_engine(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """`runs list` against a fake engine: 5 runs, newest first, paged as `GET /v1/runs` pages them. The
    calls it got are recorded."""
    from safetwin.api import client

    history = [f"r{n}" for n in range(5, 0, -1)]
    calls: list[dict[str, object]] = []

    def list_runs(info: object, **query: object) -> tuple[int, object]:
        calls.append(query)
        before, limit = query.get("before"), int(query.get("limit") or 20)
        if before is not None and before not in history:
            return 422, {
                "error": "invalid_request",
                "problems": [{"loc": ["query", "before"], "type": "unknown_run"}],
            }
        start = 0 if before is None else history.index(str(before)) + 1
        page = history[start : start + limit]
        return 200, {
            "runs": [a_summary(run_id) for run_id in page],
            "next_before": page[-1] if len(page) == limit else None,
        }

    monkeypatch.setattr(main, "_engine_for_runs", lambda: object())
    monkeypatch.setattr(client, "list_runs", list_runs)
    return calls


def listed_ids(output: str) -> list[str]:
    return [line.split()[0] for line in output.splitlines()[1:] if not line.startswith("more:")]


def test_a_full_page_says_how_to_get_the_next_one_and_before_gets_it(
    fake_engine: list[dict[str, object]],
) -> None:
    first = runner.invoke(app, ["runs", "list", "--limit", "2", "--state", "succeeded"])
    assert first.exit_code == 0, first.output
    assert listed_ids(first.stdout) == ["r5", "r4"]
    assert first.stdout.splitlines()[-1] == "more: safetwin runs list --before r4 --limit 2 --state succeeded"
    second = runner.invoke(app, ["runs", "list", "--limit", "2", "--state", "succeeded", "--before", "r4"])
    assert listed_ids(second.stdout) == ["r3", "r2"]
    assert (
        second.stdout.splitlines()[-1] == "more: safetwin runs list --before r2 --limit 2 --state succeeded"
    )
    last = runner.invoke(app, ["runs", "list", "--limit", "2", "--before", "r2"])
    assert listed_ids(last.stdout) == ["r1"]
    assert "more:" not in last.stdout  # the page is not full: nothing older
    assert fake_engine[1] == {"limit": 2, "before": "r4", "pipeline": None, "state": "succeeded"}


def test_the_hint_leaves_out_the_default_limit(fake_engine: list[dict[str, object]]) -> None:
    result = runner.invoke(app, ["runs", "list", "--limit", "20"])
    assert listed_ids(result.stdout) == ["r5", "r4", "r3", "r2", "r1"]
    assert "more:" not in result.stdout
    result = runner.invoke(app, ["runs", "list", "--limit", "5"])
    assert result.stdout.splitlines()[-1] == "more: safetwin runs list --before r1 --limit 5"


def test_an_unknown_before_is_one_error_line(fake_engine: list[dict[str, object]]) -> None:
    result = runner.invoke(app, ["runs", "list", "--before", "rnothere"])
    assert result.exit_code == 1
    assert result.stderr.strip() == "ERROR the engine has no run with the id given to --before"


def test_runs_list_help_names_before() -> None:
    text = re.sub(r"\x1b\[[0-9;]*m", "", runner.invoke(app, ["runs", "list", "--help"]).output)
    assert "--before" in text
    assert "RUN_ID" in text
