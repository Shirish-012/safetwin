"""Leak tests: the data of a pipeline ends up in its output and nowhere else (docs/internals.md).

Each test runs the real command (`safetwin run-local`, in a process of its own) on data that holds a canary, a
string made for that test alone (`CANARY-<random hex>`), in the values of several columns. The process gets
folders of its own for HOME, TMPDIR, SAFETWIN_HOME and its working folder, and SAFETWIN_DUCKDB_EXTENSIONS is
not set. The inbox and the outbox are folders of their own too. After the run the canary must be found
nowhere:

- in no file below HOME, TMPDIR, SAFETWIN_HOME or the working folder;
- in no file of the system's temporary folders (`tempfile.gettempdir()`, /tmp, and on macOS the per-user cache
  folder `C` next to the first) that changed since the test started (the later of its modification and its
  status change), except below pytest's own folder (where the sandbox, and so the inbox, is);
- not in what the command printed;
- not in the manifest. The outbox holds only the expected data files and their manifest (the data files hold
  the canary, of course: they are the user's output), or nothing at all when the run failed.

Files are searched as bytes, for the canary in UTF-8 and in UTF-16-LE. A compressed file (a zstd page of
Parquet, say) could hold the canary where a search of its bytes does not see it: these tests find plain copies
of the data, which is what a cache, a log or a spill file of a library would be. And DuckDB must not have made
`~/.duckdb` in the fake HOME, and nothing below the real `~/.duckdb` (found with `getpwuid`, as a library
that ignores $HOME would find it) may have changed since the test started: nothing installs or loads DuckDB
extensions from the home folder. That folder is only looked at, never changed.

`test_the_engine_api_leaves_the_canary_nowhere_and_the_token_only_in_its_connection_file` runs the engine
instead (`safetwin engine start`, then `safetwin engine stop`) and sends it pipelines that hold the canary to
validate. The canary must be in no file, no output and no answer, and the session token in no file but the
connection file while the engine runs (and in none once it has stopped), not in what was printed and not in
the argv or the environment of the engine.

`test_a_run_through_the_engine_leaves_the_canary_only_in_its_data_file` runs pipelines through the engine:
`safetwin engine start`, then `safetwin run` (one run that succeeds and one that fails on a value it can't
cast), with a WebSocket client that keeps every event the engine sends. The canary must be in no file of the
sandbox (SAFETWIN_HOME and its `tmp/`, where the stage workers' private folders are, included), no file of the
system's temporary folders, nothing the engine or `safetwin` printed, no event and no answer of the API; and
every worker's folder must be gone afterwards. The canary is in the data only, never in the pipeline, so the
history the engine keeps (the metadata database, which holds the pipeline's text) must not hold it either:
while the engine still runs, the raw bytes of every file of SAFETWIN_HOME are searched (`metadata.db`, `-wal`
and `-shm` included), and every column of every row of every table of the database is read and searched too.

`test_excel_in_and_out_leaves_the_canary_nowhere_and_no_staging_folder` masks an Excel workbook into
Excel workbooks, which goes through a staging folder of Parquet files (compressed, so a search of their bytes
may miss the canary): that folder must be gone. `test_the_page_leaves_the_canary_nowhere_once_it_stops` runs
`safetwin ui`, masks through its API (scan, preview, mask, report, history: no answer may hold the canary),
stops it with Ctrl-C, and its workspace must be gone with every copy of the data; the history it keeps holds
reports only.

`test_the_scanner_finds_a_canary_that_is_planted` plants the canary where the scanner must find it: a scanner
that can never fail would prove nothing.

What these tests can't see: a `safetwin run-local` that is killed (SIGKILL, a crash) can leave its temporary
file (`.part-....parquet.tmp-...`) in the outbox. The outbox is the user's own storage, and such files are
cleaned up later (T8). In the engine, the control plane removes it when a stage worker is killed
(`engine/tests/executor`). Ctrl-C (SIGINT) leaves nothing:
`test_a_run_interrupted_with_ctrl_c_leaves_nothing`.
"""

import dataclasses
import http.client
import json
import os
import pwd
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import psutil
import pytest

SAFETWIN = Path(sys.executable).parent / "safetwin"
REAL_TEMP = Path(os.path.realpath(tempfile.gettempdir()))  # of this process, which is not sandboxed
REAL_DUCKDB = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".duckdb"
SECONDS = 120
CHUNK = 1 << 20

HEAD = """\
apiVersion: safetwin/v1
kind: Pipeline
metadata:
  name: leak
spec:
  sockets:
    inbox: socket://leak-inbox
    outbox: socket://leak-outbox
  nodes:
    - {id: read, operator: source.csv, socket: inbox, config: {path: "*.csv"}}
"""
POLARS_STEPS = (
    HEAD
    + """\
    - {id: keep, operator: transform.filter, inputs: [read], config: {expr: "id IS NOT NULL"}}
    - {id: tidy, operator: transform.trim, inputs: [keep], config: {columns: [name, city]}}
    - {id: write, operator: sink.parquet, inputs: [tidy], socket: outbox, config: {path: data/}}
"""
)
DUCKDB_STEPS = (
    HEAD
    + """\
    - id: query
      operator: transform.sql
      inputs: [read]
      config: {sql: "SELECT id, name, city, upper(note) AS note FROM input WHERE id IS NOT NULL"}
    - id: ordered
      operator: transform.sort
      inputs: [query]
      config: {by: [{column: name, descending: true}]}
    - {id: write, operator: sink.parquet, inputs: [ordered], socket: outbox, config: {path: data/}}
"""
)
SORT = (
    HEAD
    + """\
    - {id: ordered, operator: transform.sort, inputs: [read], config: {by: [name, id]}}
    - {id: write, operator: sink.parquet, inputs: [ordered], socket: outbox, config: {path: data/}}
"""
)
CAST = (
    HEAD
    + """\
    - id: query
      operator: transform.sql
      inputs: [read]
      config: {sql: "SELECT CAST(name AS INTEGER) AS n FROM input"}
    - {id: write, operator: sink.parquet, inputs: [query], socket: outbox, config: {path: data/}}
"""
)
COPY = (
    HEAD
    + """\
    - {id: write, operator: sink.parquet, inputs: [read], socket: outbox, config: {path: data/}}
"""
)


# --- the scanner --------------------------------------------------------------------------------------------


def file_holds(path: Path, needles: list[bytes]) -> bool:
    """Whether the bytes of the file hold one of `needles`, read in chunks that overlap by a needle."""
    overlap = max(len(needle) for needle in needles) - 1
    tail = b""
    with path.open("rb") as file:
        while chunk := file.read(CHUNK):
            window = tail + chunk
            if any(needle in window for needle in needles):
                return True
            tail = window[-overlap:]
    return False


def needles(canary: str) -> list[bytes]:
    return [canary.encode("utf-8"), canary.encode("utf-16-le")]


def scan(
    canary: str, roots: list[Path], *, changed_since: float | None = None, skip: list[Path] | None = None
) -> list[str]:
    """Every regular file below `roots` whose bytes hold the canary. Links are not followed.

    With `changed_since`, only the files changed since then (modified, or their status changed) are read.
    Folders in `skip` are left out.
    """
    wanted = needles(canary)
    skipped = [os.path.realpath(path) for path in skip or []]
    hits: list[str] = []
    for root in roots:
        for folder, folders, files in os.walk(root):
            if os.path.realpath(folder) in skipped:
                folders[:] = []
                continue
            for name in files:
                path = Path(folder) / name
                try:
                    info = path.lstat()
                    if not path.is_file() or path.is_symlink():
                        continue
                    if changed_since is not None and changed_at(info) < changed_since:
                        continue
                    if file_holds(path, wanted):
                        hits.append(str(path))
                except OSError:  # gone already, or not ours to read
                    continue
    return hits


def database_values_holding(database: Path, canary: str) -> list[str]:
    """Every `table.column` of the SQLite database in which a value (text, or bytes) holds the canary."""
    hits: list[str] = []
    connection = sqlite3.connect(database)
    try:
        tables = [
            name for (name,) in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        ]
        for table in tables:
            columns = [row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')]
            for column in columns:
                for (value,) in connection.execute(f'SELECT "{column}" FROM "{table}"'):
                    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
                    if canary in text:
                        hits.append(f"{table}.{column}")
                        break
    finally:
        connection.close()
    return hits


def changed_at(info: os.stat_result) -> float:
    """When a file last changed: the later of its modification and its status change (which `utime` can't set
    back)."""
    return max(info.st_mtime, info.st_ctime)


def changed_below(root: Path, since: float) -> list[str]:
    """Every file and folder below `root` (and `root`) that changed since `since`. Only metadata is read."""
    if not os.path.lexists(root):
        return []
    found = [str(root)] if changed_at(root.lstat()) >= since else []
    for folder, folders, files in os.walk(root):
        for name in (*folders, *files):
            path = Path(folder) / name
            try:
                if changed_at(path.lstat()) >= since:
                    found.append(str(path))
            except OSError:
                continue
    return found


def system_temp_folders() -> list[Path]:
    """The temporary folders of the system, and the cache folder of the user that macOS keeps next to them."""
    folders = {REAL_TEMP, Path(os.path.realpath("/tmp")), REAL_TEMP.parent / "C"}
    return sorted(folder for folder in folders if folder.is_dir())


# --- the sandbox --------------------------------------------------------------------------------------------


@dataclass
class Sandbox:
    """The folders of one leak test, its canary, and the time it started."""

    root: Path
    canary: str
    started: float
    pytest_root: Path
    real_duckdb: Path = REAL_DUCKDB

    @property
    def home(self) -> Path:
        return self.root / "home"

    @property
    def tmpdir(self) -> Path:
        return self.root / "tmp"

    @property
    def safetwin_home(self) -> Path:
        return self.root / "safetwin-home"

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def inbox(self) -> Path:
        return self.root / "inbox"

    @property
    def outbox(self) -> Path:
        return self.root / "outbox"

    @property
    def private(self) -> list[Path]:
        """The folders of the process: no file in them may hold the canary."""
        return [self.home, self.tmpdir, self.safetwin_home, self.work]

    def env(self, **more: str) -> dict[str, str]:
        """A fresh environment: the folders of the sandbox, and no SAFETWIN_DUCKDB_EXTENSIONS."""
        return {
            "PATH": "/usr/bin:/bin",
            "HOME": str(self.home),
            "TMPDIR": str(self.tmpdir),
            "SAFETWIN_HOME": str(self.safetwin_home),
            "LANG": "en_US.UTF-8",
            **more,
        }

    def write_csv(self, rows: int, *, wide: int = 0) -> None:
        """`rows` rows of id, name, city and note. The canary is in name, city and note (with `wide` more
        characters in name). Every tenth id is missing."""
        canary = self.canary
        with (self.inbox / "data.csv").open("w", encoding="utf-8") as file:
            file.write("id,name,city,note\n")
            for start in range(0, rows, 100_000):
                file.write(
                    "".join(
                        f"{'' if n % 10 == 0 else n}, {canary}-{n:07d}{'x' * wide} ,{canary} city {n % 7},"
                        f"note {canary} {n % 13}\n"
                        for n in range(start, min(start + 100_000, rows))
                    )
                )

    def command(self, pipeline: str, *options: str) -> list[str]:
        path = self.root / "pipeline.yaml"
        path.write_text(pipeline, encoding="utf-8")
        return [
            str(SAFETWIN),
            "run-local",
            str(path),
            "--socket",
            f"inbox={self.inbox}",
            "--socket",
            f"outbox={self.outbox}",
            *options,
        ]

    def run(self, pipeline: str, *options: str, **env: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                self.command(pipeline, *options),
                cwd=self.work,
                env=self.env(**env),
                capture_output=True,
                text=True,
                timeout=SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            pytest.fail(f"safetwin did not end in {SECONDS} s")

    def outbox_files(self) -> list[str]:
        return sorted(str(path.relative_to(self.outbox)) for path in self.outbox.rglob("*") if path.is_file())

    def assert_no_leak(self, stdout: str, stderr: str) -> None:
        """The checks of the module docs, except the ones about the outbox."""
        assert self.canary not in stdout + stderr, "the canary was printed"
        for root in self.private:  # a folder that is not there would make its scan pass for nothing
            assert root.is_dir(), f"{root} is missing"
        assert scan(self.canary, self.private) == [], "the canary is in a folder of the process"
        assert (
            scan(self.canary, system_temp_folders(), changed_since=self.started - 1, skip=[self.pytest_root])
            == []
        ), "the canary is in the system's temporary folder"
        assert not (self.home / ".duckdb").exists(), "DuckDB made ~/.duckdb"
        assert changed_below(self.real_duckdb, self.started - 1) == [], "the real ~/.duckdb changed"
        extensions = self.safetwin_home / "duckdb_extensions"
        assert not extensions.exists() or list(extensions.iterdir()) == []

    def assert_output(self, stdout: str) -> None:
        """The outbox holds one data file and its manifest, as the summary says; the manifest no canary."""
        run_id = re.search(r"^run (r[0-9a-f]{8}) of leak", stdout, re.MULTILINE)
        assert run_id is not None, stdout
        files = self.outbox_files()
        assert len(files) == 2, files
        assert files[1] == f"data/part-00000-{run_id[1]}.parquet"
        assert re.fullmatch(rf"data/_manifest/run=[0-9T-]+Z_{run_id[1]}\.json", files[0]), files
        assert not file_holds(self.outbox / files[0], needles(self.canary)), "the manifest holds the canary"


@pytest.fixture
def sandbox(tmp_path: Path, tmp_path_factory: pytest.TempPathFactory) -> Sandbox:
    made = Sandbox(tmp_path, f"CANARY-{secrets.token_hex(8)}", time.time(), tmp_path_factory.getbasetemp())
    for folder in (*made.private, made.inbox, made.outbox):
        folder.mkdir()
    os.chmod(made.safetwin_home, 0o700)  # the engine refuses a SAFETWIN_HOME that other users may use
    return made


# --- the scenarios ------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pipeline", "path"),
    [(POLARS_STEPS, "fused"), (POLARS_STEPS, "batch"), (DUCKDB_STEPS, "hybrid")],
    ids=["fused", "batch", "hybrid (transform.sql and transform.sort)"],
)
def test_a_run_that_succeeds_leaves_the_canary_only_in_its_data_file(
    sandbox: Sandbox, pipeline: str, path: str
) -> None:
    sandbox.write_csv(3000)
    done = sandbox.run(pipeline, "--path", path)
    assert done.returncode == 0, done.stderr
    assert f"stage 1: {path}, " in done.stdout
    sandbox.assert_output(done.stdout)
    sandbox.assert_no_leak(done.stdout, done.stderr)


def test_duckdb_running_out_of_memory_leaves_nothing(sandbox: Sandbox) -> None:
    sandbox.write_csv(400_000, wide=250)  # about 120 MB to sort, far more than the 48 MB DuckDB gets
    # DuckDB's own limit is what this checks: the watchdog samples once a second, so on a system that counts
    # memory otherwise (Linux: rss less shared pages) it can't stop the stage first. Both stops are safe.
    done = sandbox.run(SORT, "--memory-limit", "60MB", SAFETWIN_TEST_WATCHDOG_INTERVAL_S="1")
    assert done.returncode == 1
    *progress, line = done.stderr.splitlines()  # a slow machine shows a progress line or two first
    assert all(shown.startswith("stage 1 (") for shown in progress)
    assert line.startswith(
        "ERROR the DuckDB steps of this stage (ordered (transform.sort)) ran out of memory"
    )
    assert done.stdout == ""
    assert sandbox.outbox_files() == []
    sandbox.assert_no_leak(done.stdout, done.stderr)


def test_a_stage_that_the_watchdog_stops_leaves_nothing(sandbox: Sandbox) -> None:
    # Real memory: the batch path keeps a row group (up to a million rows) until it writes it, about 120 MB
    # here, far more than a limit of 40 MB. The stage is over in about 0.1 s, so the test asks the watchdog to
    # sample every 5 ms (an environment variable for tests only).
    sandbox.write_csv(400_000, wide=250)
    done = sandbox.run(
        COPY, "--path", "batch", "--memory-limit", "40MB", SAFETWIN_TEST_WATCHDOG_INTERVAL_S="0.005"
    )
    assert done.returncode == 1, done.stdout
    lines = done.stderr.splitlines()
    assert len(lines) == 1, [line.replace(sandbox.canary, "CANARY") for line in lines]
    (line,) = lines
    assert line == (
        "ERROR the stage of read (source.csv), write (sink.parquet) used more memory than it may (the limit "
        "is 40 MB), so it was stopped. Raise the memory limit (--memory-limit), or add a filter before the "
        "heavy step or select fewer columns so that less data reaches it."
    )
    assert done.stdout == ""
    assert sandbox.outbox_files() == []
    sandbox.assert_no_leak(done.stdout, done.stderr)


def test_a_cast_that_fails_in_duckdb_does_not_show_the_value_it_quotes(sandbox: Sandbox) -> None:
    sandbox.write_csv(500)
    done = sandbox.run(CAST)
    assert done.returncode == 1
    assert done.stderr.splitlines() == [
        "ERROR the run failed with ConversionException (its message can quote data, so it is not shown)"
    ]
    assert sandbox.outbox_files() == []
    sandbox.assert_no_leak(done.stdout, done.stderr)


@pytest.mark.parametrize("path", ["fused", "batch", "hybrid"])
def test_a_run_interrupted_with_ctrl_c_leaves_nothing(sandbox: Sandbox, path: str) -> None:
    sandbox.write_csv(2_000_000)
    pipeline = DUCKDB_STEPS if path == "hybrid" else POLARS_STEPS
    process = subprocess.Popen(
        sandbox.command(pipeline, "--path", path),
        cwd=sandbox.work,
        env=sandbox.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # A process that is started with SIGINT ignored (as a shell does for a job in the background) would
        # ignore Ctrl-C for ever: the child gets the default.
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
    )
    deadline = time.monotonic() + SECONDS
    while not any(".tmp-" in name for name in sandbox.outbox_files()):  # the stage is writing: interrupt it
        assert process.poll() is None, "the run ended before it could be interrupted"
        assert time.monotonic() < deadline
        time.sleep(0.001)
    process.send_signal(signal.SIGINT)
    try:
        stdout, stderr = process.communicate(timeout=SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        pytest.fail("safetwin did not end after Ctrl-C")
    assert process.returncode == 130, stderr
    assert (
        stderr.splitlines()[-1] == "ERROR the run was interrupted: the stage that was running wrote nothing"
    )
    assert stdout == ""
    assert sandbox.outbox_files() == []  # not even the temporary file
    sandbox.assert_no_leak(stdout, stderr)


def engine_request(
    port: int, token: str, method: str, path: str, body: bytes | None = None
) -> tuple[int, str]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=SECONDS)
    try:
        connection.request(method, path, body=body, headers={"Authorization": f"Bearer {token}"})
        response = connection.getresponse()
        return response.status, response.read().decode()
    finally:
        connection.close()


def test_the_engine_api_leaves_the_canary_nowhere_and_the_token_only_in_its_connection_file(
    sandbox: Sandbox,
) -> None:
    # The canary is in values of the pipeline (a node config string, the SQL of a step). The second and the
    # third pipelines also have problems (one the validator finds, one the schema does), so that the engine
    # writes messages about them.
    valid = DUCKDB_STEPS.replace('path: "*.csv"', f'path: "{sandbox.canary}-*.csv"').replace(
        "upper(note)", f"upper(note) || '{sandbox.canary}'"
    )
    unknown = valid.replace("transform.sort", "transform.nope")
    extra = valid.replace("spec:\n", f"spec:\n  note: {{text: {sandbox.canary}}}\n", 1)
    engine = subprocess.Popen(
        [str(SAFETWIN), "engine", "start"],
        cwd=sandbox.work,
        env=sandbox.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert engine.stdout is not None
        ready = engine.stdout.readline()
        assert ready.startswith("engine running on 127.0.0.1:"), ready
        connection_file = sandbox.safetwin_home / "engine.json"
        written = json.loads(connection_file.read_text())
        port, token = written["port"], written["token"]
        assert written["pid"] == engine.pid
        process = psutil.Process(engine.pid)
        assert not any(token in part for part in process.cmdline()), "the token is in the argv of the engine"
        assert not any(token in value for value in process.environ().values())

        answers = [
            engine_request(port, token, "POST", "/v1/validate", text.encode())
            for text in (valid, unknown, extra)
        ]
        assert [status for status, _ in answers] == [200, 200, 200]
        codes = [{problem["code"] for problem in json.loads(body)["problems"]} for _, body in answers]
        assert codes[0] <= {"inline_secret"}  # about a quarter of the canaries look like a secret to it
        assert "unknown_operator" in codes[1]
        assert codes[2] == {"extra_forbidden"}
        assert engine_request(port, token, "GET", "/v1/status")[0] == 200
        assert scan(token, sandbox.private) == [str(connection_file)], "the token is in another file"

        stopped = subprocess.run(
            [str(SAFETWIN), "engine", "stop"],
            cwd=sandbox.work,
            env=sandbox.env(),
            capture_output=True,
            text=True,
            timeout=SECONDS,
            check=False,
        )
        assert stopped.returncode == 0, stopped.stderr
        out, err = engine.communicate(timeout=SECONDS)
    finally:
        if engine.poll() is None:
            engine.kill()
            engine.wait()
    assert engine.returncode == 0
    printed = ready + out + err + stopped.stdout + stopped.stderr
    responses = "".join(body for _, body in answers)
    assert sandbox.canary not in responses, "the canary is in an answer of the engine"
    sandbox.assert_no_leak(printed + responses, "")
    assert token not in printed, "the token was printed"
    assert not connection_file.exists()
    assert scan(token, sandbox.private) == [], "the token is in a file"
    assert (
        scan(token, system_temp_folders(), changed_since=sandbox.started - 1, skip=[sandbox.pytest_root])
        == []
    ), "the token is in the system's temporary folder"


def test_a_run_through_the_engine_leaves_the_canary_only_in_its_data_file(sandbox: Sandbox) -> None:
    from websockets.sync.client import connect

    assert sandbox.canary not in POLARS_STEPS + CAST  # in the data only
    sandbox.write_csv(3000)
    engine = subprocess.Popen(
        [str(SAFETWIN), "engine", "start"],
        cwd=sandbox.work,
        env=sandbox.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    received: list[str] = []
    try:
        assert engine.stdout is not None
        ready = engine.stdout.readline()
        assert ready.startswith("engine running on 127.0.0.1:"), ready
        written = json.loads((sandbox.safetwin_home / "engine.json").read_text())
        port, token = written["port"], written["token"]
        with connect(f"ws://127.0.0.1:{port}/v1/events", open_timeout=5) as ws:
            ws.send(token)
            runs = [
                subprocess.run(
                    [str(SAFETWIN), "run", *sandbox.command(pipeline)[2:]],  # the arguments of run-local
                    cwd=sandbox.work,
                    env=sandbox.env(),
                    capture_output=True,
                    text=True,
                    timeout=SECONDS,
                    check=False,
                )
                for pipeline in (POLARS_STEPS, CAST)
            ]
            ended = 0
            while ended < 2:
                message = ws.recv(timeout=SECONDS)
                received.append(str(message))
                ended += json.loads(message)["type"] in ("run.finished", "run.failed", "run.cancelled")
        listing = engine_request(port, token, "GET", "/v1/runs")[1]
        details = [
            engine_request(port, token, "GET", f"/v1/runs/{run['run_id']}")[1]
            for run in json.loads(listing)["runs"]
        ]
        # The history, while the engine runs (the -wal and -shm files exist only then).
        database = sandbox.safetwin_home / "metadata.db"
        names = sorted(path.name for path in sandbox.safetwin_home.glob("metadata.db*"))
        assert names == ["metadata.db", "metadata.db-shm", "metadata.db-wal"]
        assert scan(sandbox.canary, [sandbox.safetwin_home]) == [], "the canary is in a file of SAFETWIN_HOME"
        assert database_values_holding(database, sandbox.canary) == [], "the canary is in the history"
        with sqlite3.connect(database) as history:  # the search above had something to search
            states = sorted(state for (state,) in history.execute("SELECT state FROM runs"))
            assert states == ["failed", "succeeded"]
            assert history.execute("SELECT count(*) FROM run_files").fetchone()[0] == 2  # data + manifest
            assert history.execute("SELECT error_class FROM runs WHERE state = 'failed'").fetchone() == (
                "ConversionException",
            )
        stopped = subprocess.run(
            [str(SAFETWIN), "engine", "stop"],
            env=sandbox.env(),
            capture_output=True,
            text=True,
            timeout=SECONDS,
            check=False,
        )
        assert stopped.returncode == 0, stopped.stderr
        out, err = engine.communicate(timeout=SECONDS)
    finally:
        if engine.poll() is None:
            engine.kill()
            engine.wait()
    succeeded, failed = runs
    assert succeeded.returncode == 0, succeeded.stderr
    sandbox.assert_output(succeeded.stdout)
    assert failed.returncode == 1
    assert failed.stderr.splitlines()[-1] == (
        "ERROR the run failed with ConversionException (its message can quote data, so it is not shown)"
    )
    assert sorted(json.loads(event)["type"] for event in received).count("stage.started") == 2
    printed = ready + out + err + stopped.stdout + stopped.stderr
    printed += "".join(run.stdout + run.stderr for run in runs)
    answers = listing + "".join(details) + "".join(received)
    assert sandbox.canary not in answers, "the canary is in an event or an answer of the engine"
    sandbox.assert_no_leak(printed + answers, "")
    tmp_root = sandbox.safetwin_home / "tmp"
    assert tmp_root.is_dir()
    assert list(tmp_root.iterdir()) == [], "a stage worker's folder is left"


# --- the scanner can fail -----------------------------------------------------------------------------------


def test_the_scanner_finds_a_canary_that_is_planted(sandbox: Sandbox) -> None:
    canary = sandbox.canary
    assert scan(canary, sandbox.private) == []
    (sandbox.tmpdir / "spill.bin").write_bytes(b"\x00" * 100 + canary.encode() + b"\x00")
    nested = sandbox.safetwin_home / "logs" / "2026" / "10"
    nested.mkdir(parents=True)
    (nested / "run.log").write_bytes(f"value={canary}".encode("utf-16-le"))
    split = sandbox.work / "split.bin"  # the canary across the boundary of two chunks
    split.write_bytes(b"x" * (CHUNK - 5) + canary.encode() + b"x")
    (sandbox.home / "link").symlink_to(sandbox.tmpdir / "spill.bin")  # a link is not followed
    assert sorted(scan(canary, sandbox.private)) == sorted(
        [str(sandbox.tmpdir / "spill.bin"), str(nested / "run.log"), str(split)]
    )
    with pytest.raises(AssertionError, match="the canary is in a folder of the process"):
        sandbox.assert_no_leak("", "")


def test_the_database_scanner_finds_a_canary_in_any_column(sandbox: Sandbox) -> None:
    database = sandbox.root / "planted.db"
    with sqlite3.connect(database) as planted:
        planted.execute("CREATE TABLE runs (id TEXT, error_class TEXT, n INTEGER)")
        planted.execute("CREATE TABLE blobs (data BLOB)")
        planted.execute("INSERT INTO runs VALUES ('r1', NULL, 1), ('r2', ?, 2)", (f"x{sandbox.canary}x",))
        planted.execute("INSERT INTO blobs VALUES (?)", (b"\x00" + sandbox.canary.encode() + b"\x00",))
    assert sorted(database_values_holding(database, sandbox.canary)) == ["blobs.data", "runs.error_class"]
    assert database_values_holding(database, "CANARY-not-there") == []


def test_the_scanner_finds_a_canary_in_the_system_temp_folder_but_only_in_new_files(sandbox: Sandbox) -> None:
    old = tempfile.NamedTemporaryFile(dir=REAL_TEMP, prefix="safetwin-leak-selftest-", delete=False)  # noqa: SIM115
    with old:
        old.write(sandbox.canary.encode())
    time.sleep(0.05)
    since = time.time()  # the old file changed before this...
    time.sleep(0.05)
    fresh = tempfile.NamedTemporaryFile(dir=REAL_TEMP, prefix="safetwin-leak-selftest-", delete=False)  # noqa: SIM115
    backdated = tempfile.NamedTemporaryFile(dir=REAL_TEMP, prefix="safetwin-leak-selftest-", delete=False)  # noqa: SIM115
    try:
        with fresh, backdated:  # ...and these after it
            fresh.write(sandbox.canary.encode())
            backdated.write(sandbox.canary.encode())
        # A file whose modification time is set back still changed now: its status change time says so.
        os.utime(backdated.name, (since - 3600, since - 3600))
        found = scan(sandbox.canary, system_temp_folders(), changed_since=since, skip=[sandbox.pytest_root])
        assert sorted(os.path.realpath(path) for path in found) == sorted(
            [os.path.realpath(fresh.name), os.path.realpath(backdated.name)]
        )
        with pytest.raises(AssertionError, match="system's temporary folder"):
            sandbox.assert_no_leak("", "")
    finally:
        for made in (old, fresh, backdated):
            os.unlink(made.name)


def test_the_system_temp_folders_include_the_cache_folder_of_macos_and_not_the_sandbox() -> None:
    folders = system_temp_folders()
    assert REAL_TEMP in folders
    cache = REAL_TEMP.parent / "C"
    assert (cache in folders) == cache.is_dir()
    if sys.platform == "darwin":
        assert cache in folders


def test_a_change_below_the_real_duckdb_folder_is_found(sandbox: Sandbox) -> None:
    # The real ~/.duckdb is never touched: a folder of the test stands in for it.
    fake = sandbox.root / "real-duckdb"
    (fake / "extensions" / "v1.5.6").mkdir(parents=True)
    (fake / "extensions" / "v1.5.6" / "icu.duckdb_extension").write_bytes(b"old")
    time.sleep(0.05)
    since = time.time()
    time.sleep(0.05)
    stand_in = dataclasses.replace(sandbox, real_duckdb=fake, started=since + 1)  # the check allows 1 s
    stand_in.assert_no_leak("", "")  # nothing changed since
    (fake / "extensions" / "v1.5.6" / "httpfs.duckdb_extension").write_bytes(b"new")
    assert sorted(changed_below(fake, since)) == [
        str(fake / "extensions" / "v1.5.6"),
        str(fake / "extensions" / "v1.5.6" / "httpfs.duckdb_extension"),
    ]
    with pytest.raises(AssertionError, match=r"the real ~/\.duckdb changed"):
        stand_in.assert_no_leak("", "")
    assert changed_below(sandbox.root / "nowhere", since) == []


def test_a_private_folder_that_is_missing_fails_the_check(sandbox: Sandbox) -> None:
    sandbox.tmpdir.rmdir()
    with pytest.raises(AssertionError, match="is missing"):
        sandbox.assert_no_leak("", "")


def test_the_scanner_leaves_out_the_inbox_and_finds_what_is_printed_and_a_duckdb_folder(
    sandbox: Sandbox,
) -> None:
    sandbox.write_csv(10)  # the inbox, which holds the canary, is not a folder of the process
    sandbox.assert_no_leak("", "")
    with pytest.raises(AssertionError, match="the canary was printed"):
        sandbox.assert_no_leak("", f"ERROR {sandbox.canary}")
    (sandbox.home / ".duckdb" / "extensions").mkdir(parents=True)
    with pytest.raises(AssertionError, match=r"DuckDB made ~/\.duckdb"):
        sandbox.assert_no_leak("", "")


# --- safetwin key, check and mask (M1a) ---------------------------------------------------------------------

LEAK_POLICY = """\
apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {{name: leak}}
spec:
  source: {{folder: {inbox}, format: csv}}
  target: {{folder: {outbox}, format: parquet}}
  key: file://{key}
  tables:
    data:
      id: {{method: pseudonymize, prefix: i_}}
      name: {{method: pseudonymize}}
      city: {{method: fake, kind: city}}
{note}
"""
NOTE_MASKED = '      note: {method: redact, with: "[REDACTED]"}'


def safetwin(sandbox: Sandbox, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [str(SAFETWIN), *args],
            cwd=sandbox.work,
            env=sandbox.env(),
            capture_output=True,
            text=True,
            timeout=SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail(f"safetwin did not end in {SECONDS} s")


def make_key(sandbox: Sandbox) -> tuple[Path, str]:
    """`safetwin key new --file` in the sandbox's home: the key file and the key's hex."""
    path = sandbox.home / "leak.key"
    done = safetwin(sandbox, "key", "new", "--file", str(path))
    assert done.returncode == 0, done.stderr
    key_hex = path.read_text(encoding="ascii").strip()
    assert key_hex not in done.stdout + done.stderr
    return path, key_hex


def leak_policy(sandbox: Sandbox, key: Path, note: str = NOTE_MASKED) -> Path:
    path = sandbox.root / "masking.yaml"
    path.write_text(
        LEAK_POLICY.format(inbox=sandbox.inbox, outbox=sandbox.outbox, key=key, note=note), encoding="utf-8"
    )
    return path


def assert_key_only_in_its_file(sandbox: Sandbox, key_file: Path, key_hex: str, *outputs: str) -> None:
    for output in outputs:
        assert key_hex not in output, "the key was printed"
        assert key_hex.upper() not in output, "the key was printed"
    roots = [*sandbox.private, sandbox.outbox, sandbox.root / "masking.yaml"]
    hits = [hit for root in roots for hit in scan(key_hex, [root] if root.is_dir() else [root.parent])]
    assert sorted(set(hits)) == [str(key_file)], hits
    temp = scan(key_hex, system_temp_folders(), changed_since=sandbox.started - 1, skip=[sandbox.pytest_root])
    assert temp == [], "the key is in the system's temporary folder"


def test_key_new_writes_the_key_to_its_file_only(sandbox: Sandbox) -> None:
    key_file, key_hex = make_key(sandbox)
    assert_key_only_in_its_file(sandbox, key_file, key_hex)
    printed = safetwin(sandbox, "key", "new", "--print")
    assert printed.returncode == 0
    assert scan(printed.stdout.strip(), [*sandbox.private]) == []  # a printed key is written nowhere


def test_check_and_mask_leave_the_canary_only_where_it_was_and_the_key_only_in_its_file(
    sandbox: Sandbox,
) -> None:
    sandbox.write_csv(3000)
    key_file, key_hex = make_key(sandbox)
    policy = leak_policy(sandbox, key_file)
    checked = safetwin(sandbox, "check", str(policy))
    assert checked.returncode == 0, checked.stderr
    done = safetwin(sandbox, "mask", str(policy))
    assert done.returncode == 0, done.stderr
    files = sandbox.outbox_files()
    assert files[-2:] == ["report.html", "report.json"], files
    assert len(files) == 4, files
    # Every column that held the canary was masked, so the canary is nowhere in the outbox: not in the twin,
    # the manifest or the report.
    assert scan(sandbox.canary, [sandbox.outbox]) == []
    for output in (checked, done):
        sandbox.assert_no_leak(output.stdout, output.stderr)
    assert_key_only_in_its_file(
        sandbox, key_file, key_hex, checked.stdout, checked.stderr, done.stdout, done.stderr
    )


def test_a_mask_that_fails_its_checks_leaves_the_canary_nowhere(sandbox: Sandbox) -> None:
    sandbox.write_csv(500)
    key_file, key_hex = make_key(sandbox)
    # A note kept in a column the policy calls masked would be found by the residual scan only with an email
    # in it; the canary has none, so the failure here is a column the policy doesn't name.
    policy = leak_policy(sandbox, key_file, note="")
    done = safetwin(sandbox, "mask", str(policy))
    assert done.returncode == 1
    (line,) = done.stderr.splitlines()
    assert line.startswith("ERROR [unknown_column] table 'data': the policy names no method for 'note'")
    assert sandbox.outbox_files() == []
    sandbox.assert_no_leak(done.stdout, done.stderr)
    assert_key_only_in_its_file(sandbox, key_file, key_hex, done.stdout, done.stderr)


def test_a_mask_interrupted_with_ctrl_c_leaves_nothing(sandbox: Sandbox) -> None:
    sandbox.write_csv(2_000_000)
    key_file, key_hex = make_key(sandbox)
    policy = leak_policy(sandbox, key_file)
    process = subprocess.Popen(
        [str(SAFETWIN), "mask", str(policy)],
        cwd=sandbox.work,
        env=sandbox.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
    )
    deadline = time.monotonic() + SECONDS
    while not any(".tmp-" in name for name in sandbox.outbox_files()):
        assert process.poll() is None, "the run ended before it could be interrupted"
        assert time.monotonic() < deadline
        time.sleep(0.001)
    process.send_signal(signal.SIGINT)
    try:
        stdout, stderr = process.communicate(timeout=SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        pytest.fail("safetwin did not end after Ctrl-C")
    assert process.returncode == 130, stderr
    assert stderr.splitlines()[-1] == "ERROR the run was interrupted: nothing was left in the output folder"
    assert sandbox.outbox_files() == []
    sandbox.assert_no_leak(stdout, stderr)
    assert_key_only_in_its_file(sandbox, key_file, key_hex, stdout, stderr)


def test_scan_leaves_the_canary_nowhere(sandbox: Sandbox) -> None:
    sandbox.write_csv(3000)
    draft = sandbox.outbox / "masking.yaml"
    written = safetwin(sandbox, "scan", str(sandbox.inbox), "-o", str(draft))
    assert written.returncode == 0, written.stderr
    printed = safetwin(sandbox, "scan", str(sandbox.inbox))
    assert printed.returncode == 0, printed.stderr
    assert sandbox.outbox_files() == ["masking.yaml"]
    assert scan(sandbox.canary, [sandbox.outbox]) == []
    for output in (written, printed):
        sandbox.assert_no_leak(output.stdout, output.stderr)


def test_export_and_the_exported_script_leave_the_canary_and_the_key_nowhere(sandbox: Sandbox) -> None:
    sandbox.write_csv(3000)
    key_file, key_hex = make_key(sandbox)
    policy = leak_policy(sandbox, key_file)
    script = sandbox.root / "mask_leak.py"
    exported = safetwin(sandbox, "export", str(policy), "-o", str(script))
    assert exported.returncode == 0, exported.stderr
    text = script.read_text(encoding="utf-8")
    assert sandbox.canary not in text
    assert key_hex not in text
    done = subprocess.run(
        [sys.executable, str(script)],
        cwd=sandbox.work,
        env=sandbox.env(),
        capture_output=True,
        text=True,
        timeout=SECONDS,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert sandbox.outbox_files() == ["data.parquet"]
    assert scan(sandbox.canary, [sandbox.outbox]) == []
    for output in (exported, done):
        sandbox.assert_no_leak(output.stdout, output.stderr)
    outputs = (exported.stdout, exported.stderr, done.stdout, done.stderr)
    assert_key_only_in_its_file(sandbox, key_file, key_hex, *outputs)


# --- Excel through the staging folder, and the page (1.0) ---------------------------------------------------


def staging_left(sandbox: Sandbox) -> list[str]:
    """Folders a run copies data into for a while: the staging folder of a Postgres or Excel run, the
    workspace of `safetwin ui`. Their Parquet is compressed, where a search of the bytes may not see the
    canary, so they must be gone."""
    return [
        p.name for p in sandbox.tmpdir.iterdir() if p.name.startswith(("safetwin-stage-", "safetwin-ui-"))
    ]


def test_excel_in_and_out_leaves_the_canary_nowhere_and_no_staging_folder(sandbox: Sandbox) -> None:
    import polars as pl

    sandbox.write_csv(3000)
    source = sandbox.inbox / "data.csv"
    pl.read_csv(source).write_excel(sandbox.inbox / "data.xlsx", worksheet="data")
    source.unlink()
    key_file, key_hex = make_key(sandbox)
    policy = leak_policy(sandbox, key_file)
    text = policy.read_text(encoding="utf-8")
    text = text.replace("format: csv}", "format: xlsx}").replace("format: parquet}", "format: xlsx}")
    policy.write_text(text.replace("{method: pseudonymize, prefix: i_}", "{method: pseudonymize}"), "utf-8")
    checked = safetwin(sandbox, "check", str(policy))
    assert checked.returncode == 0, checked.stderr
    done = safetwin(sandbox, "mask", str(policy))
    assert done.returncode == 0, done.stderr
    assert sandbox.outbox_files() == ["data.xlsx", "report.html", "report.json"]
    assert scan(sandbox.canary, [sandbox.outbox]) == []
    assert staging_left(sandbox) == []
    for output in (checked, done):
        sandbox.assert_no_leak(output.stdout, output.stderr)
    assert_key_only_in_its_file(
        sandbox, key_file, key_hex, checked.stdout, checked.stderr, done.stdout, done.stderr
    )


def test_the_page_leaves_the_canary_nowhere_once_it_stops(sandbox: Sandbox) -> None:
    import httpx

    sandbox.write_csv(3000)
    process = subprocess.Popen(
        [str(SAFETWIN), "ui", "--no-browser"],
        cwd=sandbox.work,
        env=sandbox.env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
    )
    try:
        assert process.stdout is not None
        line = process.stdout.readline()
        address = re.search(r"open (http://127\.0\.0\.1:\d+)/#token=(\S+)", line)
        assert address is not None, line
        base, token = address[1], address[2]
        answers: list[str] = []
        with httpx.Client(base_url=base, timeout=SECONDS, headers={"X-Safetwin": "1"}) as client:
            assert client.post("/api/login", json={"token": token}).status_code == 200
            phrase = f"leak test passphrase {sandbox.canary}"  # the key it makes, and it, must stay in memory
            chosen = client.post("/api/key", json={"mode": "passphrase", "value": phrase})
            assert chosen.status_code == 200, chosen.text
            job = client.post("/api/jobs").json()["id"]
            put = client.put(
                f"/api/jobs/{job}/files/data.csv", content=(sandbox.inbox / "data.csv").read_bytes()
            )
            assert put.status_code == 200, put.text
            plan = client.post(f"/api/jobs/{job}/scan")
            answers.append(plan.text)
            picked = {"data": {"id": "siv", "name": "ff1an", "city": "gcm", "note": "drop"}}
            body = {"choices": {"data": "reversible"}, "picked": picked}
            for path in ("preview", "mask"):
                answer = client.post(f"/api/jobs/{job}/{path}", json=body)
                assert answer.status_code == 200, answer.text
                answers.append(answer.text)
            answers.append(client.get(f"/api/jobs/{job}/report").text)
            answers.append(client.get("/api/history").text)
        assert not any(sandbox.canary in answer for answer in answers), (
            "an answer of the page holds the canary"
        )
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=SECONDS)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert staging_left(sandbox) == []
    assert (sandbox.safetwin_home / "ui-history").is_dir()  # the report is kept, without a value
    sandbox.assert_no_leak(line + stdout, stderr)
    from safetwin.keys import key_from_passphrase

    key_hex = key_from_passphrase(phrase).hex_for_key_file()
    for secret in (phrase, key_hex):
        assert scan(secret, sandbox.private) == [], "the page's key or passphrase was written to a file"
        assert secret not in line + stdout + stderr
