"""Runs through the engine's control API, with the engine in a process of its own and real stage workers.

Each test starts the engine (`python -m safetwin.api.server`, through a small driver that can change the
executor's settings first) with a folder of the app of its own, and stops it at the end, whatever happens.
"""

import hashlib
import http.client
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import polars as pl
import pytest
from websockets.sync.client import ClientConnection, connect

from safetwin.api.connection import ConnectionInfo, connection_path, read_connection_file

SECONDS = 60
CANARY = "CANARY-5b2e7d-never-echoed"
ENDING = {"run.finished", "run.failed", "run.cancelled"}

DRIVER = """
import sys
from safetwin.executor import settings
settings.WARM_WORKER_S = {warm}
settings.CANCEL_GRACE_S = {grace}
from safetwin.api import server
sys.exit(server.main({argv!r}))
"""

HEAD = """\
apiVersion: safetwin/v1
kind: Pipeline
metadata:
  name: {name}
spec:
  sockets:
    inbox: socket://local-inbox
    outbox: socket://local-outbox
  nodes:
    - {{id: read, operator: source.csv, socket: inbox, config: {{path: "*.csv"}}}}
"""
CLEAN = (
    HEAD.format(name="clean")
    + """\
    - {id: keep, operator: transform.filter, inputs: [read], config: {expr: "id IS NOT NULL"}}
    - {id: tidy, operator: transform.trim, inputs: [keep], config: {columns: [name, city]}}
    - {id: write, operator: sink.parquet, inputs: [tidy], socket: outbox, config: {path: data/}}
"""
)
TWO_STAGES = (
    HEAD.format(name="two-stages")
    + """\
    - {id: raw, operator: sink.parquet, inputs: [read], socket: outbox, config: {path: raw/}}
    - {id: keep, operator: transform.filter, inputs: [raw], config: {expr: "id IS NOT NULL"}}
    - {id: clean, operator: sink.parquet, inputs: [keep], socket: outbox, config: {path: clean/}}
"""
)
SORT = (
    HEAD.format(name="sort")
    + """\
    - {id: ordered, operator: transform.sort, inputs: [read], config: {by: [name, id]}}
    - {id: write, operator: sink.parquet, inputs: [ordered], socket: outbox, config: {path: data/}}
"""
)
COPY = (
    HEAD.format(name="copy")
    + """\
    - {id: write, operator: sink.parquet, inputs: [read], socket: outbox, config: {path: data/}}
"""
)


def write_csv(path: Path, rows: int, *, wide: int = 0) -> Path:
    """`rows` rows of id, name, city and note; every tenth id is missing."""
    with path.open("w", encoding="utf-8") as file:
        file.write("id,name,city,note\n")
        for start in range(0, rows, 100_000):
            file.write(
                "".join(
                    f"{'' if n % 10 == 0 else n}, name-{n:07d}{'x' * wide} , city {n % 7} ,note {n % 13}\n"
                    for n in range(start, min(start + 100_000, rows))
                )
            )
    return path


@pytest.fixture(scope="module")
def big_csv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A CSV that takes a stage about a second (2M rows, ~70 MB), made once for the module."""
    return write_csv(tmp_path_factory.mktemp("big") / "big.csv", 2_000_000)


@dataclass
class Folders:
    inbox: Path
    outbox: Path

    @property
    def sockets(self) -> dict[str, str]:
        return {"inbox": str(self.inbox), "outbox": str(self.outbox)}

    def written(self) -> list[str]:
        return sorted(str(p.relative_to(self.outbox)) for p in self.outbox.rglob("*") if p.is_file())


@pytest.fixture
def folders(tmp_path: Path) -> Folders:
    made = Folders(tmp_path / "in", tmp_path / "out")
    made.inbox.mkdir()
    made.outbox.mkdir()
    return made


def link_big(folders: Folders, big_csv: Path) -> None:
    os.link(big_csv, folders.inbox / "big.csv")  # a symlink would lead out of the socket: refused


@dataclass
class Engine:
    process: subprocess.Popen[str]
    info: ConnectionInfo
    home: Path

    def request(self, method: str, path: str, body: Any = None) -> tuple[int, Any]:
        connection = http.client.HTTPConnection("127.0.0.1", self.info.port, timeout=SECONDS)
        headers = {"Authorization": f"Bearer {self.info.token}", "Content-Type": "application/json"}
        try:
            data = None if body is None else json.dumps(body).encode()
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
        finally:
            connection.close()

    def submit(self, pipeline: str, folders: Folders, **options: Any) -> str:
        status, answer = self.request(
            "POST", "/v1/runs", {"pipeline_yaml": pipeline, "sockets": folders.sockets, **options}
        )
        assert status == 202, answer
        assert answer["state"] == "queued"
        return str(answer["run_id"])

    def run(self, run_id: str) -> dict[str, Any]:
        status, record = self.request("GET", f"/v1/runs/{run_id}")
        assert status == 200
        return dict(record)

    def wait(self, run_id: str, *states: str) -> dict[str, Any]:
        deadline = time.monotonic() + SECONDS
        while (record := self.run(run_id))["state"] not in (states or ("succeeded", "failed", "cancelled")):
            assert time.monotonic() < deadline, record["state"]
            time.sleep(0.02)
        return record

    def wait_for_stage_worker(self, run_id: str) -> dict[str, Any]:
        deadline = time.monotonic() + SECONDS
        while True:
            record = self.run(run_id)
            if record["stages"] and record["stages"][0]["worker_pid"]:
                return record
            assert time.monotonic() < deadline
            time.sleep(0.01)

    @contextmanager
    def websocket(self) -> Iterator[ClientConnection]:
        with connect(f"ws://127.0.0.1:{self.info.port}/v1/events", open_timeout=5) as ws:
            ws.send(self.info.token)
            assert json.loads(ws.recv(timeout=5))["type"] == "hello"
            yield ws

    def status(self) -> dict[str, Any]:
        return dict(self.request("GET", "/v1/status")[1])


def events_of(ws: ClientConnection, *run_ids: str) -> list[dict[str, Any]]:
    """The events of these runs, in the order they came, until each has ended."""
    left = set(run_ids)
    found = []
    while left:
        event = json.loads(ws.recv(timeout=SECONDS))
        if event["data"].get("run_id") in run_ids:
            found.append(event)
            if event["type"] in ENDING:
                left.discard(event["data"]["run_id"])
    return found


def start_engine(home: Path, tmp_path: Path, *, warm: float = 60.0, grace: float = 5.0, **env: str) -> Engine:
    home.mkdir(mode=0o700, exist_ok=True)
    os.chmod(home, 0o700)
    script = tmp_path / "engine_driver.py"
    script.write_text(DRIVER.format(warm=warm, grace=grace, argv=["--memory-limit", "4GB"]))
    process = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "SAFETWIN_HOME": str(home), **env},
    )
    assert process.stdout is not None
    line = process.stdout.readline()
    if not line.startswith("engine running"):
        process.kill()
        pytest.fail("the engine did not start")
    info = read_connection_file(connection_path(home))
    assert info is not None
    return Engine(process, info, home)


def stop_engine(engine: Engine) -> tuple[str, str]:
    if engine.process.poll() is None:
        engine.process.send_signal(signal.SIGTERM)
    try:
        return engine.process.communicate(timeout=SECONDS)
    except subprocess.TimeoutExpired:
        engine.process.kill()
        return engine.process.communicate()


@pytest.fixture
def engine(request: pytest.FixtureRequest, safetwin_home: Path, tmp_path: Path) -> Iterator[Engine]:
    """The engine. Parametrize it (indirect) with a dict: `warm` (seconds), `grace`, and `env`."""
    options = dict(getattr(request, "param", {}))
    env = options.pop("env", {})
    made = start_engine(safetwin_home, tmp_path, **options, **env)
    try:
        yield made
    finally:
        out, err = stop_engine(made)
        assert made.process.returncode == 0, err
        assert (
            list((safetwin_home / "tmp").iterdir()) == []
        )  # every worker's folder is gone once it has stopped
        assert CANARY not in out + err


def sha256(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- runs that succeed --------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["fused", "batch"])
def test_a_run_through_the_api_writes_what_run_local_writes_and_says_so_in_order(
    engine: Engine, folders: Folders, tmp_path: Path, path: str
) -> None:
    from safetwin.dataplane.run import run_pipeline_local
    from safetwin.spec import load_pipeline_text

    write_csv(folders.inbox / "people.csv", 50_000)
    with engine.websocket() as ws:
        run_id = engine.submit(CLEAN, folders, path=path)
        events = events_of(ws, run_id)
    kinds = [event["type"] for event in events]
    progress = kinds.count("stage.progress")
    assert kinds == ["run.queued", "run.started", "stage.started", *["stage.progress"] * progress,
                     "stage.finished", "run.finished"]  # fmt: skip
    record = engine.run(run_id)
    assert record["state"] == "succeeded"
    (stage,) = record["stages"]
    assert stage["path"] == path
    assert stage["node_ids"] == ["read", "keep", "tidy", "write"]
    assert stage["rows_per_node"] == {"read": 50_000, "keep": 45_000, "tidy": 45_000, "write": 45_000}
    assert stage["attempt"] == 1
    (file,) = stage["files"]
    assert file["path"] == str(folders.outbox.resolve() / "data" / f"part-00000-{run_id}.parquet")
    assert file["sha256"] == sha256(file["path"])
    assert record["totals"] == {"rows": 45_000, "bytes": file["bytes"], "files": 1}
    assert events[-1]["data"]["totals"] == record["totals"]
    assert events[-2]["data"]["files"] == stage["files"]

    local = Folders(tmp_path / "in", tmp_path / "local-out")
    local.outbox.mkdir()
    result = run_pipeline_local(load_pipeline_text(CLEAN), {"inbox": local.inbox, "outbox": local.outbox},
                                force_path=path)  # type: ignore[arg-type]  # fmt: skip
    local_file = result.stages[0].files[0]
    assert pl.read_parquet(local_file.path).equals(pl.read_parquet(file["path"]))
    assert result.stages[0].rows_per_node == stage["rows_per_node"]
    if path == "batch":  # PyArrow's writer is deterministic: the same bytes
        assert local_file.sha256 == file["sha256"]


def test_a_pipeline_of_two_stages_runs_in_two_workers(engine: Engine, folders: Folders) -> None:
    write_csv(folders.inbox / "people.csv", 1_000)
    record = engine.wait(engine.submit(TWO_STAGES, folders))
    assert record["state"] == "succeeded", record
    first, second = record["stages"]
    assert first["worker_id"] != second["worker_id"]
    assert first["worker_pid"] != second["worker_pid"]
    assert first["finished_at"] <= second["started_at"]
    assert first["rows_per_node"] == {"read": 1_000, "raw": 1_000}
    assert second["rows_per_node"] == {"keep": 900, "clean": 900}
    assert [stage["worker_start"] for stage in record["stages"]] == ["cold", "warm"]
    assert record["totals"]["files"] == 2


def test_three_runs_at_once_run_two_at_a_time_and_the_third_waits(
    engine: Engine, folders: Folders, big_csv: Path
) -> None:
    link_big(folders, big_csv)
    with engine.websocket() as ws:
        run_ids = [engine.submit(COPY, folders) for _ in range(3)]
        assert engine.run(run_ids[2])["state"] == "queued"
        assert engine.status()["runs"]["queued"] == 1
        events = events_of(ws, *run_ids)
    active, most = 0, 0
    for event in events:
        active += {"run.started": 1}.get(event["type"], 0) - (event["type"] in ENDING)
        most = max(most, active)
    assert most == 2
    third = [event["type"] for event in events if event["data"]["run_id"] == run_ids[2]]
    assert third[0] == "run.queued"
    started_third = next(
        i for i, e in enumerate(events) if e["type"] == "run.started" and e["data"]["run_id"] == run_ids[2]
    )
    assert any(event["type"] in ENDING for event in events[:started_third])  # fmt: skip
    assert [engine.run(run_id)["state"] for run_id in run_ids] == ["succeeded"] * 3


# --- cancelling ---------------------------------------------------------------------------------------------


def wait_for_temporary_file(folders: Folders) -> None:
    deadline = time.monotonic() + SECONDS
    while not any(".tmp-" in name for name in folders.written()):
        assert time.monotonic() < deadline, "the stage never started writing"
        time.sleep(0.002)


def assert_gone(pid: int) -> None:
    deadline = time.monotonic() + 5
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        assert time.monotonic() < deadline, f"pid {pid} is still there"
        time.sleep(0.01)


def test_cancelling_a_run_leaves_no_file_no_worker_and_no_folder(
    engine: Engine, folders: Folders, big_csv: Path, safetwin_home: Path
) -> None:
    link_big(folders, big_csv)
    run_id = engine.submit(COPY, folders)
    record = engine.wait_for_stage_worker(run_id)
    worker_id, pid = record["stages"][0]["worker_id"], record["stages"][0]["worker_pid"]
    wait_for_temporary_file(folders)
    with engine.websocket() as ws:
        assert engine.request("POST", f"/v1/runs/{run_id}/cancel") == (
            202,
            {"run_id": run_id, "state": "cancelling"},
        )
        events = events_of(ws, run_id)
    record = engine.run(run_id)
    assert record["state"] == "cancelled"
    assert record["stages"][0]["state"] == "cancelled"
    assert [event["type"] for event in events][-2:] == ["stage.finished", "run.cancelled"]
    assert folders.written() == []  # no temporary file and no data file
    assert_gone(pid)
    assert not (safetwin_home / "tmp" / worker_id).exists()
    assert engine.request("POST", f"/v1/runs/{run_id}/cancel") == (409, {"error": "run_ended"})


def test_a_queued_run_is_cancelled_at_once(engine: Engine, folders: Folders, big_csv: Path) -> None:
    link_big(folders, big_csv)
    first, second, third = (engine.submit(COPY, folders) for _ in range(3))
    assert engine.request("POST", f"/v1/runs/{third}/cancel") == (
        202,
        {"run_id": third, "state": "cancelled"},
    )
    record = engine.run(third)
    assert record["state"] == "cancelled"
    assert record["started_at"] is None
    assert record["stages"] == []
    for run_id in (first, second):
        assert engine.wait(run_id)["state"] == "succeeded"


# --- failures -----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("engine", [{"warm": 0.0}], indirect=True)
def test_a_worker_killed_mid_stage_fails_the_run_cleanly_and_the_engine_goes_on(
    engine: Engine, folders: Folders, big_csv: Path, safetwin_home: Path
) -> None:
    link_big(folders, big_csv)
    run_id = engine.submit(COPY, folders)
    record = engine.wait_for_stage_worker(run_id)
    worker_id, pid = record["stages"][0]["worker_id"], record["stages"][0]["worker_pid"]
    wait_for_temporary_file(folders)
    os.kill(pid, signal.SIGKILL)
    record = engine.wait(run_id)
    assert (record["state"], record["error_class"], record["error"]) == (
        "failed",
        "WorkerStopped",
        "the stage worker stopped (signal 9)",
    )
    assert record["stages"][0]["state"] == "failed"
    assert folders.written() == []  # its temporary file was removed by the control plane
    assert not (safetwin_home / "tmp" / worker_id).exists()
    following = engine.wait(engine.submit(COPY, folders))
    assert following["state"] == "succeeded"
    assert engine.status()["runs"] == {
        "active": 0, "queued": 0, "workers_running": 0, "workers_idle": 0, "memory_limit_bytes": 4_000_000_000
    }  # fmt: skip


# DuckDB's own limit is what this checks: the watchdog samples once a second, so on a slow machine (a shared
# CI runner, say) it can't stop the stage first. Both stops are safe.
@pytest.mark.parametrize("engine", [{"env": {"SAFETWIN_TEST_WATCHDOG_INTERVAL_S": "1"}}], indirect=True)
def test_duckdb_running_out_of_memory_arrives_as_its_safe_message(engine: Engine, folders: Folders) -> None:
    write_csv(folders.inbox / "wide.csv", 400_000, wide=250)  # about 120 MB to sort
    sorted_run = engine.wait(engine.submit(SORT, folders, memory_limit="60MB"))
    assert sorted_run["state"] == "failed"
    assert sorted_run["error_class"] == "OutOfMemory"
    assert sorted_run["error"].startswith(
        "the DuckDB steps of this stage (ordered (transform.sort)) ran out of memory (the limit is 60 MB)"
    )
    assert folders.written() == []


@pytest.mark.parametrize("engine", [{"env": {"SAFETWIN_TEST_WATCHDOG_INTERVAL_S": "0.005"}}], indirect=True)
def test_the_memory_limit_of_a_stage_arrives_as_its_safe_message(engine: Engine, folders: Folders) -> None:
    write_csv(folders.inbox / "wide.csv", 400_000, wide=250)  # about 120 MB in a row group of the batch path
    copied = engine.wait(engine.submit(COPY, folders, memory_limit="40MB", path="batch"))
    assert (copied["state"], copied["error_class"]) == ("failed", "MemoryLimitReached")
    assert copied["error"] == (
        "the stage of read (source.csv), write (sink.parquet) used more memory than it may (the limit is "
        "40 MB), so it was stopped. Raise the memory limit (--memory-limit), or add a filter before the "
        "heavy step or select fewer columns so that less data reaches it."
    )
    assert copied["memory_limit_bytes"] == 40_000_000
    assert folders.written() == []


def test_a_bad_request_is_refused_without_repeating_it(
    engine: Engine, folders: Folders, tmp_path: Path
) -> None:
    bad = CLEAN.replace("transform.trim", "transform.nope").replace(
        '"id IS NOT NULL"', f"\"note = '{CANARY}'\""
    )
    status, answer = engine.request("POST", "/v1/runs", {"pipeline_yaml": bad, "sockets": folders.sockets})
    assert status == 422
    assert answer["error"] == "invalid_pipeline"
    assert answer["valid"] is False
    assert "unknown_operator" in {problem["code"] for problem in answer["problems"]}
    assert CANARY not in json.dumps(answer)
    missing = tmp_path / f"{CANARY}.yaml"
    status, answer = engine.request("POST", "/v1/runs", {"pipeline_path": str(missing), "sockets": {}})
    assert (status, answer) == (404, {"error": "pipeline_not_found"})
    status, answer = engine.request("POST", "/v1/runs", {"pipeline_path": f"{CANARY}.yaml", "sockets": {}})
    assert status == 422
    assert answer == {
        "error": "invalid_request",
        "problems": [{"loc": ["body", "pipeline_path"], "type": "not_absolute"}],
    }
    status, answer = engine.request("POST", "/v1/runs", {"pipeline_yaml": CLEAN, "pipeline_path": "/x"})
    assert status == 422
    assert CANARY not in json.dumps(answer)
    status, answer = engine.request(
        "POST", "/v1/runs", {"pipeline_yaml": CLEAN, "sockets": {"inbox": CANARY}, "memory_limit": CANARY}
    )
    assert status == 422
    assert {problem["type"] for problem in answer["problems"]} == {"not_absolute", "invalid_size"}
    assert CANARY not in json.dumps(answer)
    assert engine.request("GET", f"/v1/runs/{CANARY}") == (404, {"error": "run_not_found"})
    assert engine.request("POST", f"/v1/runs/{CANARY}/cancel") == (404, {"error": "run_not_found"})
    assert engine.request("GET", "/v1/runs") == (200, {"runs": [], "next_before": None})


def test_a_pipeline_file_is_read_by_the_engine_and_a_planning_error_fails_the_run_safely(
    engine: Engine, folders: Folders, tmp_path: Path
) -> None:
    write_csv(folders.inbox / "people.csv", 100)
    pipeline = tmp_path / "clean.yaml"
    pipeline.write_text(CLEAN)
    status, answer = engine.request(
        "POST", "/v1/runs", {"pipeline_path": str(pipeline), "sockets": folders.sockets}
    )
    assert status == 202
    assert engine.wait(answer["run_id"])["state"] == "succeeded"
    status, answer = engine.request(
        "POST", "/v1/runs", {"pipeline_path": str(pipeline), "sockets": {"inbox": str(folders.inbox)}}
    )
    record = engine.wait(answer["run_id"])
    assert (record["state"], record["error_class"]) == ("failed", "ConfigError")
    assert (
        record["error"]
        == "write (sink.parquet): socket 'outbox' has no folder (folders were given for: inbox)"
    )
    listed = engine.request("GET", "/v1/runs")[1]["runs"]
    assert [run["state"] for run in listed] == ["failed", "succeeded"]  # newest first


def test_an_engine_that_is_killed_leaves_no_worker_and_the_next_one_removes_its_folders(
    safetwin_home: Path, tmp_path: Path, folders: Folders, big_csv: Path
) -> None:
    link_big(folders, big_csv)
    killed = start_engine(safetwin_home, tmp_path)
    try:
        run_id = killed.submit(COPY, folders)
        record = killed.wait_for_stage_worker(run_id)
        worker_id, pid = record["stages"][0]["worker_id"], record["stages"][0]["worker_pid"]
        wait_for_temporary_file(folders)
        killed.process.kill()
        killed.process.communicate(timeout=SECONDS)
    finally:
        if killed.process.poll() is None:
            killed.process.kill()
    assert_gone(pid)  # its stdin closed mid-stage: it cancelled the stage and ended by itself
    assert folders.written() == []  # and the stage cleaned up after itself
    assert (safetwin_home / "tmp" / worker_id).exists()  # nobody deleted its folder...
    following = start_engine(safetwin_home, tmp_path)
    try:
        assert not (safetwin_home / "tmp" / worker_id).exists()  # ...until the next engine started
        assert following.wait(following.submit(COPY, folders))["state"] == "succeeded"
    finally:
        stop_engine(following)


@pytest.mark.parametrize("engine", [{"env": {"SAFETWIN_TEST_WORKER_HOOK": "print"}}], indirect=True)
def test_a_library_that_prints_in_a_worker_does_not_break_the_protocol(
    engine: Engine, folders: Folders
) -> None:
    write_csv(folders.inbox / "people.csv", 200_000)  # long enough for progress, which prints too
    record = engine.wait(engine.submit(CLEAN, folders))
    assert record["state"] == "succeeded", record
    assert record["stages"][0]["rows_per_node"]["write"] == 180_000


def test_an_orphaned_worker_stuck_past_sigint_ends_and_its_folder_is_kept_until_then(
    safetwin_home: Path, tmp_path: Path, folders: Folders, big_csv: Path
) -> None:
    link_big(folders, big_csv)
    grace = 1.0
    killed = start_engine(safetwin_home, tmp_path, grace=grace, SAFETWIN_TEST_WORKER_HOOK="ignore_sigint")
    try:
        run_id = killed.submit(COPY, folders, path="batch")
        record = killed.wait_for_stage_worker(run_id)
        worker_id, pid = record["stages"][0]["worker_id"], record["stages"][0]["worker_pid"]
        wait_for_temporary_file(folders)
        killed.process.kill()
        killed_at = time.monotonic()
        killed.process.communicate(timeout=SECONDS)
    finally:
        if killed.process.poll() is None:
            killed.process.kill()
    following = start_engine(safetwin_home, tmp_path, grace=grace)  # at once: the orphan may still run
    try:
        folder = safetwin_home / "tmp" / worker_id
        try:
            os.kill(pid, 0)
            assert folder.exists()  # it still runs: its folder is not deleted under it
        except ProcessLookupError:
            pass
        assert_gone(pid)
        assert time.monotonic() - killed_at < grace + 4.0
        assert folders.written() == []  # the forced exit removed the stage's temporary file first
        deadline = time.monotonic() + grace + 15.0
        while folder.exists():  # deleted once the next engine tries again, a grace period later
            assert time.monotonic() < deadline, "the stale folder was never deleted"
            time.sleep(0.1)
        assert following.wait(following.submit(COPY, folders))["state"] == "succeeded"
    finally:
        stop_engine(following)


# --- the commit lock of a worker whose engine dies ----------------------------------------------------------


@pytest.mark.parametrize(
    ("hook", "committed"),
    [
        ("hold_commit", True),  # SIGINT ignored: the commit finishes, then the cleanup finds it listed
        ("hold_commit_sigint", False),  # SIGINT honoured: the stage gives up and removes its file
    ],
)
def test_a_worker_whose_engine_dies_mid_commit_leaves_a_whole_commit_or_none(
    safetwin_home: Path, tmp_path: Path, folders: Folders, hook: str, committed: bool
) -> None:
    # The worker stops between the rename of its data file and its manifest (for 1.5 grace periods) while
    # its engine is killed. Its stdin thread then cleans up before the forced exit. Without the commit lock,
    # that cleanup found the file not listed yet and deleted it, and the manifest written a moment later
    # listed a file that was gone.
    write_csv(folders.inbox / "people.csv", 1_000)
    grace = 1.0
    killed = start_engine(safetwin_home, tmp_path, grace=grace, SAFETWIN_TEST_WORKER_HOOK=hook)
    dataset = folders.outbox / "data"
    try:
        run_id = killed.submit(COPY, folders)
        pid = killed.wait_for_stage_worker(run_id)["stages"][0]["worker_pid"]
        data = dataset / f"part-00000-{run_id}.parquet"
        deadline = time.monotonic() + SECONDS
        while not data.exists():  # renamed into place: the stage is inside its commit now
            assert time.monotonic() < deadline, "the stage never committed its file"
            time.sleep(0.002)
        assert not list(dataset.glob("_manifest/*.json"))
        killed.process.kill()
        killed.process.communicate(timeout=SECONDS)
    finally:
        if killed.process.poll() is None:
            killed.process.kill()
    deadline = time.monotonic() + 2 * grace + 5
    while True:  # it ends by itself within two grace periods
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        assert time.monotonic() < deadline, "the orphaned worker did not end"
        time.sleep(0.01)
    manifests = list(dataset.glob("_manifest/*.json"))
    for manifest in manifests:  # never a manifest that lists a file which is not there
        for entry in json.loads(manifest.read_text())["files"]:
            assert (dataset / entry["path"]).is_file(), entry["path"]
    if committed:
        assert data.is_file()
        (manifest,) = manifests
        assert [entry["path"] for entry in json.loads(manifest.read_text())["files"]] == [data.name]
    else:
        assert not data.exists()
        assert manifests == []
    assert [name for name in folders.written() if ".tmp-" in name] == []
