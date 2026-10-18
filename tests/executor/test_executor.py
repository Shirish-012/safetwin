"""The executor without the data plane: the protocol, the memory share, the store, the temporary folders, the
queue and its limit, the warm worker, cancelling and the failures of a worker.

The queue tests run a fake worker (`FAKE`, a few lines of Python that speak the protocol and load no data
library), told what to do by the pipeline text it is sent: `sleep=<s>` (the stage takes that long), `fail`
(the stage fails with an error whose message must not cross), `crash` (the worker kills itself with SIGKILL
in the middle of the stage), `garbage` (it answers with a line that is not the protocol), `flood` (it writes
2 MiB without a newline instead of a plan), `stray` (it sends progress for another job), `stages=<n>`.
"""

import contextlib
import itertools
import json
import os
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from safetwin.executor import tmp
from safetwin.executor.executor import Executor, RunEnded, RunNotFound
from safetwin.executor.process import WorkerProcess, describe_exit, worker_command, worker_environment
from safetwin.executor.protocol import (
    Failed,
    FileOut,
    PlanJob,
    Progress,
    ProtocolError,
    StageJob,
    decode_job,
    decode_worker_message,
    encode,
)
from safetwin.executor.settings import ExecutorSettings
from safetwin.executor.store import MemoryRunStore, RunRecord

SECONDS = 30
SHA = "a" * 64

FAKE = r"""
import json, os, signal, sys, time
out = os.fdopen(os.dup(1), "w")
def send(**message):
    out.write(json.dumps({"v": 1, **message}) + "\n"); out.flush()
send(type="ready", pid=os.getpid(), import_s=0.0)
for line in sys.stdin:
    job = json.loads(line)
    text = job["pipeline_yaml"]
    options = dict(part.split("=") if "=" in part else (part, "1") for part in text.split())
    if job["type"] == "plan":
        if "flood" in options:
            out.write("x" * (2 << 20)); out.flush(); time.sleep(30)
        stages = int(options.get("stages", 1))
        send(type="plan_done", job_id=job["job_id"], pipeline="fake", stages=[
            {"index": i, "node_ids": [f"read{i}", f"write{i}"], "operators": ["source.csv", "sink.parquet"],
             "path": "fused", "input_from": None,
             "sink": {"file": os.path.join(job["sockets"]["outbox"], f"part-{i}-{job['run_id']}.parquet"),
                      "dataset_dir": job["sockets"]["outbox"],
                      "relative": f"part-{i}-{job['run_id']}.parquet"}}
            for i in range(stages)])
        continue
    index = job["stage_index"]
    target = os.path.join(job["sockets"]["outbox"], f".part-{index}-{job['run_id']}.parquet.tmp-0123456789ab")
    open(target, "w").close()  # what a writer that was cut off leaves behind
    with open(os.path.join(os.environ["TMPDIR"], "scratch"), "w") as f:
        f.write("x")
    send(type="progress", job_id=job["job_id"], stage=index, path="fused", rows_per_node={f"read{index}": 5},
         bytes_written=10, memory_bytes=100, elapsed_s=0.1)
    if "crash" in options:
        os.kill(os.getpid(), signal.SIGKILL)
    if "stray" in options:
        send(type="progress", job_id="jother", stage=index, path="fused", rows_per_node={}, bytes_written=0,
             memory_bytes=None, elapsed_s=0.1)
        time.sleep(30)
    if "garbage" in options:
        out.write("not json\n"); out.flush(); time.sleep(30)
    time.sleep(float(options.get("sleep", 0)))
    os.unlink(target)
    if "fail" in options:
        send(type="failed", job_id=job["job_id"], error_class="ComputeError", message="CANARY-row-value")
        break
    final = os.path.join(job["sockets"]["outbox"], f"part-{index}-{job['run_id']}.parquet")
    open(final, "w").close()
    send(type="stage_done", job_id=job["job_id"], rows_per_node={f"read{index}": 5, f"write{index}": 5},
         files=[{"path": final, "bytes": 0, "sha256": "a" * 64}], duration_s=0.1, path="fused",
         manifest=final + ".json")
    break
"""


# --- the protocol -------------------------------------------------------------------------------------------


def test_the_protocol_round_trips_jobs_and_refuses_what_does_not_fit() -> None:
    now = datetime.now(UTC)
    job = StageJob(
        job_id="j1",
        pipeline_yaml="x",
        sockets={"inbox": "/in"},
        run_id="r1",
        started_at=now,
        memory_limit_bytes=10,
        stage_index=1,
        committed={"write": [FileOut(path="/out/a", bytes=3, sha256=SHA)]},
    )
    line = encode(job)
    assert line.endswith(b"\n")
    assert line.count(b"\n") == 1
    assert decode_job(line) == job
    assert isinstance(
        decode_job(encode(PlanJob(**job.model_dump(exclude={"type", "stage_index", "committed"})))), PlanJob
    )
    wrong_version = json.loads(line) | {"v": 2}
    for bad in (
        b"not json",
        json.dumps(wrong_version).encode(),
        json.dumps(json.loads(line) | {"extra": 1}).encode(),
    ):
        with pytest.raises(ProtocolError) as refused:
            decode_job(bad)
        assert "not json" not in str(refused.value)


def test_a_message_from_a_worker_keeps_the_text_of_safe_errors_only() -> None:
    def failed(error_class: str) -> bytes:
        return json.dumps(
            {"v": 1, "type": "failed", "job_id": "j", "error_class": error_class, "message": "CANARY"}
        ).encode()

    assert decode_worker_message(failed("MemoryLimitReached")) == Failed(
        job_id="j", error_class="MemoryLimitReached", message="CANARY"
    )
    for unsafe in ("ComputeError", "ConversionException", "KeyError"):
        message = decode_worker_message(failed(unsafe))
        assert isinstance(message, Failed)
        assert message.message is None
    with pytest.raises(ProtocolError):
        decode_worker_message(failed("not a class name!"))
    progress = Progress(
        job_id="j",
        stage=0,
        path="fused",
        rows_per_node={"a": 1},
        bytes_written=2,
        memory_bytes=None,
        elapsed_s=1,
    )
    assert decode_worker_message(encode(progress)) == progress
    with pytest.raises(ProtocolError):
        decode_worker_message(encode(progress).replace(b'"a":1', b'"a":-1'))


# --- settings, store ----------------------------------------------------------------------------------------


def test_the_memory_limit_is_split_between_the_workers_and_a_run_can_only_lower_its_share() -> None:
    settings = ExecutorSettings(memory_limit_bytes=4_000_000_000)
    assert settings.max_stage_workers == 2
    assert settings.worker_share_bytes == 2_000_000_000
    assert settings.share_for(None) == 2_000_000_000
    assert settings.share_for(512_000_000) == 512_000_000
    assert settings.share_for(9_000_000_000) == 2_000_000_000
    assert ExecutorSettings(memory_limit_bytes=3, max_stage_workers=4).worker_share_bytes == 1
    with pytest.raises(ValueError, match="at least one byte"):
        ExecutorSettings(memory_limit_bytes=0)


def test_the_memory_store_keeps_the_newest_runs_and_never_drops_one_that_runs() -> None:
    store = MemoryRunStore(max_runs=3)

    def record(run_id: str, state: str) -> RunRecord:
        return RunRecord(run_id=run_id, state=state, pipeline="p", created_at="t", memory_limit_bytes=1)  # type: ignore[arg-type]

    store.save(record("r1", "running"))
    for n in range(2, 6):
        store.save(record(f"r{n}", "succeeded"))
    assert [run.run_id for run in store.recent(10)] == ["r5", "r4", "r1"]
    assert store.get("r2") is None
    store.save(record("r1", "failed"))  # saved again: keeps its place
    assert [run.run_id for run in store.recent(2)] == ["r5", "r4"]


# --- temporary folders --------------------------------------------------------------------------------------


def test_a_worker_folder_is_new_private_and_deleted_without_following_links(
    tmp_path: Path, safetwin_home: Path
) -> None:
    folder = tmp.make_worker_tmp(safetwin_home, "w0123abcd")
    assert folder == safetwin_home / "tmp" / "w0123abcd"
    for path in (folder, folder.parent):
        assert stat.S_IMODE(path.lstat().st_mode) == 0o700
    with pytest.raises(FileExistsError):
        tmp.make_worker_tmp(safetwin_home, "w0123abcd")
    with pytest.raises(ValueError, match="worker id"):
        tmp.make_worker_tmp(safetwin_home, "../x")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    (folder / "sub").mkdir()
    (folder / "sub" / "spill.bin").write_bytes(b"x")
    (folder / "link").symlink_to(outside, target_is_directory=True)
    (folder / "sub" / "file-link").symlink_to(outside / "keep.txt")
    assert tmp.remove_tree(folder)
    assert not folder.exists()
    assert (outside / "keep.txt").read_text() == "keep"
    link = safetwin_home / "tmp" / "w9999aaaa"
    link.symlink_to(outside, target_is_directory=True)
    assert tmp.remove_tree(link)
    assert (outside / "keep.txt").exists()


def test_a_link_in_place_of_the_tmp_folder_is_removed_not_followed(
    tmp_path: Path, safetwin_home: Path
) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir(mode=0o755)
    (safetwin_home / "tmp").symlink_to(outside, target_is_directory=True)
    root = tmp.ensure_tmp_root(safetwin_home)
    assert not root.is_symlink()
    assert root.is_dir()
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755  # not touched


def test_stale_folders_are_removed_at_start(tmp_path: Path, safetwin_home: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep")
    root = tmp.ensure_tmp_root(safetwin_home)
    (root / "wdeadbeef").mkdir()
    (root / "wdeadbeef" / "spill.bin").write_bytes(b"left by a crash")
    (root / "stray-file").write_text("x")
    (root / "w1111aaaa").symlink_to(outside, target_is_directory=True)
    # A worker of the dead engine that still runs (this process stands in for it): its folder is kept.
    (root / "w2222bbbb").mkdir()
    (root / "w2222bbbb" / "in-use").write_bytes(b"x")
    tmp.write_worker_pid(safetwin_home, "w2222bbbb", os.getpid())
    # A pid file that names a process which is gone, or one whose pid was used again (another start time).
    (root / "w3333cccc").mkdir()
    (root / "w3333cccc.pid").write_text(f"{dead_pid()} 1.0\n")
    (root / "w4444dddd").mkdir()
    (root / "w4444dddd.pid").write_text(f"{os.getpid()} 1.0\n")
    (root / "w5555eeee.pid").write_text(f"{dead_pid()} 1.0\n")  # its folder is gone already
    (root / "w6666ffff.pid").symlink_to(outside / "keep.txt")  # a link: removed, never followed
    # Folders named like pid files (the engine never makes them): removed, links inside them not followed.
    for name in ("w7777aaaa.pid", "w8888bbbb.pid"):
        (root / name).mkdir()
        (root / name / "junk").write_text("x")
        (root / name / "link").symlink_to(outside, target_is_directory=True)
    (root / "w8888bbbb").mkdir()  # with a folder of its own too
    removed, kept = tmp.remove_stale(safetwin_home)
    assert sorted(removed) == [
        "stray-file",
        "w1111aaaa",
        "w3333cccc",
        "w4444dddd",
        "w5555eeee.pid",
        "w6666ffff.pid",
        "w7777aaaa.pid",
        "w8888bbbb",
        "wdeadbeef",
    ]
    assert kept == ["w2222bbbb"]
    assert sorted(path.name for path in root.iterdir()) == ["w2222bbbb", "w2222bbbb.pid"]
    assert (outside / "keep.txt").read_text() == "keep"
    assert tmp.remove_stale(safetwin_home, only=["w2222bbbb"]) == ([], ["w2222bbbb"])  # still running
    (root / "w2222bbbb.pid").write_text(f"{dead_pid()} 1.0\n")  # now it has ended
    assert tmp.remove_stale(safetwin_home, only=["w2222bbbb"]) == (["w2222bbbb"], [])
    assert tmp.remove_stale(tmp_path / "no-home") == ([], [])


def dead_pid() -> int:
    ended = subprocess.Popen([sys.executable, "-c", "pass"])
    ended.wait()
    return ended.pid


# --- a worker process ---------------------------------------------------------------------------------------


def test_the_worker_command_and_environment(safetwin_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert worker_command() == [sys.executable, "-m", "safetwin.executor.worker"]
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert worker_command() == [sys.executable, "worker"]
    env = worker_environment(Path("/x/tmp/w1"), {"PATH": "/bin", "TMPDIR": "/tmp"})
    assert env == {
        "PATH": "/bin",
        "TMPDIR": "/x/tmp/w1",
        "TMP": "/x/tmp/w1",
        "TEMP": "/x/tmp/w1",
        "POLARS_TEMP_DIR": "/x/tmp/w1",
    }
    assert describe_exit(-9) == "signal 9"
    assert describe_exit(3) == "exit code 3"
    assert describe_exit(None) is None


def test_a_worker_sees_its_folder_as_tmpdir_and_its_folder_goes_however_it_ends(safetwin_home: Path) -> None:
    script = (
        "import json, os, sys, tempfile, time\n"
        "print('CANARY-on-stderr', file=sys.stderr, flush=True)\n"
        "print(json.dumps({'v': 1, 'type': 'ready', 'pid': os.getpid(), 'import_s': 0}), flush=True)\n"
        "open(os.path.join(tempfile.gettempdir(), 'f'), 'w').write(os.environ['POLARS_TEMP_DIR'])\n"
        "time.sleep(60)\n"
    )
    worker = WorkerProcess(safetwin_home, command=[sys.executable, "-c", script])
    ready = worker.wait_ready(SECONDS)
    assert ready.pid == worker.pid
    deadline = time.monotonic() + SECONDS
    while not (worker.tmp / "f").exists():
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert worker.stderr_bytes() > 0  # kept in memory, never handed out
    worker.kill()
    assert worker.finish(SECONDS) == "signal 9"
    assert not worker.tmp.exists()
    assert worker.stderr_bytes() == 0


# --- the queue, with the fake worker ------------------------------------------------------------------------


class Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.lock = threading.Lock()

    def __call__(self, kind: str, data: dict[str, Any]) -> None:
        with self.lock:
            self.events.append((kind, json.loads(json.dumps(data))))

    def of(self, run_id: str) -> list[str]:
        with self.lock:
            return [kind for kind, data in self.events if data.get("run_id") == run_id]


@pytest.fixture
def fake(tmp_path: Path) -> Path:
    script = tmp_path / "fake_worker.py"
    script.write_text(FAKE)
    return script


@pytest.fixture
def outbox(tmp_path: Path) -> Path:
    folder = tmp_path / "out"
    folder.mkdir()
    return folder


@pytest.fixture
def make_executor(safetwin_home: Path, fake: Path) -> Iterator[Any]:
    made: list[Executor] = []

    def make(**settings: Any) -> tuple[Executor, Recorder]:
        recorder = Recorder()
        executor = Executor(
            safetwin_home,
            ExecutorSettings(memory_limit_bytes=1_000_000, **{"cancel_grace_s": 2.0, **settings}),
            on_event=recorder,
            worker_command=[sys.executable, str(fake)],
        )
        executor.start()
        made.append(executor)
        return executor, recorder

    yield make
    for executor in made:
        executor.shutdown()


def submit(executor: Executor, outbox: Path, text: str = "", **options: Any) -> str:
    return executor.submit(
        pipeline="fake", pipeline_yaml=text, sockets={"outbox": str(outbox)}, **options
    ).run_id


def wait_for(executor: Executor, run_id: str, *states: str) -> RunRecord:
    deadline = time.monotonic() + SECONDS
    while True:
        record = executor.get(run_id)
        assert record is not None
        if record.state in states:
            return record
        assert time.monotonic() < deadline, record.state
        time.sleep(0.01)


def test_at_most_two_runs_at_once_and_the_rest_wait_their_turn_in_order(
    make_executor: Any, outbox: Path, safetwin_home: Path
) -> None:
    executor, events = make_executor(warm_worker_s=0)
    running_at_once = 0
    run_ids = [submit(executor, outbox, "sleep=0.4") for _ in range(4)]
    assert [executor.get(run_id).state for run_id in run_ids[2:]] == ["queued", "queued"]  # type: ignore[union-attr]
    deadline = time.monotonic() + SECONDS
    while not all(executor.get(run_id).ended for run_id in run_ids):  # type: ignore[union-attr]
        running_at_once = max(running_at_once, executor.counts()["runs_active"])
        assert executor.counts()["workers_running"] <= 2
        assert time.monotonic() < deadline
        time.sleep(0.005)
    assert running_at_once == 2
    records = [executor.get(run_id) for run_id in run_ids]
    assert all(record is not None and record.state == "succeeded" for record in records)
    started = [record.started_at for record in records if record is not None]
    assert max(started[:2]) <= min(started[2:])  # FIFO: the two that waited start after the first two
    assert events.of(run_ids[3]) == [
        "run.queued",
        "run.started",
        "stage.started",
        "stage.progress",
        "stage.finished",
        "run.finished",
    ]
    record = records[0]
    assert record is not None
    assert record.stages[0].attempt == 1
    assert record.memory_limit_bytes == 500_000  # half the engine's limit
    assert (record.totals.files, record.totals.rows) == (1, 5)
    deadline = time.monotonic() + SECONDS
    while list((safetwin_home / "tmp").iterdir()):  # warm_worker_s=0: nothing kept
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_a_queued_run_is_cancelled_at_once_and_an_ended_one_can_not_be(
    make_executor: Any, outbox: Path
) -> None:
    executor, events = make_executor()
    first, _second, third = (submit(executor, outbox, "sleep=1") for _ in range(3))
    record = executor.cancel(third)
    assert record.state == "cancelled"
    assert events.of(third) == ["run.queued", "run.cancelled"]
    with pytest.raises(RunEnded):
        executor.cancel(third)
    with pytest.raises(RunNotFound):
        executor.cancel("rnothere")
    wait_for(executor, first, "succeeded")
    assert executor.get(third).started_at is None  # type: ignore[union-attr]


def test_a_cancelled_run_leaves_no_temporary_file_and_no_worker(
    make_executor: Any, outbox: Path, safetwin_home: Path
) -> None:
    executor, events = make_executor(warm_worker_s=0)
    run_id = submit(executor, outbox, "sleep=20")
    record = wait_for(executor, run_id, "running")
    deadline = time.monotonic() + SECONDS
    while not (record := executor.get(run_id)).stages or record.stages[0].worker_pid is None:  # type: ignore[union-attr]
        assert time.monotonic() < deadline
        time.sleep(0.01)
    pid = record.stages[0].worker_pid
    while not any(".tmp-" in path.name for path in outbox.iterdir()):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    started = time.monotonic()
    executor.cancel(run_id)
    record = wait_for(executor, run_id, "cancelled", "failed")
    assert record.state == "cancelled"
    assert time.monotonic() - started < 2.0 + 3  # the fake ignores nothing: SIGINT ends it at once
    assert record.stages[0].state == "cancelled"
    assert list(outbox.iterdir()) == []
    assert not (safetwin_home / "tmp" / str(record.stages[0].worker_id)).exists()
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)  # type: ignore[arg-type]
    assert events.of(run_id)[-2:] == ["stage.finished", "run.cancelled"]


def test_a_worker_that_ignores_sigint_gets_sigkill_after_the_grace_period(
    make_executor: Any, outbox: Path, fake: Path
) -> None:
    fake.write_text("import signal; signal.signal(signal.SIGINT, signal.SIG_IGN)\n" + FAKE)
    executor, _ = make_executor(cancel_grace_s=0.5)
    run_id = submit(executor, outbox, "sleep=30")
    deadline = time.monotonic() + SECONDS
    while not any(".tmp-" in path.name for path in outbox.iterdir()):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    started = time.monotonic()
    executor.cancel(run_id)
    assert wait_for(executor, run_id, "cancelled", "failed").state == "cancelled"
    assert 0.4 < time.monotonic() - started < 5
    assert list(outbox.iterdir()) == []


@pytest.mark.parametrize(
    ("text", "error_class", "error"),
    [
        ("crash", "WorkerStopped", "the stage worker stopped (signal 9)"),
        ("fail", "ComputeError", None),
        ("garbage", "ProtocolError", "the stage worker sent a message that does not fit the protocol"),
    ],
)
def test_a_stage_that_fails_or_a_worker_that_dies_is_cleaned_up_and_the_next_run_goes_on(
    make_executor: Any, outbox: Path, safetwin_home: Path, text: str, error_class: str, error: str | None
) -> None:
    executor, events = make_executor(warm_worker_s=0)
    run_id = submit(executor, outbox, text)
    record = wait_for(executor, run_id, "failed", "succeeded")
    assert (record.state, record.error_class, record.error) == ("failed", error_class, error)
    assert (record.stages[0].state, record.stages[0].error_class) == ("failed", error_class)
    assert list(outbox.iterdir()) == []  # the temporary file the worker left is gone
    assert not (safetwin_home / "tmp" / str(record.stages[0].worker_id)).exists()
    failed = [data for kind, data in events.events if kind == "run.failed"]
    assert failed == [
        {"run_id": run_id, "pipeline": "fake", "stage": 0, "error_class": error_class, "error": error}
    ]
    assert "CANARY" not in json.dumps(events.events) + record.model_dump_json()
    following = submit(executor, outbox)
    assert wait_for(executor, following, "succeeded", "failed").state == "succeeded"


def test_the_stages_of_a_run_go_one_after_another_and_a_warm_worker_serves_the_next(
    make_executor: Any, outbox: Path, safetwin_home: Path
) -> None:
    executor, _ = make_executor(warm_worker_s=1.0)
    run_id = submit(executor, outbox, "stages=3 sleep=0.3")
    record = wait_for(executor, run_id, "succeeded", "failed")
    assert record.state == "succeeded"
    assert [stage.worker_start for stage in record.stages] == ["cold", "warm", "warm"]
    assert len({stage.worker_id for stage in record.stages}) == 3  # one worker per stage
    starts = [stage.started_at or "" for stage in record.stages]
    ends = [stage.finished_at or "" for stage in record.stages]
    assert ends[0] <= starts[1]
    assert ends[1] <= starts[2]
    assert executor.counts()["workers_idle"] == 1  # kept warm...
    deadline = time.monotonic() + SECONDS
    while executor.counts()["workers_idle"] or list((safetwin_home / "tmp").iterdir()):
        assert time.monotonic() < deadline  # ...then let go
        time.sleep(0.02)
    again = submit(executor, outbox)
    assert wait_for(executor, again, "succeeded").stages[0].worker_start == "cold"


def test_shutdown_cancels_what_runs_and_what_waits(
    make_executor: Any, outbox: Path, safetwin_home: Path
) -> None:
    executor, _ = make_executor()
    run_ids = [submit(executor, outbox, "sleep=20") for _ in range(3)]
    wait_for(executor, run_ids[0], "running")
    time.sleep(0.3)
    executor.shutdown()
    assert [executor.get(run_id).state for run_id in run_ids] == ["cancelled"] * 3  # type: ignore[union-attr]
    assert list((safetwin_home / "tmp").iterdir()) == []
    assert not any(".tmp-" in path.name for path in outbox.iterdir())


# --- fix round 1 --------------------------------------------------------------------------------------------


def test_a_line_longer_than_1_mib_from_a_worker_is_a_protocol_error(safetwin_home: Path, fake: Path) -> None:
    flood = (
        "import json, os, sys, time\n"
        "print(json.dumps({'v': 1, 'type': 'ready', 'pid': os.getpid(), 'import_s': 0}), flush=True)\n"
        "sys.stdout.write('x' * (2 << 20)); sys.stdout.flush(); time.sleep(30)\n"
    )
    worker = WorkerProcess(safetwin_home, command=[sys.executable, "-c", flood])
    worker.wait_ready(SECONDS)
    with pytest.raises(ProtocolError, match="too long"):
        worker.receive(SECONDS)
    worker.kill()
    worker.finish(SECONDS)
    assert not worker.tmp.exists()


def test_a_worker_that_floods_or_answers_for_another_job_is_killed_and_cleaned_up(
    make_executor: Any, outbox: Path, safetwin_home: Path
) -> None:
    executor, _ = make_executor(warm_worker_s=0)
    for text in ("flood", "stray"):
        record = wait_for(executor, submit(executor, outbox, text), "failed", "succeeded")
        assert (record.state, record.error_class) == ("failed", "ProtocolError"), text
        assert list(outbox.iterdir()) == []
    deadline = time.monotonic() + SECONDS
    while list((safetwin_home / "tmp").iterdir()):
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_a_job_too_large_for_the_protocol_is_not_sent(make_executor: Any, outbox: Path) -> None:
    executor, _ = make_executor(warm_worker_s=0)
    record = wait_for(executor, submit(executor, outbox, "x" * (1 << 20)), "failed", "succeeded")
    assert (record.state, record.error_class, record.error) == (
        "failed",
        "ProtocolError",
        "the job is too large to send to a stage worker",
    )


def test_the_queue_is_capped_and_says_where_each_run_waits(make_executor: Any, outbox: Path) -> None:
    from safetwin.executor.executor import QueueFull

    executor, events = make_executor(max_queued_runs=2)
    run_ids = [submit(executor, outbox, "sleep=2") for _ in range(4)]
    with pytest.raises(QueueFull):
        submit(executor, outbox)
    positions = [
        data["position"] for kind, data in events.events if kind == "run.queued" and data["run_id"] in run_ids
    ]
    assert positions == [None, None, 1, 2]
    executor.cancel(run_ids[3])
    submit(executor, outbox)  # room again


def test_a_warm_worker_that_died_is_replaced_by_a_cold_start(
    make_executor: Any, outbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import psutil

    executor, _ = make_executor(warm_worker_s=30)
    assert wait_for(executor, submit(executor, outbox), "succeeded").state == "succeeded"
    deadline = time.monotonic() + SECONDS
    while executor._idle is None:  # the warm worker that the stage's end started
        assert time.monotonic() < deadline
        time.sleep(0.01)
    idle = executor._idle
    assert idle is not None
    os.kill(idle.pid, 9)
    while psutil.Process(idle.pid).status() != psutil.STATUS_ZOMBIE:  # dead, not reaped: `alive` would see it
        assert time.monotonic() < deadline
        time.sleep(0.01)
    monkeypatch.setattr(WorkerProcess, "alive", property(lambda self: True))  # it died after the check
    record = wait_for(executor, submit(executor, outbox), "succeeded", "failed")
    assert record.state == "succeeded", record.error
    assert record.stages[0].worker_start == "cold"
    assert record.stages[0].worker_id != idle.worker_id


class BrokenOnce(MemoryRunStore):
    """A store that fails once, when the first progress of a stage is saved."""

    def __init__(self) -> None:
        super().__init__()
        self.broken = False

    def save(self, run: RunRecord) -> None:
        if (
            not self.broken
            and run.stages
            and run.stages[0].rows_per_node
            and run.stages[0].state == "running"
        ):
            self.broken = True
            raise RuntimeError("CANARY-from-the-store")
        super().save(run)


def test_an_error_of_the_engine_mid_stage_cleans_up_and_says_only_its_kind(
    safetwin_home: Path, fake: Path, outbox: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    events = Recorder()
    store = BrokenOnce()
    executor = Executor(
        safetwin_home,
        ExecutorSettings(memory_limit_bytes=1_000_000, warm_worker_s=0, cancel_grace_s=2.0),
        store=store,
        on_event=events,
        worker_command=[sys.executable, str(fake)],
    )
    executor.start()
    try:
        record = wait_for(executor, submit(executor, outbox, "sleep=5"), "failed", "succeeded")
    finally:
        executor.shutdown()
    assert store.broken
    assert (record.state, record.error_class) == ("failed", "InternalError")
    stage = record.stages[0]
    assert (stage.state, stage.error_class) == ("failed", "InternalError")
    with pytest.raises(ProcessLookupError):
        os.kill(stage.worker_pid, 0)  # type: ignore[arg-type]
    assert list(outbox.iterdir()) == []  # the temporary file the worker left is gone
    assert list((safetwin_home / "tmp").iterdir()) == []
    finished = [data for kind, data in events.events if kind == "stage.finished"]
    assert [(data["stage"], data["state"]) for data in finished] == [(0, "failed")]
    everything = json.dumps(events.events) + record.model_dump_json() + caplog.text
    assert "CANARY" not in everything
    assert "a stage failed in the engine with RuntimeError" in caplog.text


def test_a_cancel_that_races_the_end_of_a_stage_leaves_a_consistent_run(
    make_executor: Any, outbox: Path
) -> None:
    executor, _ = make_executor(warm_worker_s=0)
    for delay in (0.15, 0.2, 0.25, 0.3, 0.35):
        run_id = submit(executor, outbox, "sleep=0.25")
        wait_for(executor, run_id, "running")
        time.sleep(delay)
        with contextlib.suppress(RunEnded):
            executor.cancel(run_id)
        record = wait_for(executor, run_id, "succeeded", "cancelled", "failed")
        written = [path.name for path in outbox.iterdir()]
        if record.state == "succeeded":
            assert record.stages[0].state == "succeeded"
            assert written == [f"part-0-{run_id}.parquet"]
        else:
            assert record.state == "cancelled", record.error
            assert record.stages[0].state in ("cancelled", "pending")
            assert record.stages[0].files == []
            assert written == []
        for path in outbox.iterdir():
            path.unlink()


def test_a_slow_worker_start_does_not_hold_up_the_api(
    safetwin_home: Path, fake: Path, outbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import warnings

    from safetwin.api.app import create_app

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")
        from starlette.testclient import TestClient

    executor = Executor(
        safetwin_home,
        ExecutorSettings(memory_limit_bytes=1_000_000, warm_worker_s=5),
        worker_command=[sys.executable, str(fake)],
    )
    spawn = executor._spawn

    def slow_spawn() -> WorkerProcess:
        time.sleep(1.0)
        return spawn()

    monkeypatch.setattr(executor, "_spawn", slow_spawn)
    executor.start()
    token = "t" * 43
    app = create_app(token, 48124, ("http://localhost:5173",), heartbeat_s=0.1, executor=executor)
    auth = {"Authorization": f"Bearer {token}"}
    try:
        with (
            TestClient(app, base_url="http://127.0.0.1:48124") as client,
            client.websocket_connect("ws://127.0.0.1:48124/v1/events") as ws,
        ):
            ws.send_text(token)
            assert ws.receive_json()["type"] == "hello"
            answer = client.post(
                "/v1/runs", headers=auth, json={"pipeline_yaml": "x", "sockets": {"outbox": str(outbox)}}
            )
            assert answer.status_code == 422  # not a pipeline: validated first
            executor.submit(pipeline="fake", pipeline_yaml="stages=2", sockets={"outbox": str(outbox)})
            slowest = 0.0
            beats: list[float] = []
            started = time.monotonic()
            while time.monotonic() - started < 2.5:  # the run waits 1 s for each of its cold starts
                before = time.monotonic()
                assert client.get("/v1/status", headers=auth).status_code == 200
                slowest = max(slowest, time.monotonic() - before)
                message = ws.receive_json()
                if message["type"] == "heartbeat":
                    beats.append(time.monotonic())
            gaps = [later - earlier for earlier, later in itertools.pairwise(beats)]
            assert slowest < 0.5
            assert len(beats) > 10
            assert max(gaps) < 0.6
    finally:
        executor.shutdown()


# --- the real worker and the end of its stdin ---------------------------------------------------------------


def stage_job(inbox: Path, outbox: Path, run_id: str = "rrace") -> StageJob:
    pipeline = (
        "apiVersion: safetwin/v1\nkind: Pipeline\nmetadata: {name: race}\nspec:\n"
        "  sockets: {inbox: socket://local-inbox, outbox: socket://local-outbox}\n"
        "  nodes:\n"
        '    - {id: read, operator: source.csv, socket: inbox, config: {path: "*.csv"}}\n'
        "    - {id: write, operator: sink.parquet, inputs: [read], socket: outbox, config: {path: data/}}\n"
    )
    return StageJob(
        job_id="j1",
        pipeline_yaml=pipeline,
        sockets={"inbox": str(inbox), "outbox": str(outbox)},
        run_id=run_id,
        started_at=datetime.now(UTC),
        memory_limit_bytes=2_000_000_000,
        stage_index=0,
        path="batch",
    )


def write_rows(path: Path, rows: int) -> None:
    with path.open("w") as file:
        file.write("id,name\n")
        for start in range(0, rows, 100_000):
            file.write("".join(f"{n},name {n}\n" for n in range(start, min(rows, start + 100_000))))


def test_a_stage_job_followed_at_once_by_the_end_of_stdin_is_cancelled(
    safetwin_home: Path, tmp_path: Path
) -> None:
    inbox, outbox = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outbox.mkdir()
    write_rows(inbox / "rows.csv", 300_000)
    worker = WorkerProcess(safetwin_home)
    worker.wait_ready(SECONDS)
    worker.send(stage_job(inbox, outbox))
    worker.close_stdin()  # the engine is gone right after it queued the job
    assert worker.finish(SECONDS) == "exit code 130"
    assert list(outbox.rglob("*")) == [] or not any(p.is_file() for p in outbox.rglob("*"))


def test_an_orphaned_worker_that_ignores_sigint_ends_after_the_grace_period(
    safetwin_home: Path, tmp_path: Path
) -> None:
    inbox, outbox = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outbox.mkdir()
    write_rows(inbox / "rows.csv", 3_000_000)
    worker = WorkerProcess(
        safetwin_home, env={**os.environ, "SAFETWIN_TEST_WORKER_HOOK": "ignore_sigint"}, grace_s=0.1
    )
    worker.wait_ready(SECONDS)
    worker.send(stage_job(inbox, outbox))
    deadline = time.monotonic() + SECONDS
    while not any(".tmp-" in p.name for p in outbox.rglob("*")):
        assert time.monotonic() < deadline, "the stage never started writing"
        time.sleep(0.002)
    closed = time.monotonic()
    worker.close_stdin()
    worker.process.wait(timeout=SECONDS)
    assert time.monotonic() - closed < 0.1 + 3.0
    assert worker.process.returncode == 130  # not 0: the stage (about 0.7 s more) did not get to finish
    worker.finish(1.0)
    assert [
        p for p in outbox.rglob("*") if p.is_file()
    ] == []  # it removed its temporary file before it ended


def test_a_line_longer_than_1_mib_ends_the_worker(safetwin_home: Path) -> None:
    worker = WorkerProcess(safetwin_home)
    worker.wait_ready(SECONDS)
    assert worker.process.stdin is not None
    worker.process.stdin.write(b"x" * ((1 << 20) + 10))
    worker.process.stdin.flush()
    assert worker.finish(SECONDS) == "exit code 2"


def test_the_api_answers_503_when_the_queue_is_full(safetwin_home: Path, fake: Path, outbox: Path) -> None:
    import warnings

    from safetwin.api.app import create_app

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")
        from starlette.testclient import TestClient

    repo = Path(__file__).resolve().parents[2]
    executor = Executor(
        safetwin_home,
        ExecutorSettings(memory_limit_bytes=1_000_000, max_queued_runs=1),
        worker_command=[sys.executable, str(fake)],
    )
    executor.start()
    token = "t" * 43
    auth = {"Authorization": f"Bearer {token}"}
    body = {
        "pipeline_yaml": (repo / "tests" / "fixtures" / "csv-clean.yaml").read_text(),
        "sockets": {"outbox": str(outbox)},
    }
    try:
        with TestClient(
            create_app(token, 48125, (), executor=executor), base_url="http://127.0.0.1:48125"
        ) as client:
            for _ in range(2):
                executor.submit(pipeline="fake", pipeline_yaml="sleep=5", sockets={"outbox": str(outbox)})
            first = client.post("/v1/runs", headers=auth, json=body)
            assert first.status_code == 202  # the one place in the queue
            full = client.post("/v1/runs", headers=auth, json=body)
            assert (full.status_code, full.json()) == (503, {"error": "queue_full"})
            assert client.get("/v1/status", headers=auth).json()["runs"]["queued"] == 1
    finally:
        executor.shutdown()


def test_a_warm_worker_started_while_the_engine_stops_is_ended_and_its_folder_deleted(
    make_executor: Any, outbox: Path, safetwin_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executor, events = make_executor(warm_worker_s=30)
    spawn = executor._spawn
    spawned: list[WorkerProcess] = []

    def spawn_slowly_after_the_first() -> WorkerProcess:
        if spawned:  # the warm worker that the end of the stage starts
            time.sleep(0.5)
        spawned.append(spawn())
        return spawned[-1]

    monkeypatch.setattr(executor, "_spawn", spawn_slowly_after_the_first)
    run_id = submit(executor, outbox)
    deadline = time.monotonic() + SECONDS
    while "stage.finished" not in events.of(run_id):
        assert time.monotonic() < deadline
        time.sleep(0.005)
    executor.shutdown()  # while the warm worker is being started
    assert len(spawned) == 2
    assert not spawned[1].alive
    assert list((safetwin_home / "tmp").iterdir()) == []
