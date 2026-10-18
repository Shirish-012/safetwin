"""The history of the runs in the metadata database (`executor.history.DbRunStore`), without the data plane.

The mapping of a run onto the tables, pipeline versions, the recovery of runs a dead engine left, pagination
and filters, retention with a clock of the test's own, saves from several threads at once, the modes of the
database's files, what stays in memory, and the same through the executor with a fake worker.

The store writes with sqlite3 SQL of its own. Every test runs it against a database that the real Alembic
migrations made (`migrated_db`, a copy of one made once), and checks what it wrote with the SQLAlchemy models:
a difference between the SQL and the schema fails here. `test_every_column_the_store_writes_is_in_the_schema`
compares `history.WRITES` with the migrated tables directly.
"""

import json
import logging
import os
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from safetwin.executor.executor import Executor
from safetwin.executor.history import NOT_KEPT, WRITES, DbRunStore, kept_text, metadata_path
from safetwin.executor.settings import ExecutorSettings, HistorySettings
from safetwin.executor.store import FileRecord, RunRecord, StageRecord, Totals, UnknownCursor
from safetwin.metadata import lite, open_metadata_db, session_factory
from safetwin.metadata.models import (
    AuditEvent,
    Dataset,
    Lineage,
    Metric,
    Pipeline,
    PipelineVersion,
    Run,
    RunFile,
    TaskAttempt,
    TaskInstance,
)

SECONDS = 30
SHA_A, SHA_B, SHA_M = "a" * 64, "b" * 64, "c" * 64
T0 = datetime(2026, 10, 2, 9, 0, tzinfo=UTC)
YAML = "apiVersion: safetwin/v1\nkind: Pipeline\nmetadata: {name: people}\n# first\n"


def at(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@pytest.fixture(autouse=True)
def history_db(safetwin_home: Path, migrated_db: Callable[[Path], Path]) -> Path:
    """`$SAFETWIN_HOME/metadata.db`, at the latest migration (made by the migrations)."""
    return migrated_db(metadata_path(safetwin_home))


@pytest.fixture
def store(safetwin_home: Path) -> Iterator[DbRunStore]:
    made = DbRunStore.open(metadata_path(safetwin_home))
    try:
        yield made
    finally:
        made.close()


@contextmanager
def session_of(store: DbRunStore) -> Iterator[Session]:
    """A SQLAlchemy session on the store's database, to check what the store's own SQL wrote."""
    engine = open_metadata_db(store.path)  # at the latest migration already: Alembic is not needed
    try:
        with session_factory(engine)() as session:
            yield session
    finally:
        engine.dispose()


def two_stage_run(run_id: str = "r1", pipeline: str = "people") -> RunRecord:
    return RunRecord(run_id=run_id, pipeline=pipeline, created_at=at(0), memory_limit_bytes=1000)


def planned(run: RunRecord, out: Path) -> RunRecord:
    """The run once it is running and its two stages are planned."""
    return run.model_copy(
        update={
            "state": "running",
            "started_at": at(1),
            "stages": [
                StageRecord(
                    index=0,
                    node_ids=["read", "raw"],
                    operators=["source.csv", "sink.parquet"],
                    path="fused",
                    output=str(out / "raw"),
                ),
                StageRecord(
                    index=1,
                    node_ids=["keep", "clean"],
                    operators=["transform.filter", "sink.parquet"],
                    path="batch",
                    output=str(out / "clean"),
                ),
            ],
        },
        deep=True,
    )


def with_stage(run: RunRecord, index: int, **fields: Any) -> RunRecord:
    copy = run.model_copy(deep=True)
    copy.stages[index] = copy.stages[index].model_copy(update=fields)
    return copy


def drive_a_whole_run(
    store: DbRunStore, out: Path, run_id: str = "r1", pipeline: str = "people"
) -> RunRecord:
    """Queue a run, run both stages (the first with progress), and end it: as the executor would save it."""
    run = two_stage_run(run_id, pipeline)
    store.add(run, YAML)
    run = planned(run, out)
    store.save(run)
    run = with_stage(run, 0, state="running", started_at=at(2), worker_id="w1", worker_pid=11)
    store.save(run)
    for rows in (10, 20, 30):  # progress: memory only
        run = with_stage(run, 0, rows_per_node={"read": rows}, bytes_written=rows, memory_bytes=rows * 1000)
        run.stages[0].memory_peak_bytes = rows * 1000
        store.save(run)
    first = [FileRecord(path=str(out / "raw" / f"part-00000-{run_id}.parquet"), bytes=300, sha256=SHA_A)]
    run = with_stage(
        run,
        0,
        state="succeeded",
        finished_at=at(3),
        duration_s=1.25,
        rows_per_node={"read": 40, "raw": 40},
        bytes_written=300,
        files=first,
        manifest=str(out / "raw" / "_manifest" / f"run=x_{run_id}.json"),
        manifest_bytes=900,
        manifest_sha256=SHA_M,
        exit_reason="exit_0",
    )
    run.totals = Totals(rows=40, bytes=300, files=1)
    store.save(run)
    run = with_stage(run, 1, state="running", started_at=at(4))
    store.save(run)
    second = [FileRecord(path=str(out / "clean" / f"part-00000-{run_id}.parquet"), bytes=200, sha256=SHA_B)]
    run = with_stage(
        run,
        1,
        state="succeeded",
        finished_at=at(5),
        duration_s=0.5,
        rows_per_node={"keep": 36, "clean": 36},
        bytes_written=200,
        files=second,
        exit_reason="exit_0",
    )
    run.totals = Totals(rows=76, bytes=500, files=2)
    store.save(run)
    run = run.model_copy(update={"state": "succeeded", "finished_at": at(6)})
    store.save(run)
    return run


# --- the mapping -------------------------------------------------------------------------------------------


def test_a_run_is_written_to_every_table_it_belongs_in(store: DbRunStore, tmp_path: Path) -> None:
    drive_a_whole_run(store, tmp_path)
    with session_of(store) as session:
        assert [(p.id, p.name) for p in session.scalars(select(Pipeline))] == [("people", "people")]
        (version,) = session.scalars(select(PipelineVersion))
        assert (version.pipeline_id, version.version, version.yaml_text) == ("people", 1, YAML)
        assert version.spec_sha256 == __import__("hashlib").sha256(YAML.encode()).hexdigest()
        (run,) = session.scalars(select(Run))
        assert (run.id, run.pipeline_id, run.pipeline_version_id) == ("r1", "people", version.id)
        assert (run.state, run.started_at, run.ended_at, run.error_class) == (
            "succeeded",
            T0 + timedelta(seconds=1),
            T0 + timedelta(seconds=6),
            None,
        )
        tasks = list(session.scalars(select(TaskInstance).order_by(TaskInstance.id)))
        assert [(t.node_id, t.stage_index, t.state) for t in tasks] == [
            ("read", 0, "succeeded"),
            ("raw", 0, "succeeded"),
            ("keep", 1, "succeeded"),
            ("clean", 1, "succeeded"),
        ]
        assert [t.started_at for t in tasks] == [T0 + timedelta(seconds=s) for s in (2, 2, 4, 4)]
        assert [t.ended_at for t in tasks] == [T0 + timedelta(seconds=s) for s in (3, 3, 5, 5)]
        attempts = list(session.scalars(select(TaskAttempt).order_by(TaskAttempt.task_instance_id)))
        assert [(a.attempt, a.state, a.exit_reason, a.error_class) for a in attempts] == [
            (1, "succeeded", "exit_0", None)
        ] * 4
        assert [a.started_at for a in attempts] == [T0 + timedelta(seconds=s) for s in (2, 2, 4, 4)]
        by_task = {t.id: t.node_id for t in tasks}
        metrics = {
            (by_task.get(m.task_instance_id, "run") if m.task_instance_id else "run", m.name): (
                m.value,
                m.unit,
            )
            for m in session.scalars(select(Metric))
        }
        assert metrics == {
            ("read", "rows_out"): (40.0, "rows"),
            ("raw", "rows_out"): (40.0, "rows"),
            ("raw", "bytes_written"): (300.0, "bytes"),
            ("raw", "duration_s"): (1.25, "seconds"),
            ("keep", "rows_out"): (36.0, "rows"),
            ("clean", "rows_out"): (36.0, "rows"),
            ("clean", "bytes_written"): (200.0, "bytes"),
            ("clean", "duration_s"): (0.5, "seconds"),
            ("run", "memory_peak_bytes"): (30_000.0, "bytes"),
        }
        assert {m.resolution for m in session.scalars(select(Metric))} == {"raw"}
        files = [(f.stage_index, f.kind, f.size_bytes, f.sha256) for f in session.scalars(select(RunFile))]
        assert files == [(0, "data", 300, SHA_A), (0, "manifest", 900, SHA_M), (1, "data", 200, SHA_B)]
        datasets = {d.uri: d.last_run_id for d in session.scalars(select(Dataset))}
        assert datasets == {(tmp_path / "raw").as_uri(): "r1", (tmp_path / "clean").as_uri(): "r1"}
        assert {(edge.run_id, edge.direction) for edge in session.scalars(select(Lineage))} == {
            ("r1", "output")
        }
        assert session.scalar(select(func.count()).select_from(Lineage)) == 2


def test_progress_is_kept_in_memory_and_writes_only_on_transitions(store: DbRunStore, tmp_path: Path) -> None:
    run = two_stage_run()
    store.add(run, YAML)
    run = with_stage(planned(run, tmp_path), 0, state="running", started_at=at(2))
    store.save(planned(two_stage_run(), tmp_path))
    store.save(run)
    writes = store.writes
    for rows in range(1, 50):
        run = with_stage(run, 0, rows_per_node={"read": rows}, bytes_written=rows)
        store.save(run)
    assert store.writes == writes  # no write for progress
    shown = store.get("r1")
    assert shown is not None
    assert shown.stages[0].rows_per_node == {"read": 49}  # the latest progress, from memory
    with session_of(store) as session:
        assert session.scalar(select(func.count()).select_from(Metric)) == 0
    (listed,) = store.recent(10)
    assert listed.state == "running"


def test_the_record_read_back_is_the_one_that_was_saved(
    store: DbRunStore, safetwin_home: Path, tmp_path: Path
) -> None:
    saved = drive_a_whole_run(store, tmp_path)
    assert store.get("r1") == saved  # in memory: everything
    store.close()
    after_restart = DbRunStore.open(metadata_path(safetwin_home))
    try:
        record = after_restart.get("r1")
    finally:
        after_restart.close()
    assert record is not None
    # What only the engine that ran it knew is gone; everything else came back from the database.
    assert (record.created_at, record.memory_limit_bytes) == (None, None)
    assert [stage.path for stage in record.stages] == [None, None]
    assert [stage.worker_id for stage in record.stages] == [None, None]
    expected = saved.model_copy(update={"created_at": None, "memory_limit_bytes": None}, deep=True)
    for stage in expected.stages:
        stage.path = stage.worker_id = stage.worker_pid = stage.output = None
        stage.memory_bytes = stage.memory_peak_bytes = None
        stage.operators = ["unknown", "unknown"]  # YAML has no nodes: nothing to name them by
    assert record == expected


def test_a_failed_run_keeps_its_error_class_and_its_message_only_in_memory(
    store: DbRunStore, safetwin_home: Path, tmp_path: Path
) -> None:
    run = two_stage_run()
    store.add(run, YAML)
    run = with_stage(planned(run, tmp_path), 0, state="running", started_at=at(2))
    store.save(run)
    message = "the stage of read used more memory than it may (the limit is 1 MB)"
    run = with_stage(
        run,
        0,
        state="failed",
        finished_at=at(3),
        rows_per_node={"read": 7},
        error_class="MemoryLimitReached",
        error=message,
        exit_reason="exit_0",
    )
    store.save(run)
    run = run.model_copy(
        update={
            "state": "failed",
            "finished_at": at(3),
            "error_class": "MemoryLimitReached",
            "error": message,
        }
    )
    store.save(run)
    shown = store.get("r1")
    assert shown is not None
    assert (shown.error_class, shown.error, shown.stages[0].error) == ("MemoryLimitReached", message, message)
    store.close()
    again = DbRunStore.open(metadata_path(safetwin_home))
    try:
        record = again.get("r1")
        (listed,) = again.recent(5)
    finally:
        again.close()
    assert record is not None
    assert (record.state, record.error_class, record.error) == ("failed", "MemoryLimitReached", None)
    assert (record.stages[0].state, record.stages[0].error_class, record.stages[0].error) == (
        "failed",
        "MemoryLimitReached",
        None,
    )
    assert record.stages[1].state == "pending"  # it never ran
    assert record.stages[0].rows_per_node == {"read": 7}
    assert (listed.state, listed.error_class) == ("failed", "MemoryLimitReached")
    raw = metadata_path(safetwin_home).read_bytes() + b"".join(
        path.read_bytes() for path in safetwin_home.glob("metadata.db-*")
    )
    assert b"more memory" not in raw  # the message never reached the database


def test_a_stage_that_never_started_still_gets_an_ended_attempt(store: DbRunStore, tmp_path: Path) -> None:
    run = two_stage_run()
    store.add(run, YAML)
    run = planned(run, tmp_path)
    store.save(run)
    run = with_stage(run, 0, state="cancelled", finished_at=at(2), exit_reason="cancelled")
    store.save(run)
    with session_of(store) as session:
        attempts = list(session.scalars(select(TaskAttempt)))
        assert [(a.state, a.exit_reason, a.started_at) for a in attempts] == [
            ("cancelled", "cancelled", T0 + timedelta(seconds=2))
        ] * 2


# --- pipeline versions --------------------------------------------------------------------------------------


def versions(store: DbRunStore) -> list[tuple[str, int]]:
    with session_of(store) as session:
        return [
            (run.id, run.version.version) for run in session.scalars(select(Run).order_by(literal_rowid()))
        ]


def literal_rowid() -> Any:
    from sqlalchemy import literal_column

    return literal_column("runs.rowid")


def test_the_same_text_reuses_the_latest_version_and_other_text_makes_a_new_one(store: DbRunStore) -> None:
    changed = YAML.replace("# first", "# second")
    for run_id, text in [("r1", YAML), ("r2", YAML), ("r3", changed), ("r4", changed), ("r5", YAML)]:
        store.add(two_stage_run(run_id), text)
    assert versions(store) == [("r1", 1), ("r2", 1), ("r3", 2), ("r4", 2), ("r5", 3)]
    store.add(two_stage_run("o1", pipeline="other"), YAML)  # versions count per pipeline
    with session_of(store) as session:
        assert (
            session.scalar(select(PipelineVersion.version).where(PipelineVersion.pipeline_id == "other")) == 1
        )
        assert session.scalar(select(func.count()).select_from(PipelineVersion)) == 4


def test_text_with_something_that_looks_like_a_secret_is_not_kept(store: DbRunStore) -> None:
    token = "ghp_8sK2mQ9xZ4vL7pR1tY6wN3bC5dF0gH2jK4lM"
    secret_in_comment = YAML + f"# my token: {token}\n"
    assert kept_text(secret_in_comment) == NOT_KEPT
    assert kept_text(YAML) == YAML
    store.add(two_stage_run(), secret_in_comment)
    with session_of(store) as session:
        (version,) = session.scalars(select(PipelineVersion))
        assert version.yaml_text == NOT_KEPT
        assert token not in version.yaml_text
        assert version.spec_sha256 == __import__("hashlib").sha256(secret_in_comment.encode()).hexdigest()


# --- recovery -----------------------------------------------------------------------------------------------


def test_runs_a_dead_engine_left_unfinished_are_marked_interrupted(
    store: DbRunStore, safetwin_home: Path, tmp_path: Path
) -> None:
    queued = two_stage_run("rq")
    store.add(queued, YAML)
    running = two_stage_run("rr")
    store.add(running, YAML)
    running = with_stage(planned(running, tmp_path), 0, state="running", started_at=at(2))
    store.save(planned(two_stage_run("rr"), tmp_path))
    store.save(running)
    drive_a_whole_run(store, tmp_path, "rdone")
    store.close()  # the engine died here: nobody ended rq and rr

    later = T0 + timedelta(hours=1)
    again = DbRunStore.open(metadata_path(safetwin_home), clock=lambda: later)
    try:
        assert again.recover_interrupted() == 2
        assert again.recover_interrupted() == 0  # nothing is left to recover
        with session_of(again) as session:
            states = {
                run.id: (run.state, run.error_class, run.ended_at) for run in session.scalars(select(Run))
            }
            assert states == {
                "rq": ("interrupted", "EngineStopped", later),
                "rr": ("interrupted", "EngineStopped", later),
                "rdone": ("succeeded", None, T0 + timedelta(seconds=6)),
            }
            tasks = {
                (t.node_id, t.stage_index): (t.state, t.ended_at)
                for t in session.scalars(select(TaskInstance).where(TaskInstance.run_id == "rr"))
            }
            assert tasks == {
                ("read", 0): ("interrupted", later),
                ("raw", 0): ("interrupted", later),
                ("keep", 1): ("interrupted", None),  # it never started
                ("clean", 1): ("interrupted", None),
            }
            attempts = list(
                session.scalars(select(TaskAttempt).join(TaskInstance).where(TaskInstance.run_id == "rr"))
            )
            assert [(a.state, a.exit_reason, a.error_class, a.ended_at) for a in attempts] == [
                ("interrupted", "engine_stopped", "EngineStopped", later)
            ] * 2
        record = again.get("rr")
        assert record is not None
        assert (record.state, [stage.state for stage in record.stages]) == (
            "interrupted",
            ["interrupted", "interrupted"],
        )
        assert [run.state for run in again.recent(10, state="interrupted")] == ["interrupted"] * 2
    finally:
        again.close()


# --- pagination and filters ---------------------------------------------------------------------------------


def test_runs_are_listed_newest_first_with_a_cursor_and_filters(store: DbRunStore, tmp_path: Path) -> None:
    for number in range(12):
        run_id = f"r{number:02d}"
        run = two_stage_run(run_id, pipeline="even" if number % 2 == 0 else "odd")
        store.add(run, YAML)
        if number % 3 == 0:
            store.save(run.model_copy(update={"state": "cancelled", "finished_at": at(number)}))
    ids = [summary.run_id for summary in store.recent(100)]
    assert ids == [f"r{n:02d}" for n in reversed(range(12))]
    first = store.recent(5)
    assert [s.run_id for s in first] == ["r11", "r10", "r09", "r08", "r07"]
    second = store.recent(5, before=first[-1].run_id)
    assert [s.run_id for s in second] == ["r06", "r05", "r04", "r03", "r02"]
    assert [s.run_id for s in store.recent(5, before="r02")] == ["r01", "r00"]
    assert store.recent(5, before="r00") == []
    assert [s.run_id for s in store.recent(100, pipeline="odd")] == ["r11", "r09", "r07", "r05", "r03", "r01"]
    assert [s.run_id for s in store.recent(100, state="cancelled")] == ["r09", "r06", "r03", "r00"]
    assert [s.run_id for s in store.recent(2, pipeline="even", state="queued", before="r10")] == [
        "r08",
        "r04",
    ]
    assert store.recent(10, pipeline="nobody") == []
    with pytest.raises(UnknownCursor):
        store.recent(5, before="rnothere")


def test_a_listing_has_the_totals_of_each_run(store: DbRunStore, tmp_path: Path) -> None:
    drive_a_whole_run(store, tmp_path, "rdone")
    store.add(two_stage_run("rnew"), YAML)
    done, new = sorted(store.recent(10), key=lambda summary: summary.run_id)
    assert done.totals == Totals(rows=76, bytes=500, files=2)
    assert new.totals == Totals()
    assert done.created_at == at(0)  # in memory: when it was queued


# --- retention ----------------------------------------------------------------------------------------------


def test_retention_deletes_old_runs_by_the_clock_it_is_given(safetwin_home: Path, tmp_path: Path) -> None:
    now = [T0]
    store = DbRunStore.open(
        metadata_path(safetwin_home),
        clock=lambda: now[0],
        settings=HistorySettings(runs_days=90),
    )
    try:
        drive_a_whole_run(store, tmp_path, "rold")  # ended at T0 + 6 s
        now[0] = T0 + timedelta(days=90)
        assert store.prune().runs == 0  # not quite 90 days since it ended
        now[0] = T0 + timedelta(days=91)
        assert store.prune().runs == 1
        with session_of(store) as session:
            assert session.scalar(select(func.count()).select_from(Run)) == 0
            for model in (TaskInstance, TaskAttempt, Metric, RunFile, Lineage):
                assert session.scalar(select(func.count()).select_from(model)) == 0, model.__name__
            assert session.scalar(select(func.count()).select_from(Dataset)) == 2  # datasets outlive runs
            assert [e.action for e in session.scalars(select(AuditEvent))] == ["retention.prune"] * 2
    finally:
        store.close()


def test_start_recovers_prunes_and_then_prunes_again_on_its_interval(
    safetwin_home: Path, tmp_path: Path
) -> None:
    now = [T0 + timedelta(days=200)]
    first = DbRunStore.open(metadata_path(safetwin_home))
    drive_a_whole_run(first, tmp_path, "rold")
    first.add(two_stage_run("rleft"), YAML)  # left queued by an engine that died
    first.close()
    store = DbRunStore.open(
        metadata_path(safetwin_home), clock=lambda: now[0], settings=HistorySettings(prune_interval_s=0.05)
    )
    try:
        store.start()
        with session_of(store) as session:
            states = {run.id: run.state for run in session.scalars(select(Run))}
        assert states == {"rleft": "interrupted"}  # rold was pruned; rleft ended just now (by the clock)
        deadline = time.monotonic() + SECONDS
        while True:
            with session_of(store) as session:
                prunes = session.scalar(
                    select(func.count()).select_from(AuditEvent).where(AuditEvent.action == "retention.prune")
                )
            if prunes is not None and prunes >= 3:  # at start, then on the interval
                break
            assert time.monotonic() < deadline
            time.sleep(0.02)
        now[0] += timedelta(days=91)
        deadline = time.monotonic() + SECONDS
        while store.get("rleft") is not None:  # the daily prune got it too, once it was old by the clock
            assert time.monotonic() < deadline
            time.sleep(0.02)
    finally:
        store.close()
    assert store._pruner is not None
    assert not store._pruner.is_alive()


def test_the_retention_settings_are_the_ones_the_docs_decided() -> None:
    settings = HistorySettings.from_defaults()
    assert (settings.runs_days, settings.prune_interval_s) == (90, 86_400.0)
    assert not hasattr(settings, "logs_days")  # there are no log lines in the database


# --- concurrency, files, failures ---------------------------------------------------------------------------


def test_runs_saved_from_several_threads_at_once_are_all_written(store: DbRunStore, tmp_path: Path) -> None:
    errors: list[BaseException] = []
    barrier = threading.Barrier(8)

    def one(number: int) -> None:
        try:
            barrier.wait()
            drive_a_whole_run(store, tmp_path / str(number), f"r{number}", pipeline=f"p{number % 2}")
        except BaseException as err:
            errors.append(err)

    threads = [threading.Thread(target=one, args=(number,)) for number in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(SECONDS)
    assert errors == []
    with session_of(store) as session:
        assert session.scalar(select(func.count()).select_from(Run).where(Run.state == "succeeded")) == 8
        assert session.scalar(select(func.count()).select_from(TaskInstance)) == 32
        assert session.scalar(select(func.count()).select_from(RunFile)) == 24
        assert session.scalar(select(func.count()).select_from(PipelineVersion)) == 2  # one per pipeline
    assert all(summary.totals.rows == 76 for summary in store.recent(10))


def test_two_stores_writing_one_database_at_once_wait_for_each_other(
    safetwin_home: Path, tmp_path: Path
) -> None:
    # Two engines never share a database (the instance lock), but the transactions must still be safe if two
    # connections write at once: each takes the write lock first (BEGIN IMMEDIATE) and waits for the other.
    stores = [DbRunStore.open(metadata_path(safetwin_home)) for _ in range(2)]
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def write(store: DbRunStore, prefix: str) -> None:
        try:
            barrier.wait()
            for number in range(5):
                drive_a_whole_run(store, tmp_path / prefix, f"{prefix}{number}")
        except BaseException as err:
            errors.append(err)

    threads = [threading.Thread(target=write, args=(store, f"s{n}")) for n, store in enumerate(stores)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(SECONDS)
    try:
        assert errors == []
        with session_of(stores[0]) as session:
            assert session.scalar(select(func.count()).select_from(Run)) == 10
            assert session.scalar(select(func.count()).select_from(PipelineVersion)) == 1  # never two "1"s
    finally:
        for store in stores:
            store.close()


def test_the_database_and_its_wal_and_shm_files_are_private(
    store: DbRunStore, safetwin_home: Path, tmp_path: Path
) -> None:
    previous = os.umask(0o000)
    try:
        drive_a_whole_run(store, tmp_path)
    finally:
        os.umask(previous)
    files = sorted(path.name for path in safetwin_home.iterdir() if path.name.startswith("metadata.db"))
    assert files == ["metadata.db", "metadata.db-shm", "metadata.db-wal"]
    for name in files:
        assert stat.S_IMODE((safetwin_home / name).stat().st_mode) == 0o600, name


def test_a_write_that_fails_is_logged_by_its_kind_and_the_run_goes_on(
    store: DbRunStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR)
    run = two_stage_run()
    store.add(run, YAML)
    bad = planned(run, tmp_path)
    bad.stages[0].files = [FileRecord(path="/x", bytes=1, sha256="CANARY-not-a-digest")]
    bad = with_stage(bad, 0, state="succeeded", finished_at=at(2))
    store.save(bad)  # the CHECK on sha256 refuses the file: the transaction is rolled back
    assert "the history of a run could not be written (IntegrityError)" in caplog.text
    assert "CANARY" not in caplog.text
    shown = store.get("r1")
    assert shown is not None
    assert shown.stages[0].state == "succeeded"  # memory still has it
    fixed = with_stage(bad, 0, files=[FileRecord(path="/x", bytes=1, sha256=SHA_A)])
    fixed = fixed.model_copy(update={"state": "succeeded", "finished_at": at(3)})
    store.save(fixed)  # the next transition writes what was missed
    with session_of(store) as session:
        assert session.scalar(select(Run.state)) == "succeeded"
        assert session.scalar(select(func.count()).select_from(TaskInstance)) == 4
        assert session.scalar(select(RunFile.sha256)) == SHA_A


def test_the_sha256_of_a_file_must_be_64_lowercase_hex_characters(store: DbRunStore) -> None:
    store.add(two_stage_run(), YAML)
    for bad in ("A" * 64, "a" * 63, "a" * 65, "g" * 64, "a" * 32 + "\x00" + "a" * 31):
        with session_of(store) as session:
            session.add(RunFile(run_id="r1", stage_index=0, path="/x", size_bytes=1, sha256=bad, kind="data"))
            with pytest.raises(IntegrityError, match="ck_run_files_sha256"):
                session.commit()
    with session_of(store) as session:
        session.add(RunFile(run_id="r1", stage_index=0, path="/x", size_bytes=1, sha256=SHA_A, kind="other"))
        with pytest.raises(IntegrityError, match="ck_run_files_kind"):
            session.commit()


# --- through the executor -----------------------------------------------------------------------------------

FAKE = r"""
import json, os, sys, time
out = os.fdopen(os.dup(1), "w")
def send(**message):
    out.write(json.dumps({"v": 1, **message}) + "\n"); out.flush()
send(type="ready", pid=os.getpid(), import_s=0.0)
for line in sys.stdin:
    job = json.loads(line)
    folder = job["sockets"]["outbox"]
    if job["type"] == "plan":
        send(type="plan_done", job_id=job["job_id"], pipeline="fake", stages=[
            {"index": i, "node_ids": [f"read{i}", f"write{i}"], "operators": ["source.csv", "sink.parquet"],
             "path": "fused", "input_from": None,
             "sink": {"file": os.path.join(folder, f"part-{i}-{job['run_id']}.parquet"),
                      "dataset_dir": folder, "relative": f"part-{i}-{job['run_id']}.parquet"}}
            for i in range(2)])
        continue
    index = job["stage_index"]
    send(type="progress", job_id=job["job_id"], stage=index, path="fused", rows_per_node={f"read{index}": 5},
         bytes_written=10, memory_bytes=1000 * (index + 1), elapsed_s=0.1)
    if "fail" in job["pipeline_yaml"] and index == 1:
        send(type="failed", job_id=job["job_id"], error_class="ComputeError", message="CANARY-row-value")
        break
    final = os.path.join(folder, f"part-{index}-{job['run_id']}.parquet")
    open(final, "w").close()
    send(type="stage_done", job_id=job["job_id"], rows_per_node={f"read{index}": 5, f"write{index}": 4},
         files=[{"path": final, "bytes": 7, "sha256": "d" * 64}], duration_s=0.1, path="fused",
         manifest=final + ".json", manifest_bytes=3, manifest_sha256="e" * 64)
    break
"""


@pytest.fixture
def executor(safetwin_home: Path, tmp_path: Path) -> Iterator[Executor]:
    fake = tmp_path / "fake_worker.py"
    fake.write_text(FAKE)
    store = DbRunStore.open(metadata_path(safetwin_home))
    made = Executor(
        safetwin_home,
        ExecutorSettings(memory_limit_bytes=1_000_000, warm_worker_s=0, cancel_grace_s=2.0),
        store=store,
        worker_command=[sys.executable, str(fake)],
    )
    made.start()
    try:
        yield made
    finally:
        made.shutdown()
        store.close()


def wait_for(executor: Executor, run_id: str) -> RunRecord:
    deadline = time.monotonic() + SECONDS
    while (record := executor.get(run_id)) is None or not record.ended:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    return record


def test_the_executor_writes_its_runs_through_the_store(executor: Executor, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    sockets = {"outbox": str(out)}
    good = executor.submit(pipeline="fake", pipeline_yaml="good", sockets=sockets).run_id
    bad = executor.submit(pipeline="fake", pipeline_yaml="fail", sockets=sockets).run_id
    assert wait_for(executor, good).state == "succeeded"
    failed = wait_for(executor, bad)
    assert (failed.state, failed.error_class) == ("failed", "ComputeError")
    store = executor.store
    assert isinstance(store, DbRunStore)
    with session_of(store) as session:
        runs = {
            run.id: (run.state, run.error_class, run.version.version) for run in session.scalars(select(Run))
        }
        assert runs == {good: ("succeeded", None, 1), bad: ("failed", "ComputeError", 2)}
        attempts = session.execute(
            select(TaskInstance.node_id, TaskAttempt.state, TaskAttempt.exit_reason, TaskAttempt.error_class)
            .join(TaskAttempt)
            .where(TaskInstance.run_id == bad)
            .order_by(TaskInstance.id)
        ).all()
        assert [tuple(row) for row in attempts] == [
            ("read0", "succeeded", "exit_0", None),
            ("write0", "succeeded", "exit_0", None),
            ("read1", "failed", "exit_0", "ComputeError"),  # the worker said it failed, then ended
            ("write1", "failed", "exit_0", "ComputeError"),
        ]
        kinds = [
            (f.stage_index, f.kind, f.sha256[0])
            for f in session.scalars(select(RunFile).where(RunFile.run_id == good))
        ]
        assert kinds == [(0, "data", "d"), (0, "manifest", "e"), (1, "data", "d"), (1, "manifest", "e")]
        peak = session.scalar(
            select(Metric.value).where(Metric.run_id == good, Metric.name == "memory_peak_bytes")
        )
        assert peak == 2000.0
        everything = json.dumps(
            [
                list(map(str, row))
                for model in (Run, TaskAttempt, Metric)
                for row in session.execute(select(model)).all()
            ]
        )
        assert "CANARY" not in everything
    shown = executor.get(good)
    assert shown is not None
    assert shown.totals == Totals(rows=8, bytes=14, files=2)
    assert [summary.run_id for summary in executor.recent(10)] == [bad, good]
    assert executor.recent(10, state="failed")[0].run_id == bad


# --- the schema, and the maintenance child ------------------------------------------------------------------

AFFINITY = {str: ("VARCHAR", "TEXT"), int: ("INTEGER",), float: ("FLOAT", "REAL"), datetime: ("DATETIME",)}


def test_every_column_the_store_writes_is_in_the_schema(history_db: Path) -> None:
    # The store's SQL is its own (sqlite3, no SQLAlchemy): read what the migrations made and compare.
    connection = sqlite3.connect(history_db)
    try:
        for table, written in WRITES.items():
            info = {row[1]: row for row in connection.execute(f'PRAGMA table_info("{table}")')}
            assert info, f"{table} is not in the schema"
            for column, kind in written.items():
                assert column in info, f"{table}.{column} is not in the schema"
                declared = str(info[column][2]).upper()
                assert declared.startswith(AFFINITY[kind]), (
                    f"{table}.{column} is {declared}, written as {kind}"
                )
            # An insert gives every column it must: each NOT NULL column without a default, but the id.
            required = {name for name, row in info.items() if row[3] and row[4] is None and not row[5]}
            assert required <= set(written), f"{table} needs {sorted(required - set(written))}"
            # And it writes nothing a foreign key would refuse: every column it names exists in the parent.
            for _, _, parent, child_column, parent_column, *_ in connection.execute(
                f'PRAGMA foreign_key_list("{table}")'
            ):
                assert parent_column in {
                    row[1] for row in connection.execute(f'PRAGMA table_info("{parent}")')
                }
                assert child_column in info
        checks = " ".join(
            sql for (sql,) in connection.execute("SELECT sql FROM sqlite_master WHERE type = 'table'")
        )
    finally:
        connection.close()
    for value in ("'raw'", "'data'", "'manifest'", "'output'"):  # the enum values the store writes
        assert value in checks, value


def audit_actions(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [action for (action,) in connection.execute("SELECT action FROM audit_events ORDER BY id")]
    finally:
        connection.close()


def test_a_new_file_is_migrated_and_pruned_by_the_child_and_an_up_to_date_one_needs_no_child(
    tmp_path: Path,
) -> None:
    path = tmp_path / "fresh" / "metadata.db"
    store = DbRunStore.open(path)
    try:
        assert store.maintenance_seconds > 0  # it waited for the child
        connection = lite.connect(path)
        assert lite.current_revision(connection) == lite.HEAD_REVISION
        connection.close()
        store.start()  # the child pruned just now: no prune is due
        assert audit_actions(path) == ["retention.prune"]
    finally:
        store.close()
    again = DbRunStore.open(path)
    try:
        assert again.maintenance_seconds == 0.0
        again.start()
        assert again.maintenance_seconds == 0.0
        assert audit_actions(path) == ["retention.prune"]  # still the one prune
    finally:
        again.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_a_prune_that_is_a_day_old_is_due_when_the_engine_starts(
    store: DbRunStore, safetwin_home: Path
) -> None:
    store.prune()
    store.close()
    tomorrow = DbRunStore.open(
        metadata_path(safetwin_home), clock=lambda: datetime.now(UTC) + timedelta(days=1)
    )
    try:
        tomorrow.start()
        assert tomorrow.maintenance_seconds > 0
        assert audit_actions(metadata_path(safetwin_home)) == ["retention.prune"] * 2
    finally:
        tomorrow.close()


@pytest.mark.parametrize(
    ("script", "options", "reason"),
    [
        ("import sys; sys.stderr.write('CANARY-from-the-child'); sys.exit(3)", {}, "exit code 3"),
        ("import os, signal; os.kill(os.getpid(), signal.SIGKILL)", {}, "signal 9"),
        ("import time; time.sleep(30)", {"timeout": 0.3}, "it took longer than 0.3 s"),
    ],
)
def test_a_child_that_fails_is_reported_by_how_it_ended_only(
    tmp_path: Path, script: str, options: dict[str, Any], reason: str
) -> None:
    started = time.monotonic()
    with pytest.raises(lite.MaintenanceFailed) as failed:
        lite.run_maintenance(tmp_path / "metadata.db", command=[sys.executable, "-c", script], **options)
    assert str(failed.value) == f"the maintenance of the metadata database failed ({reason})"
    assert "CANARY" not in str(failed.value)
    assert time.monotonic() - started < 10


def test_a_child_is_killed_when_the_engine_stops(tmp_path: Path) -> None:
    stop = threading.Event()
    threading.Timer(0.2, stop.set).start()
    with pytest.raises(lite.MaintenanceFailed, match="the engine is stopping"):
        lite.run_maintenance(
            tmp_path / "metadata.db", command=[sys.executable, "-c", "import time; time.sleep(30)"], stop=stop
        )


def test_an_engine_whose_database_can_not_be_migrated_does_not_open_it(tmp_path: Path) -> None:
    with pytest.raises(lite.MaintenanceFailed, match="exit code 1"):
        DbRunStore.open(tmp_path / "new" / "metadata.db", maintain_command=[sys.executable, "-c", "exit(1)"])


def test_the_child_refuses_a_prune_time_without_a_timezone(tmp_path: Path) -> None:
    from safetwin.metadata import maintain

    with pytest.raises(SystemExit) as refused:
        maintain.main(["--database", str(tmp_path / "m.db"), "--prune-at", "2026-10-02T09:00:00"])
    assert refused.value.code == 2
    assert (
        maintain.main(["--database", str(tmp_path / "not-a-folder" / "\0")]) == 1
    )  # the type is printed only


def test_the_store_and_the_engine_never_import_sqlalchemy_or_alembic() -> None:
    script = (
        "import sys\n"
        "from safetwin.api import server\n"
        "from safetwin.executor import history\n"
        "print(sorted({name.split('.')[0] for name in sys.modules} & {'sqlalchemy', 'alembic'}))\n"
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "[]"


# --- round 3: no orphaned child, no lost write, one audit chain ---------------------------------------------

PID_CHILD = "import os, sys, time; open(sys.argv[2] + '.pid', 'w').write(str(os.getpid())); time.sleep(60)"


def test_a_wait_that_is_interrupted_kills_and_reaps_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "metadata.db"
    pid_file = Path(f"{database}.pid")
    real_sleep = time.sleep

    def interrupted(seconds: float) -> None:  # Ctrl-C while the engine waits for the child
        if pid_file.exists() and pid_file.read_text():
            raise KeyboardInterrupt
        real_sleep(seconds)

    monkeypatch.setattr(lite.time, "sleep", interrupted)
    with pytest.raises(KeyboardInterrupt):
        lite.run_maintenance(database, command=[sys.executable, "-c", PID_CHILD])
    monkeypatch.undo()
    with pytest.raises(ProcessLookupError):  # killed and reaped before the interrupt went on
        os.kill(int(pid_file.read_text()), 0)


def database_state(path: Path, run_id: str) -> str | None:
    connection = sqlite3.connect(path)
    try:
        row = connection.execute("SELECT state FROM runs WHERE id = ?", (run_id,)).fetchone()
    finally:
        connection.close()
    return None if row is None else str(row[0])


def wait_for_state(path: Path, run_id: str, state: str) -> None:
    deadline = time.monotonic() + SECONDS
    while database_state(path, run_id) != state:
        assert time.monotonic() < deadline, database_state(path, run_id)
        time.sleep(0.02)


def after_restart(safetwin_home: Path, run_id: str) -> RunRecord:
    """The run as the next engine sees it, once that engine has recovered what was left unfinished."""
    again = DbRunStore.open(metadata_path(safetwin_home))
    try:
        again.start()
        record = again.get(run_id)
    finally:
        again.close()
    assert record is not None
    return record


def test_a_final_write_that_fails_is_written_again_and_the_run_is_not_left_running(
    store: DbRunStore, safetwin_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.retry_delays_s = (0.05, 0.05)
    failed: list[str] = []
    write_changes = DbRunStore._write_changes

    def flaky(self: DbRunStore, connection: sqlite3.Connection, before: RunRecord, run: RunRecord) -> None:
        if run.state == "succeeded" and not failed:  # the run's last write, once: "database is locked"
            failed.append(run.run_id)
            raise sqlite3.OperationalError("database is locked")
        write_changes(self, connection, before, run)

    monkeypatch.setattr(DbRunStore, "_write_changes", flaky)
    drive_a_whole_run(store, tmp_path)
    assert failed == ["r1"]
    wait_for_state(store.path, "r1", "succeeded")  # the retrier wrote it
    store.close()
    record = after_restart(safetwin_home, "r1")
    assert (record.state, [stage.state for stage in record.stages]) == ("succeeded", ["succeeded"] * 2)
    assert record.totals == Totals(rows=76, bytes=500, files=2)


def test_a_write_that_keeps_failing_is_tried_once_more_when_the_store_closes(
    store: DbRunStore, safetwin_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store.retry_delays_s = (0.01, 0.01)
    broken = [True]
    write_changes = DbRunStore._write_changes

    def failing(self: DbRunStore, connection: sqlite3.Connection, before: RunRecord, run: RunRecord) -> None:
        if run.ended and broken[0]:
            raise sqlite3.OperationalError("disk I/O error")
        write_changes(self, connection, before, run)

    monkeypatch.setattr(DbRunStore, "_write_changes", failing)
    drive_a_whole_run(store, tmp_path)
    time.sleep(0.2)  # the retrier has given up by now
    assert database_state(store.path, "r1") == "running"
    broken[0] = False
    store.close()  # the last try
    assert after_restart(safetwin_home, "r1").state == "succeeded"  # not interrupted


def test_a_run_whose_add_failed_is_still_written_in_full(
    store: DbRunStore, safetwin_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    insert_run = DbRunStore._insert_run

    def once_broken(self: DbRunStore, connection: sqlite3.Connection, run: RunRecord, text: str) -> None:
        calls.append(run.run_id)
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        insert_run(self, connection, run, text)

    monkeypatch.setattr(DbRunStore, "_insert_run", once_broken)
    saved = drive_a_whole_run(store, tmp_path)
    assert calls == ["r1", "r1"]  # the add, then the first save, which inserted it with all since
    store.close()
    record = after_restart(safetwin_home, "r1")
    assert record.state == "succeeded"
    assert [stage.files for stage in record.stages] == [stage.files for stage in saved.stages]
    assert record.stages[0].rows_per_node == {"read": 40, "raw": 40}


HOLDER = (
    "import sqlite3, sys, time; c = sqlite3.connect(sys.argv[2], isolation_level=None); "
    "c.execute('BEGIN IMMEDIATE'); open(sys.argv[2] + '.held', 'w').close(); "
    "time.sleep(1.0); c.execute('COMMIT')"
)


def test_a_child_that_holds_the_write_lock_past_the_busy_timeout_loses_no_write(
    safetwin_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(lite, "BUSY_TIMEOUT_MS", 200)  # the store gives up on the lock after 0.2 s
    store = DbRunStore.open(metadata_path(safetwin_home))
    store.retry_delays_s = (0.5, 1.0, 2.0)
    try:
        run = two_stage_run()
        store.add(run, YAML)
        running = planned(run, tmp_path)
        store.save(running)
        held = Path(f"{store.path}.held")
        child = threading.Thread(
            target=lite.run_maintenance,
            args=(store.path,),
            kwargs={"command": [sys.executable, "-c", HOLDER]},
        )
        child.start()
        deadline = time.monotonic() + SECONDS
        while not held.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        store.save(running.model_copy(update={"state": "cancelled", "finished_at": at(9)}))  # waits, fails
        assert database_state(store.path, "r1") == "running"
        child.join(SECONDS)
        wait_for_state(store.path, "r1", "cancelled")  # both finished, and the write was not lost
    finally:
        store.close()


def test_prunes_by_the_child_between_the_stores_writes_keep_one_valid_audit_chain(
    safetwin_home: Path, tmp_path: Path
) -> None:
    from safetwin.metadata import verify_audit_chain

    store = DbRunStore.open(
        metadata_path(safetwin_home),
        clock=lambda: datetime.now(UTC) + timedelta(days=1),  # a prune is due at start
        settings=HistorySettings(prune_interval_s=0.1),
    )
    try:
        store.start()  # one prune at start, then one every 0.1 s from the timer thread
        for number in range(8):
            drive_a_whole_run(store, tmp_path / str(number), f"r{number}")
            time.sleep(0.05)
        deadline = time.monotonic() + SECONDS
        while audit_actions(store.path).count("retention.prune") < 4:
            assert time.monotonic() < deadline
            time.sleep(0.05)
    finally:
        store.close()
    with session_of(store) as session:
        check = verify_audit_chain(session)
        assert check.ok, check.reason
        assert check.checked >= 4
        assert session.scalar(select(func.count()).select_from(Run).where(Run.state == "succeeded")) == 8


def test_the_text_of_a_pipeline_is_scanned_line_by_line_references_included() -> None:
    token = "ghp_8sK2mQ9xZ4vL7pR1tY6wN3bC5dF0gH2jK4lM"
    assert kept_text(YAML + f"    password: secret://vault {token}\n") == NOT_KEPT  # after a reference
    assert kept_text(YAML + f"secret://{token}\n") == NOT_KEPT  # a line that starts with one
    assert kept_text(YAML + f"extra: {{note: {token}}}\n") == NOT_KEPT  # a section validation would refuse
    assert kept_text(YAML + "    inbox: socket://local-inbox\n") == YAML + "    inbox: socket://local-inbox\n"


def test_the_versions_of_a_pipeline_are_pruned_with_their_last_run(
    safetwin_home: Path, tmp_path: Path
) -> None:
    now = [T0]
    store = DbRunStore.open(metadata_path(safetwin_home), clock=lambda: now[0])
    try:
        drive_a_whole_run(store, tmp_path, "rold")
        now[0] = T0 + timedelta(days=91)
        assert store.prune() == lite.Pruned(runs=1, versions=1, pipelines=1)
        connection = sqlite3.connect(store.path)
        try:
            for table in ("runs", "pipeline_versions", "pipelines"):
                assert connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0, table
        finally:
            connection.close()
    finally:
        store.close()


def test_nothing_in_the_engine_vacuums_the_history() -> None:
    # The cursor of `GET /v1/runs` relies on the rowids of `runs`, which VACUUM may renumber.
    source = Path(__file__).resolve().parents[2] / "src" / "safetwin"
    found = [
        str(path) for path in source.rglob("*.py") if "vacuum" in path.read_text(encoding="utf-8").lower()
    ]
    assert found == [str(source / "executor" / "history.py")]  # where the rule is written, and nowhere else


def one_stage_text(read: str, write: str) -> str:
    return (
        "apiVersion: safetwin/v1\nkind: Pipeline\nmetadata: {name: people}\nspec:\n  nodes:\n"
        f"    - {{id: read, operator: {read}, socket: socket://in}}\n"
        f"    - {{id: write, operator: {write}, inputs: [read], socket: socket://out}}\n"
    )


def a_finished_one_stage_run(store: DbRunStore, run_id: str, text: str, out: Path) -> None:
    """A run of `text` with one stage (`read` → `write`), queued, started and ended, as saved."""
    run = RunRecord(run_id=run_id, pipeline="people", created_at=at(0), memory_limit_bytes=1000)
    store.add(run, text)
    run = run.model_copy(
        update={
            "state": "running",
            "started_at": at(1),
            "stages": [
                StageRecord(
                    index=0, node_ids=["read", "write"], operators=["?", "?"], path="fused", output=str(out)
                )
            ],
        },
        deep=True,
    )
    store.save(run)
    run = with_stage(run, 0, state="running", started_at=at(2))
    store.save(run)
    run = with_stage(run, 0, state="succeeded", finished_at=at(3), rows_per_node={"read": 1, "write": 1})
    run.state, run.finished_at = "succeeded", at(4)
    store.save(run)


def test_a_prune_that_deletes_versions_empties_the_cache_of_their_operators(
    safetwin_home: Path, tmp_path: Path
) -> None:
    # `pipeline_versions.id` has no AUTOINCREMENT: once the newest version is pruned, SQLite gives its id to
    # the next new version. The operators cached for the old version must not be shown for the new one.
    now = [T0]
    store = DbRunStore.open(metadata_path(safetwin_home), clock=lambda: now[0], max_runs=0)
    try:
        a_finished_one_stage_run(store, "rold", one_stage_text("source.csv", "sink.parquet"), tmp_path)
        old = store.get("rold")  # read from the database (max_runs=0: nothing stays in memory)
        assert old is not None
        assert old.stages[0].operators == ["source.csv", "sink.parquet"]  # and now cached by version id

        now[0] = T0 + timedelta(days=91)
        assert store.prune() == lite.Pruned(runs=1, versions=1, pipelines=1)

        a_finished_one_stage_run(store, "rnew", one_stage_text("source.csv@1", "sink.parquet@1"), tmp_path)
        connection = sqlite3.connect(store.path)
        try:
            ids = connection.execute("SELECT id FROM pipeline_versions").fetchall()
        finally:
            connection.close()
        assert ids == [(1,)]  # the id of the pruned version, used again
        new = store.get("rnew")
        assert new is not None
        assert new.stages[0].operators == ["source.csv@1", "sink.parquet@1"]
    finally:
        store.close()


def test_a_prune_that_deletes_no_version_keeps_the_cache(safetwin_home: Path, tmp_path: Path) -> None:
    store = DbRunStore.open(metadata_path(safetwin_home), clock=lambda: T0, max_runs=0)
    try:
        a_finished_one_stage_run(store, "r1", one_stage_text("source.csv", "sink.parquet"), tmp_path)
        assert store.get("r1") is not None
        cached = dict(store._operators)
        assert cached != {}
        assert store.prune() == lite.Pruned(runs=0)
        assert store._operators == cached
    finally:
        store.close()
