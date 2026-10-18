"""The tables: what the database itself refuses, what it deletes together, and how timestamps are kept."""

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import CheckConstraint, DateTime, Engine, PrimaryKeyConstraint, func, inspect, select, text
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from safetwin.metadata.models import (
    AUDIT_DETAILS_MAX_BYTES,
    CODE_MAX_BYTES,
    LINEAGE_DIRECTIONS,
    METRIC_RESOLUTIONS,
    RUN_FILE_KINDS,
    AuditEvent,
    Base,
    Dataset,
    Lineage,
    Metric,
    Pipeline,
    PipelineVersion,
    Run,
    RunFile,
    Setting,
    TaskAttempt,
    TaskInstance,
    UTCDateTime,
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
AddRun = Callable[..., Run]


def count(session: Session, model: Any, *criteria: Any) -> int:
    statement = select(func.count()).select_from(model)
    if criteria:
        statement = statement.where(*criteria)
    return session.scalar(statement) or 0


def test_a_timestamp_with_an_offset_is_stored_as_utc_and_comes_back_as_utc(session: Session) -> None:
    plus_five = timezone(timedelta(hours=5))
    session.add(Pipeline(id="p1", name="p1", created_at=datetime(2026, 9, 30, 12, 0, tzinfo=plus_five)))
    session.commit()
    assert session.execute(text("SELECT created_at FROM pipelines")).scalar() == "2026-09-30 07:00:00.000000"
    session.expire_all()
    stored = session.get_one(Pipeline, "p1").created_at
    assert stored == datetime(2026, 9, 30, 7, 0, tzinfo=UTC)
    assert stored.tzinfo is UTC


def test_a_timestamp_without_a_timezone_is_refused(session: Session) -> None:
    session.add(Pipeline(id="p1", name="p1", created_at=datetime(2026, 9, 30, 12, 0)))
    with pytest.raises(StatementError, match="has no timezone"):
        session.flush()


def test_a_timestamp_that_is_left_out_is_now_in_utc(session: Session) -> None:
    before = datetime.now(UTC)
    session.add(Pipeline(id="p1", name="p1"))
    session.commit()
    session.expire_all()
    pipeline = session.get_one(Pipeline, "p1")
    assert before <= pipeline.created_at <= datetime.now(UTC)
    assert pipeline.created_at.utcoffset() == timedelta(0)
    assert pipeline.updated_at.utcoffset() == timedelta(0)


def test_updated_at_moves_when_a_row_is_changed(session: Session) -> None:
    session.add(Pipeline(id="p1", name="p1", updated_at=datetime(2020, 1, 1, tzinfo=UTC)))
    session.commit()
    pipeline = session.get_one(Pipeline, "p1")
    pipeline.name = "renamed"
    session.commit()
    session.expire_all()
    assert session.get_one(Pipeline, "p1").updated_at > datetime(2026, 1, 1, tzinfo=UTC)


def test_no_timestamp_column_is_a_plain_datetime() -> None:
    # A plain DateTime would hand back naive datetimes from SQLite and accept them without a word.
    columns = [(table.name, column) for table in Base.metadata.sorted_tables for column in table.columns]
    assert [f"{table}.{column.name}" for table, column in columns if isinstance(column.type, DateTime)] == []
    assert len([column for _, column in columns if isinstance(column.type, UTCDateTime)]) > 10


# --- no secrets -----------------------------------------------------------------------------------


def test_no_column_stands_in_for_a_secret() -> None:
    names = {
        f"{table.name}.{column.name}" for table in Base.metadata.sorted_tables for column in table.columns
    }
    secretive = {
        name for name in names if any(word in name for word in ("secret", "password", "token", "credential"))
    }
    assert secretive == set()


def test_the_tables_are_the_run_history_and_nothing_else() -> None:
    assert sorted(Base.metadata.tables) == [
        "audit_events",
        "datasets",
        "lineage",
        "metrics",
        "pipeline_versions",
        "pipelines",
        "run_files",
        "runs",
        "settings",
        "task_attempts",
        "task_instances",
    ]


# --- enums ---------------------------------------------------------------------------------------

Builder = Callable[[Session, AddRun, str], object]


def a_lineage(session: Session, add_run: AddRun, direction: str) -> Lineage:
    run = add_run()
    session.add(Dataset(id=1, uri="file:///out"))
    session.flush()
    return Lineage(run_id=run.id, dataset_id=1, direction=direction)


def a_run_file(session: Session, add_run: AddRun, kind: str) -> RunFile:
    run = add_run()
    return RunFile(run_id=run.id, stage_index=0, path="/out/x", size_bytes=1, sha256="0" * 64, kind=kind)


ENUMS: dict[str, tuple[Builder, tuple[str, ...]]] = {
    "metrics.resolution": (
        lambda s, r, value: Metric(name="rows_in", value=1.0, ts=NOW, resolution=value),
        METRIC_RESOLUTIONS,
    ),
    "lineage.direction": (a_lineage, LINEAGE_DIRECTIONS),
    "run_files.kind": (a_run_file, RUN_FILE_KINDS),
}


def cases(valid: bool) -> list[Any]:
    out = []
    for name, (builder, values) in ENUMS.items():
        wrong = [
            "",
            "other",
            *(v.swapcase() for v in values if v.swapcase() != v),
            f" {values[0]}",
            f"{values[0]} ",
        ]
        out += [
            pytest.param(name, builder, value, id=f"{name}={value!r}")
            for value in (values if valid else wrong)
        ]
    return out


@pytest.mark.parametrize(("name", "builder", "value"), cases(valid=True))
def test_every_value_of_an_enum_is_accepted(
    session: Session, add_run: AddRun, name: str, builder: Builder, value: str
) -> None:
    session.add(builder(session, add_run, value))
    session.commit()


@pytest.mark.parametrize(("name", "builder", "value"), cases(valid=False))
def test_any_other_value_of_an_enum_is_refused_by_the_database(
    session: Session, add_run: AddRun, name: str, builder: Builder, value: str
) -> None:
    table, column = name.split(".")
    session.add(builder(session, add_run, value))
    with pytest.raises(IntegrityError, match=f"ck_{table}_{column}"):
        session.flush()


def test_the_states_and_the_other_free_text_are_not_enums(session: Session, add_run: AddRun) -> None:
    add_run("r1", state="a state the engine invents later")
    session.add(Metric(run_id="r1", name="a metric the engine invents later", value=1.0, ts=NOW))
    session.commit()


# --- codes and audit details are short on purpose -------------------------------------------------


def an_audit_row(session: Session, add_run: AddRun, value: str) -> AuditEvent:
    return AuditEvent(
        ts=NOW,
        principal="u1",
        action="x",
        resource="r",
        outcome="ok",
        details_json=value,
        prev_hash="0" * 64,
        hash="1" * 64,
    )


def a_failed_run(session: Session, add_run: AddRun, value: str) -> Run:
    add_run("setup")  # makes the pipeline and its version
    return Run(
        id="r1",
        pipeline_id="p1",
        pipeline_version_id=1,
        state="failed",
        error_class=value,
    )


def an_attempt(column: str) -> Builder:
    def build(session: Session, add_run: AddRun, value: str) -> TaskAttempt:
        add_run("setup")
        session.add(TaskInstance(id=1, run_id="setup", node_id="read", stage_index=0, state="failed"))
        session.flush()
        return TaskAttempt(task_instance_id=1, attempt=1, state="failed", **{column: value})

    return build


# column: (how to make a row that holds the value, its limit in bytes, the constraint that enforces it)
LIMITED: dict[str, tuple[Builder, int, str]] = {
    "audit_events.details_json": (an_audit_row, AUDIT_DETAILS_MAX_BYTES, "ck_audit_events_details_json_size"),
    "runs.error_class": (a_failed_run, CODE_MAX_BYTES, "ck_runs_error_class_length"),
    "task_attempts.error_class": (
        an_attempt("error_class"),
        CODE_MAX_BYTES,
        "ck_task_attempts_error_class_length",
    ),
    "task_attempts.exit_reason": (
        an_attempt("exit_reason"),
        CODE_MAX_BYTES,
        "ck_task_attempts_exit_reason_length",
    ),
}


def test_the_limits_are_the_ones_that_were_decided() -> None:
    assert (CODE_MAX_BYTES, AUDIT_DETAILS_MAX_BYTES) == (256, 4096)
    assert [limit for _, limit, _ in LIMITED.values()] == [4096, 256, 256, 256]


@pytest.mark.parametrize("name", LIMITED)
def test_a_limited_column_takes_a_value_of_exactly_its_limit(
    session: Session, add_run: AddRun, name: str
) -> None:
    builder, limit, _ = LIMITED[name]
    session.add(builder(session, add_run, "x" * limit))
    session.commit()


@pytest.mark.parametrize("name", LIMITED)
def test_a_limited_column_refuses_one_byte_more(session: Session, add_run: AddRun, name: str) -> None:
    builder, limit, constraint = LIMITED[name]
    session.add(builder(session, add_run, "x" * (limit + 1)))
    with pytest.raises(IntegrityError, match=constraint):
        session.flush()


@pytest.mark.parametrize("name", LIMITED)
def test_the_limit_counts_bytes_and_a_nul_character_does_not_hide_the_rest(
    session: Session, add_run: AddRun, name: str
) -> None:
    builder, limit, constraint = LIMITED[name]
    session.add(builder(session, add_run, "é" * (limit // 2)))  # the most that fits: 2 bytes each
    session.flush()
    session.rollback()
    too_long = {
        "a character that takes 2 bytes": "é" * (limit // 2 + 1),  # fewer characters than the limit
        "a NUL character": "x\x00" + "x" * limit,
    }
    for value in too_long.values():
        session.add(builder(session, add_run, value))
        with pytest.raises(IntegrityError, match=constraint):
            session.flush()
        session.rollback()


# --- what is deleted with what ---------------------------------------------------------------------


CHILDREN_OF_A_RUN = (TaskInstance, Metric, Lineage, RunFile)


def test_deleting_a_run_deletes_its_tasks_attempts_metrics_lineage_and_files(
    session: Session, add_run_tree: AddRun
) -> None:
    gone = add_run_tree("gone")
    add_run_tree("kept")
    session.commit()
    assert count(session, TaskAttempt) == 2

    session.delete(gone)
    session.commit()

    assert count(session, Run) == 1
    for model in CHILDREN_OF_A_RUN:
        assert count(session, model, model.run_id == "gone") == 0, model.__name__
        assert count(session, model, model.run_id == "kept") == 1, model.__name__
    assert count(session, TaskAttempt) == 1  # the attempt of the deleted run's task instance
    assert count(session, Dataset) == 1  # a dataset outlives the run that wrote it
    assert session.execute(text("PRAGMA foreign_key_check")).all() == []


def test_deleting_a_task_instance_deletes_its_attempts_and_metrics(
    session: Session, add_run_tree: AddRun
) -> None:
    add_run_tree("r1")
    session.commit()
    session.execute(text("DELETE FROM task_instances"))
    assert count(session, TaskAttempt) == 0
    assert count(session, Metric) == 0
    assert count(session, RunFile) == 1  # a file goes with its run, not with its task instance
    assert count(session, Run) == 1


def test_deleting_a_pipeline_deletes_everything_that_is_about_it(
    session: Session, add_run_tree: AddRun
) -> None:
    add_run_tree("r1")
    session.add(Pipeline(id="other", name="other"))
    session.commit()

    session.delete(session.get_one(Pipeline, "p1"))
    session.commit()

    for model in (
        PipelineVersion,
        Run,
        TaskInstance,
        TaskAttempt,
        Metric,
        Lineage,
        RunFile,
    ):
        assert count(session, model) == 0, model.__name__
    assert count(session, Pipeline) == 1
    assert count(session, Dataset) == 1  # a dataset is not part of a pipeline
    assert session.execute(text("PRAGMA foreign_key_check")).all() == []


def test_deleting_a_pipeline_version_deletes_the_runs_of_that_version(
    session: Session, add_run: AddRun
) -> None:
    add_run("r1")
    session.commit()
    session.delete(session.get_one(PipelineVersion, 1))
    session.commit()
    assert count(session, Run) == 0
    assert count(session, Pipeline) == 1


def test_deleting_a_dataset_deletes_its_lineage(session: Session, add_run_tree: AddRun) -> None:
    add_run_tree("r1")
    session.commit()
    session.delete(session.get_one(Dataset, 1))
    session.commit()
    assert count(session, Lineage) == 0
    assert count(session, Run) == 1


def test_a_row_cannot_point_at_a_parent_that_is_not_there(session: Session) -> None:
    session.add(Run(id="r1", pipeline_id="nope", pipeline_version_id=1, state="queued"))
    with pytest.raises(IntegrityError, match="FOREIGN KEY constraint failed"):
        session.flush()


def test_a_child_can_be_added_in_the_same_flush_as_its_parents_whatever_the_order(session: Session) -> None:
    # Without a relationship() SQLAlchemy inserts in the order of the class names: "Metric" before "Run".
    session.add(TaskAttempt(task_instance_id=1, attempt=1, state="running"))
    session.add(Metric(run_id="r1", task_instance_id=1, name="rows_in", value=1.0, ts=NOW))
    session.add(TaskInstance(id=1, run_id="r1", node_id="read", stage_index=0, state="running"))
    session.add(Run(id="r1", pipeline_id="p1", pipeline_version_id=1, state="running"))
    session.add(PipelineVersion(id=1, pipeline_id="p1", version=1, yaml_text="x", spec_sha256="0" * 64))
    session.add(Pipeline(id="p1", name="p1"))
    session.commit()
    assert count(session, TaskAttempt) == 1


# --- uniqueness ----------------------------------------------------------------------------------


def test_a_version_number_is_used_once_per_pipeline(session: Session) -> None:
    session.add_all([Pipeline(id="a", name="a"), Pipeline(id="b", name="b")])
    session.flush()
    for pipeline_id in ("a", "b"):  # the same number in two pipelines is fine
        session.add(PipelineVersion(pipeline_id=pipeline_id, version=1, yaml_text="x", spec_sha256="0" * 64))
    session.commit()
    session.add(PipelineVersion(pipeline_id="a", version=1, yaml_text="y", spec_sha256="1" * 64))
    with pytest.raises(
        IntegrityError,
        match=re.escape("UNIQUE constraint failed: pipeline_versions.pipeline_id, pipeline_versions.version"),
    ):
        session.flush()


def test_a_node_has_one_task_instance_per_run_and_one_attempt_of_each_number(
    session: Session, add_run: AddRun
) -> None:
    add_run("r1")
    add_run("r2")
    for run_id in ("r1", "r2"):
        session.add(
            TaskInstance(
                id=1 if run_id == "r1" else 2, run_id=run_id, node_id="read", stage_index=0, state="x"
            )
        )
    session.commit()
    session.add(TaskInstance(run_id="r1", node_id="read", stage_index=0, state="x"))
    with pytest.raises(
        IntegrityError,
        match=re.escape("UNIQUE constraint failed: task_instances.run_id, task_instances.node_id"),
    ):
        session.flush()
    session.rollback()
    session.add(TaskAttempt(task_instance_id=1, attempt=1, state="failed"))
    session.commit()
    session.add(TaskAttempt(task_instance_id=1, attempt=1, state="failed"))
    with pytest.raises(
        IntegrityError,
        match=re.escape("UNIQUE constraint failed: task_attempts.task_instance_id, task_attempts.attempt"),
    ):
        session.flush()


@pytest.mark.parametrize(
    ("make", "message"),
    [
        (lambda: Dataset(uri="file:///out"), "UNIQUE constraint failed: datasets.uri"),
        (lambda: Setting(key="theme", value_json="1"), "UNIQUE constraint failed: settings.key"),
    ],
    ids=["a dataset uri", "a setting key"],
)
def test_some_names_are_used_once(session: Session, make: Callable[[], Any], message: str) -> None:
    session.add(make())
    session.commit()
    session.add(make())
    with pytest.raises(IntegrityError, match=message):
        session.flush()


# --- indexes and names ---------------------------------------------------------------------------


def test_metrics_are_found_by_name_and_time_through_the_index(session: Session) -> None:
    plan = session.execute(
        text("EXPLAIN QUERY PLAN SELECT value FROM metrics WHERE name = 'rows_in' AND ts > '2026-01-01'")
    ).all()
    assert any("ix_metrics_name_ts" in row[3] for row in plan), plan


def test_every_foreign_key_has_an_index_that_starts_with_its_columns(engine: Engine) -> None:
    # Otherwise deleting a row of the parent table looks through the whole child table, once per row.
    with engine.connect() as connection:
        inspector = inspect(connection)
        unindexed = []
        for table in inspector.get_table_names():
            leading = [tuple(index["column_names"]) for index in inspector.get_indexes(table)]
            leading += [tuple(unique["column_names"]) for unique in inspector.get_unique_constraints(table)]
            leading.append(tuple(inspector.get_pk_constraint(table)["constrained_columns"]))
            for fk in inspector.get_foreign_keys(table):
                columns = tuple(fk["constrained_columns"])
                if not any(entry[: len(columns)] == columns for entry in leading):
                    unindexed.append(f"{table}{columns}")
    assert unindexed == []


def test_every_constraint_and_index_has_a_name() -> None:
    # Unnamed constraints can't be dropped or changed by a later migration.
    unnamed = [
        f"{table.name}: {constraint!r}"
        for table in Base.metadata.sorted_tables
        for constraint in (*table.constraints, *table.indexes)
        if constraint.name is None and not isinstance(constraint, PrimaryKeyConstraint)
    ]
    assert unnamed == []


def test_the_check_constraints_of_the_migration_are_those_of_the_models(engine: Engine) -> None:
    # Alembic's autogenerate does not compare CHECK constraints, so this does.
    def squeezed(sql: str) -> str:
        return " ".join(sql.split())

    with engine.connect() as connection:
        inspector = inspect(connection)
        for table in Base.metadata.sorted_tables:
            in_models = {
                (constraint.name, squeezed(str(constraint.sqltext)))
                for constraint in table.constraints
                if isinstance(constraint, CheckConstraint)
            }
            in_database = {
                (check["name"], squeezed(check["sqltext"]))
                for check in inspector.get_check_constraints(table.name)
            }
            assert in_database == in_models, table.name
    # Two enums (metrics.resolution, lineage.direction), four limits on codes (the audit details,
    # runs.error_class, task_attempts.error_class and exit_reason), and two of run_files: its kind and its
    # sha256.
    assert (
        sum(isinstance(c, CheckConstraint) for t in Base.metadata.sorted_tables for c in t.constraints) == 8
    )


# --- every table takes a row ---------------------------------------------------------------------


def test_every_table_takes_a_row_and_fills_in_the_defaults(session: Session, add_run_tree: AddRun) -> None:
    add_run_tree("r1")
    session.add_all(
        [
            AuditEvent(
                ts=NOW,
                principal="u1",
                action="x",
                resource="r",
                outcome="ok",
                details_json="{}",
                prev_hash="0" * 64,
                hash="1" * 64,
            ),
            Setting(key="theme", value_json='"dark"'),
        ]
    )
    session.commit()
    session.expire_all()

    empty = [table.name for table in Base.metadata.sorted_tables if count(session, table) == 0]
    assert empty == []
    assert session.scalars(select(Metric.resolution)).one() == "raw"
