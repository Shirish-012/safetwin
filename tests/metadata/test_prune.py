"""Retention (docs/internals.md): runs are kept 90 days. Old ones go and nothing else does."""

import inspect
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.orm import Session

from safetwin.metadata import PruneResult, append_audit_event, prune, session_factory, verify_audit_chain
from safetwin.metadata.models import (
    AuditEvent,
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
)

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
DAY = timedelta(days=1)
AddRun = Callable[..., Run]


def ids(session: Session, column: Any) -> list[Any]:
    return sorted(session.scalars(select(column)))


def test_the_limits_are_the_ones_the_docs_decided() -> None:
    parameters = inspect.signature(prune).parameters
    assert parameters["runs_days"].default == 90
    assert "logs_days" not in parameters  # there are no log lines in the database


def test_runs_that_ended_more_than_90_days_ago_go_with_everything_that_belongs_to_them(
    session: Session, add_run_tree: AddRun
) -> None:
    add_run_tree("old", ended_at=NOW - 91 * DAY)
    add_run_tree("recent", ended_at=NOW - 89 * DAY)
    session.commit()

    result = prune(session, NOW)
    session.commit()

    assert ids(session, Run.id) == ["recent"]
    assert ids(session, TaskInstance.run_id) == ["recent"]
    assert ids(session, Metric.run_id) == ["recent"]
    assert ids(session, Lineage.run_id) == ["recent"]
    assert ids(session, RunFile.run_id) == ["recent"]
    assert session.scalar(select(func.count()).select_from(TaskAttempt)) == 1
    assert result == PruneResult(runs=1)


def test_a_run_is_old_when_it_ended_before_the_limit_and_not_when_it_ended_on_it(
    session: Session, add_run: AddRun
) -> None:
    add_run("on-the-limit", ended_at=NOW - 90 * DAY)
    add_run("just-over", ended_at=NOW - 90 * DAY - timedelta(microseconds=1))
    session.commit()
    assert prune(session, NOW).runs == 1
    assert ids(session, Run.id) == ["on-the-limit"]


def test_a_run_that_has_not_ended_is_kept_however_long_it_has_been_going(
    session: Session, add_run_tree: AddRun
) -> None:
    add_run_tree("long", started_at=NOW - 400 * DAY, ended_at=None, state="running")
    session.commit()
    assert prune(session, NOW) == PruneResult(runs=0)
    assert ids(session, Run.id) == ["long"]
    assert ids(session, TaskInstance.run_id) == ["long"]


def test_limits_can_be_changed(session: Session, add_run: AddRun) -> None:
    add_run("a-week", ended_at=NOW - 8 * DAY)
    add_run("a-day", ended_at=NOW - DAY)
    session.commit()
    assert prune(session, NOW, runs_days=7).runs == 1
    assert ids(session, Run.id) == ["a-day"]


def test_the_time_limit_is_the_same_instant_in_any_timezone(session: Session, add_run: AddRun) -> None:
    add_run("old", ended_at=NOW - 91 * DAY)
    add_run("recent", ended_at=NOW - 89 * DAY)
    session.commit()
    prune(session, NOW.astimezone(timezone(timedelta(hours=-11))))
    assert ids(session, Run.id) == ["recent"]


def test_everything_but_runs_and_unused_pipeline_text_is_left_alone(
    session: Session, add_run_tree: AddRun
) -> None:
    add_run_tree("old", ended_at=NOW - 200 * DAY)
    session.add(Metric(name="bytes_written", value=1.0, ts=NOW - 200 * DAY))  # no run
    session.add(Setting(key="theme", value_json='"dark"', updated_at=NOW - 200 * DAY))
    append_audit_event(session, principal="me", action="x", resource="r", outcome="ok", details={})
    session.commit()

    prune(session, NOW + 400 * DAY)  # far in the future: everything is old
    session.commit()

    assert session.scalar(select(func.count()).select_from(Dataset)) == 1  # a dataset outlives its runs
    assert session.scalar(select(func.count()).select_from(Setting)) == 1
    # The pipeline and its version went with their last run: the text is not kept longer than its runs.
    assert session.scalar(select(func.count()).select_from(PipelineVersion)) == 0
    assert session.scalar(select(func.count()).select_from(Pipeline)) == 0
    # The audit log lost nothing and gained the event of the prune itself.
    assert ids(session, AuditEvent.action) == ["retention.prune", "x"]
    assert verify_audit_chain(session).ok
    assert session.scalar(select(func.count()).select_from(Metric).where(Metric.run_id.is_(None))) == 1
    assert session.scalar(select(func.count()).select_from(Run)) == 0


def test_the_database_is_consistent_afterwards(session: Session, add_run_tree: AddRun) -> None:
    add_run_tree("old", ended_at=NOW - 200 * DAY)
    add_run_tree("new", ended_at=NOW - DAY)
    session.commit()
    prune(session, NOW)
    session.commit()
    assert session.execute(text("PRAGMA foreign_key_check")).all() == []
    assert session.execute(text("PRAGMA integrity_check")).scalar() == "ok"


def test_pruning_changes_nothing_until_the_caller_commits(
    engine: Engine, session: Session, add_run: AddRun
) -> None:
    add_run("old", ended_at=NOW - 200 * DAY)
    session.commit()
    assert prune(session, NOW) == PruneResult(runs=1, versions=1, pipelines=1)
    with session_factory(engine)() as other:  # prune did not commit: nobody else sees any of it
        assert ids(other, Run.id) == ["old"]
        assert ids(other, AuditEvent.id) == []
    session.rollback()
    assert ids(session, Run.id) == ["old"]
    assert ids(session, PipelineVersion.id) == [1]
    assert ids(session, AuditEvent.id) == []  # the event is rolled back with the deletions


# --- the audit event ---------------------------------------------------------------------------------


def test_a_prune_leaves_a_retention_event_in_the_audit_log_with_the_counts(
    session: Session, add_run_tree: AddRun
) -> None:
    add_run_tree("old", ended_at=NOW - 91 * DAY)
    session.commit()

    assert prune(session, NOW) == PruneResult(runs=1, versions=1, pipelines=1)
    session.commit()

    (event,) = session.scalars(select(AuditEvent)).all()
    assert (event.principal, event.action, event.resource, event.outcome) == (
        "system",
        "retention.prune",
        "run_history",
        "success",
    )
    assert json.loads(event.details_json) == {"runs": 1, "versions": 1, "pipelines": 1}  # counts only
    assert verify_audit_chain(session).ok


def test_a_prune_that_deletes_nothing_is_in_the_audit_log_too(session: Session) -> None:
    prune(session, NOW)
    session.commit()
    (event,) = session.scalars(select(AuditEvent)).all()
    assert (event.action, json.loads(event.details_json)) == (
        "retention.prune",
        {"runs": 0, "versions": 0, "pipelines": 0},
    )


def test_every_prune_adds_an_event_to_the_one_chain(session: Session, add_run: AddRun) -> None:
    append_audit_event(session, principal="me", action="x", resource="r", outcome="ok", details={})
    add_run("old", ended_at=NOW - 200 * DAY)
    session.commit()
    prune(session, NOW)
    prune(session, NOW)
    session.commit()
    events = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
    assert [e.action for e in events] == ["x", "retention.prune", "retention.prune"]
    assert [json.loads(e.details_json)["runs"] for e in events[1:]] == [1, 0]
    assert events[1].prev_hash == events[0].hash
    assert events[2].prev_hash == events[1].hash
    assert verify_audit_chain(session).ok


def test_pruning_twice_or_an_empty_database_deletes_nothing(session: Session, add_run: AddRun) -> None:
    assert prune(session, NOW) == PruneResult(runs=0)
    add_run("old", ended_at=NOW - 200 * DAY)
    session.commit()
    assert prune(session, NOW).runs == 1
    assert prune(session, NOW) == PruneResult(runs=0)


def test_a_time_without_a_timezone_is_refused(session: Session) -> None:
    with pytest.raises(ValueError, match="no timezone"):
        prune(session, datetime(2026, 9, 30, 12, 0))


def test_the_result_says_what_it_counts() -> None:
    result = PruneResult(runs=2, versions=1, pipelines=1)
    assert (result.runs, result.versions, result.pipelines) == (2, 1, 1)
    with pytest.raises(AttributeError):
        result.runs = 3  # type: ignore[misc]


def test_the_text_of_a_pipeline_goes_with_the_last_run_that_used_it(
    session: Session, add_run: AddRun
) -> None:
    add_run("old", ended_at=NOW - 200 * DAY)  # version 1 of p1
    session.add(PipelineVersion(id=2, pipeline_id="p1", version=2, yaml_text="y", spec_sha256="1" * 64))
    session.add(Pipeline(id="p2", name="p2"))
    session.add(PipelineVersion(id=3, pipeline_id="p2", version=1, yaml_text="z", spec_sha256="2" * 64))
    session.flush()
    session.add(Run(id="kept", pipeline_id="p1", pipeline_version_id=2, state="running"))
    session.add(
        Run(id="p2-old", pipeline_id="p2", pipeline_version_id=3, state="failed", ended_at=NOW - 100 * DAY)
    )
    session.add(Pipeline(id="p3", name="p3"))  # no run, no version, nothing: it goes too
    session.commit()

    assert prune(session, NOW) == PruneResult(runs=2, versions=2, pipelines=2)
    session.commit()

    assert ids(session, PipelineVersion.id) == [2]  # the version of the run that is left
    assert ids(session, Pipeline.id) == ["p1"]
    assert session.execute(text("PRAGMA foreign_key_check")).all() == []
