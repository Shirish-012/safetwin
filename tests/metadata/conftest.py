"""Fixtures for the metadata database tests: a fresh, migrated database for every test."""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from safetwin.metadata import open_metadata_db, session_factory
from safetwin.metadata.models import (
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


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "metadata.db"


@pytest.fixture
def engine(db_path: Path) -> Iterator[Engine]:
    engine = open_metadata_db(db_path)
    yield engine
    engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with session_factory(engine)() as session:
        yield session


@pytest.fixture
def add_run(session: Session) -> Callable[..., Run]:
    """Adds a run and returns it. The pipeline and version that it needs are added the first time."""

    def add(run_id: str = "run-1", **fields: Any) -> Run:
        if session.get(Pipeline, "p1") is None:
            session.add(Pipeline(id="p1", name="p1"))
            session.add(
                PipelineVersion(id=1, pipeline_id="p1", version=1, yaml_text="x", spec_sha256="0" * 64)
            )
        run = Run(id=run_id, pipeline_id="p1", pipeline_version_id=1, state="success")
        for name, value in fields.items():
            setattr(run, name, value)
        session.add(run)
        session.flush()
        return run

    return add


@pytest.fixture
def add_run_tree(session: Session, add_run: Callable[..., Run]) -> Callable[..., Run]:
    """Adds a run with a task instance, an attempt, a metric, a lineage edge and a file."""

    def add(run_id: str, **fields: Any) -> Run:
        run = add_run(run_id, **fields)
        instance = TaskInstance(run_id=run_id, node_id="read", stage_index=0, state="success")
        session.add(instance)
        session.flush()
        now = datetime.now(UTC)
        session.add(TaskAttempt(task_instance_id=instance.id, attempt=1, state="success"))
        session.add(Metric(run_id=run_id, task_instance_id=instance.id, name="rows_in", value=1.0, ts=now))
        if session.get(Dataset, 1) is None:
            session.add(Dataset(id=1, uri="file:///out"))
            session.flush()
        session.add(Lineage(run_id=run_id, dataset_id=1, direction="output"))
        session.add(
            RunFile(
                run_id=run_id,
                stage_index=0,
                path="/out/part.parquet",
                size_bytes=1,
                sha256="0" * 64,
                kind="data",
            )
        )
        session.flush()
        return run

    return add
