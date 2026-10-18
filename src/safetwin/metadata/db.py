"""Open the metadata database: a private SQLite file in WAL mode, migrated to the latest version.

Also the retention rule (docs/internals.md): run history is kept 90 days.

This module needs SQLAlchemy, so the engine's control plane never imports it: it uses `lite.py` (sqlite3)
and runs what needs this module in a child process (`maintain.py`). The pragmas, the mode of the file and the
latest revision are defined once, in `lite.py`, and used by both. Alembic is imported only when the database
is not at the latest migration (`HEAD_REVISION`): the version is read with a plain query first.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from sqlalchemy import URL, CursorResult, Delete, Engine, create_engine, delete, event, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from . import lite
from .audit import append_audit_event
from .lite import HEAD_REVISION
from .models import Pipeline, PipelineVersion, Run

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def open_metadata_db(path: Path) -> Engine:
    """Open the metadata database at `path`, creating and upgrading it as needed.

    The folder is created with mode 0700 (when it is not there yet) and the file with 0600, so other users
    of the machine can't read it. Every connection is set to WAL mode with foreign keys on, a busy timeout of
    5 seconds and `synchronous=NORMAL`, and the schema is upgraded to the latest migration before this
    returns. Several threads or processes may do this at once. SQLite gives the -wal and -shm files the mode
    of the database file, so they are 0600 too.
    """
    lite.create_private_file(path)
    engine = create_engine(URL.create("sqlite", database=str(path)))
    event.listen(engine, "connect", _set_pragmas)
    try:
        if current_revision(engine) != HEAD_REVISION:
            _upgrade(engine)
    except BaseException:
        engine.dispose()  # don't leave a connection open on a file that could not be set up
        raise
    return engine


def session_factory(engine: Engine) -> sessionmaker[Session]:
    """Sessions for `engine`. Objects stay usable after a commit, without being read again."""
    return sessionmaker(engine, expire_on_commit=False)


def _set_pragmas(dbapi_connection: sqlite3.Connection, _record: object) -> None:
    """Every new connection gets the pragmas of `lite.set_pragmas`, as the engine's own connections do."""
    lite.set_pragmas(dbapi_connection)


def current_revision(engine: Engine) -> str | None:
    """The migration the database is at, read without Alembic. None for a database without tables."""
    with engine.connect() as connection:
        try:
            return connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar()
        except OperationalError:  # no such table: a new file
            return None


def _upgrade(engine: Engine) -> None:
    from alembic import command  # only here: see the module docs
    from alembic.config import Config

    config = Config()  # no alembic.ini: everything Alembic needs is set here or handed to env.py
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    with engine.connect() as connection:
        # One upgrade at a time (a second process waits here, then finds nothing to do), and all or nothing:
        # SQLite can roll back DDL, but only when the transaction is started by hand.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        connection.commit()


@dataclass(frozen=True)
class PruneResult:
    """How many runs `prune` deleted, and how many pipeline versions and pipelines it deleted because nothing
    refers to them any more."""

    runs: int
    versions: int = 0
    pipelines: int = 0


def prune(session: Session, now: datetime, runs_days: int = 90) -> PruneResult:
    """Delete runs that ended more than `runs_days` ago.

    A run that has not ended is kept, however long it has been going. Deleting a run also deletes its tasks,
    attempts, metrics, lineage and files (they are cascades of the database, so objects of those that the
    session has loaded are stale afterwards).

    The text of a pipeline goes with the last run that used it: a pipeline version that no run refers to any
    more is deleted, and so is a pipeline that nothing refers to (no run or version). The text was checked for
    secrets before it was kept (`history.kept_text`), but a plain password in a URL or in a comment may look
    like nothing in particular, so it is not kept longer than its runs.

    Every call adds a `retention.prune` event to the audit log (`audit.py`), with the three counts
    and nothing else, also when nothing was deleted. The changes and the event are part of the session's
    transaction: the caller commits. `now` must have a timezone.
    """
    if now.utcoffset() is None:
        raise ValueError(f"{now!r} has no timezone: use an aware datetime such as datetime.now(UTC)")
    runs = _delete(session, delete(Run).where(Run.ended_at < now - timedelta(days=runs_days)))
    versions = _delete(
        session,
        delete(PipelineVersion).where(
            ~select(Run.id).where(Run.pipeline_version_id == PipelineVersion.id).exists()
        ),
    )
    pipelines = _delete(
        session,
        delete(Pipeline).where(
            *(
                ~select(model.id).where(model.pipeline_id == Pipeline.id).exists()
                for model in (Run, PipelineVersion)
            )
        ),
    )
    append_audit_event(
        session,
        principal="system",
        action="retention.prune",
        resource="run_history",
        outcome="success",
        details={"runs": runs, "versions": versions, "pipelines": pipelines},
    )
    return PruneResult(runs=runs, versions=versions, pipelines=pipelines)


def _delete(session: Session, statement: Delete) -> int:
    """Run a DELETE and say how many rows it deleted, not counting what the database cascaded."""
    result = cast(
        "CursorResult[Any]", session.execute(statement, execution_options={"synchronize_session": False})
    )
    return result.rowcount
