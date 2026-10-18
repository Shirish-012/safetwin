"""Opening the metadata database: the file, the connections, and the migration that builds the tables."""

import os
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from safetwin.metadata import db, lite, open_metadata_db, session_factory
from safetwin.metadata.db import MIGRATIONS_DIR
from safetwin.metadata.models import Base, Pipeline

TABLES = {
    "pipelines",
    "pipeline_versions",
    "runs",
    "task_instances",
    "task_attempts",
    "metrics",
    "datasets",
    "lineage",
    "audit_events",
    "settings",
    "run_files",
}


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def head() -> str | None:
    return ScriptDirectory(str(MIGRATIONS_DIR)).get_current_head()


def revision_of(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def differences(engine: Engine) -> list[str]:
    """What Alembic's autogenerate would change in the database to make it match the models."""
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        return sorted(str(diff[0]) for diff in compare_metadata(context, Base.metadata))


# --- the migration -------------------------------------------------------------------------------


def test_a_fresh_database_is_upgraded_to_the_latest_migration(engine: Engine) -> None:
    assert head() is not None
    assert revision_of(engine) == head()
    with engine.connect() as connection:
        assert set(inspect(connection).get_table_names()) == TABLES | {"alembic_version"}


def test_the_models_match_the_migration(engine: Engine) -> None:
    # Alembic's autogenerate compares the database with the models. No difference means that a model changed
    # without a migration, or the other way round, would show up here.
    assert differences(engine) == []


def test_the_comparison_does_notice_a_difference(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP INDEX ix_metrics_name_ts")
        connection.exec_driver_sql("ALTER TABLE settings ADD COLUMN extra TEXT")
    assert differences(engine) == ["add_index", "remove_column"]


def test_the_migration_can_be_undone_and_done_again(engine: Engine) -> None:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        command.downgrade(config, "base")
        connection.commit()
        assert inspect(connection).get_table_names() == ["alembic_version"]
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        command.upgrade(config, "head")
        connection.commit()
    assert revision_of(engine) == head()
    assert differences(engine) == []


BROKEN_MIGRATION = """
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table("first", sa.Column("id", sa.Integer(), primary_key=True))
    raise RuntimeError("the second table is where it breaks")


def downgrade() -> None:
    op.drop_table("first")
"""


def test_a_migration_that_fails_halfway_leaves_nothing_behind(
    db_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The whole upgrade is one transaction, so a file is never left with half of its tables.
    scratch = tmp_path / "broken-migrations"
    (scratch / "versions").mkdir(parents=True)
    (scratch / "env.py").write_text((MIGRATIONS_DIR / "env.py").read_text(encoding="utf-8"), encoding="utf-8")
    (scratch / "versions" / "0001_broken.py").write_text(BROKEN_MIGRATION, encoding="utf-8")
    with monkeypatch.context() as patch:
        patch.setattr("safetwin.metadata.db.MIGRATIONS_DIR", scratch)
        with pytest.raises(RuntimeError, match="the second table is where it breaks"):
            open_metadata_db(db_path)
    with sqlite3.connect(db_path) as raw:
        assert raw.execute("SELECT name FROM sqlite_master").fetchall() == []
    engine = open_metadata_db(db_path)  # the real migrations, on the same file
    assert revision_of(engine) == head()
    engine.dispose()


def test_opening_a_database_again_keeps_what_is_in_it(db_path: Path) -> None:
    engine = open_metadata_db(db_path)
    with session_factory(engine)() as session:
        session.add(Pipeline(id="p1", name="First"))
        session.commit()
    engine.dispose()
    engine = open_metadata_db(db_path)
    with session_factory(engine)() as session:
        assert session.get(Pipeline, "p1") is not None
    assert revision_of(engine) == head()
    engine.dispose()


def test_several_threads_may_open_a_new_database_at_the_same_time(tmp_path: Path) -> None:
    # The switch to WAL mode fails at once, busy timeout or not, when connections meet on a new file.
    # That is a matter of timing, so there are many rounds: before this was handled one in fifty failed.
    errors: list[Exception] = []
    engines: list[Engine] = []
    for round_number in range(10):
        path = tmp_path / f"round-{round_number}" / "metadata.db"
        barrier = threading.Barrier(4)

        def open_it(path: Path = path, barrier: threading.Barrier = barrier) -> None:
            try:
                barrier.wait()
                engines.append(open_metadata_db(path))
            except Exception as err:
                errors.append(err)  # reported below, from the main thread

        threads = [threading.Thread(target=open_it) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    assert errors == []
    assert len(engines) == 40
    for engine in engines:
        assert revision_of(engine) == head()
        engine.dispose()


def busy_writer(path: Path) -> sqlite3.Connection:
    """A connection in the middle of a write to a file that is not in WAL mode yet."""
    writer = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
    writer.execute("CREATE TABLE t (x)")
    writer.execute("BEGIN IMMEDIATE")
    return writer


def test_opening_a_database_that_is_being_written_waits_for_the_writer(tmp_path: Path) -> None:
    path = tmp_path / "metadata.db"
    writer = busy_writer(path)
    impatient = sqlite3.connect(path)
    impatient.execute("PRAGMA busy_timeout=5000")
    with pytest.raises(
        sqlite3.OperationalError, match="locked"
    ):  # the reason for the wait: SQLite gives up at once
        impatient.execute("PRAGMA journal_mode=WAL")
    impatient.close()

    threading.Timer(0.3, writer.execute, args=("COMMIT",)).start()
    started = time.monotonic()
    engine = open_metadata_db(path)
    assert time.monotonic() - started >= 0.2
    assert revision_of(engine) == head()
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
    engine.dispose()
    writer.close()


def test_opening_a_database_gives_up_when_the_writer_does_not_finish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "metadata.db"
    writer = busy_writer(path)
    monkeypatch.setattr(lite, "BUSY_TIMEOUT_MS", 200)  # the pragmas are lite's, shared with the engine
    started = time.monotonic()
    with pytest.raises(OperationalError, match="database is locked"):
        open_metadata_db(path)
    assert 0.15 <= time.monotonic() - started < 5
    writer.execute("COMMIT")
    writer.close()


def test_an_error_that_is_not_about_a_busy_file_is_not_waited_for(tmp_path: Path) -> None:
    path = tmp_path / "readonly.db"
    with sqlite3.connect(path) as setup:
        setup.execute("CREATE TABLE t (x)")
    readonly = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    started = time.monotonic()
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        db._set_pragmas(readonly, None)
    assert time.monotonic() - started < 1  # it did not retry for the 5 seconds of the busy timeout
    readonly.close()


# --- the connections -----------------------------------------------------------------------------


def test_every_new_connection_gets_the_pragmas(engine: Engine) -> None:
    connections = [engine.connect() for _ in range(3)]  # held together, so that three really are opened
    try:
        for connection in connections:
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar() == 5000
            assert connection.exec_driver_sql("PRAGMA synchronous").scalar() == 1  # NORMAL
    finally:
        for connection in connections:
            connection.close()


def test_foreign_keys_are_enforced_not_just_switched_on(session: Session) -> None:
    insert = (
        "INSERT INTO runs (id, pipeline_id, pipeline_version_id, state) VALUES ('r', 'nope', 1, 'queued')"
    )
    with pytest.raises(IntegrityError, match="FOREIGN KEY constraint failed"):
        session.execute(text(insert))


def test_the_journal_stays_in_wal_mode_when_the_file_is_opened_again(db_path: Path) -> None:
    open_metadata_db(db_path).dispose()
    engine = open_metadata_db(db_path)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
    engine.dispose()


def test_sessions_keep_their_objects_usable_after_a_commit(engine: Engine) -> None:
    with session_factory(engine)() as session:
        pipeline = Pipeline(id="p1", name="First")
        session.add(pipeline)
        session.commit()
    assert pipeline.name == "First"  # the session is closed, and nothing is read again


# --- the file and the folder ---------------------------------------------------------------------


def test_the_folder_is_private_and_so_are_the_database_files(db_path: Path) -> None:
    engine = open_metadata_db(db_path)
    with session_factory(engine)() as session:
        session.add(Pipeline(id="p1", name="First"))
        session.commit()
    assert mode(db_path.parent) == 0o700
    assert sorted(path.name for path in db_path.parent.iterdir()) == [
        "metadata.db",
        "metadata.db-shm",  # these two exist while the database is in use
        "metadata.db-wal",
    ]
    for path in db_path.parent.iterdir():
        assert mode(path) == 0o600, path.name
    engine.dispose()


@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_the_modes_do_not_depend_on_the_umask(db_path: Path, umask: int) -> None:
    previous = os.umask(umask)
    try:
        engine = open_metadata_db(db_path)
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
    finally:
        os.umask(previous)
    assert mode(db_path.parent) == 0o700
    assert {mode(path) for path in db_path.parent.iterdir()} == {0o600}
    engine.dispose()


def test_folders_that_are_missing_are_created(tmp_path: Path) -> None:
    path = tmp_path / "a" / "b" / "metadata.db"
    engine = open_metadata_db(path)
    assert path.is_file()
    assert mode(path.parent) == 0o700
    engine.dispose()


def test_a_file_that_has_looser_rights_is_made_private(db_path: Path) -> None:
    db_path.parent.mkdir()
    db_path.parent.chmod(0o755)
    db_path.touch()
    db_path.chmod(0o644)
    engine = open_metadata_db(db_path)
    assert mode(db_path) == 0o600
    assert mode(db_path.parent) == 0o755  # a folder that was already there is not the app's to change
    engine.dispose()


# --- the one migration and the check without Alembic --------------------------------------------------------


def test_the_head_revision_the_code_knows_is_the_latest_migration() -> None:
    assert head() == db.HEAD_REVISION


def test_there_is_one_migration_and_it_is_the_first() -> None:
    # Nothing was released before the schema was squashed into one migration, so there is no upgrade path.
    revisions = list(ScriptDirectory(str(MIGRATIONS_DIR)).walk_revisions())
    assert [(revision.revision, revision.down_revision) for revision in revisions] == [("0001", None)]


def test_the_migration_can_be_undone_to_an_empty_database(engine: Engine) -> None:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        command.downgrade(config, "base")
        connection.commit()
        assert inspect(connection).get_table_names() == ["alembic_version"]
    assert revision_of(engine) is None


def test_a_database_that_is_up_to_date_is_opened_without_importing_alembic(db_path: Path) -> None:
    open_metadata_db(db_path).dispose()  # made and migrated, with Alembic
    script = (
        "import sys\n"
        "from pathlib import Path\n"
        "from safetwin.metadata import open_metadata_db\n"
        f"engine = open_metadata_db(Path({str(db_path)!r}))\n"
        "engine.dispose()\n"
        "print(sorted(name for name in sys.modules if name.split('.')[0] == 'alembic'))\n"
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "[]"
    fresh = db_path.parent / "fresh.db"
    script = script.replace(repr(str(db_path)), repr(str(fresh)))
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True)
    assert "alembic" in done.stdout  # a new file needs it
    assert current_revision_of(fresh) == db.HEAD_REVISION


def current_revision_of(path: Path) -> str | None:
    engine = db.create_engine(db.URL.create("sqlite", database=str(path)))
    try:
        return db.current_revision(engine)
    finally:
        engine.dispose()


def test_the_revision_of_a_file_without_tables_is_none(tmp_path: Path) -> None:
    path = tmp_path / "empty.db"
    sqlite3.connect(path).close()
    assert current_revision_of(path) is None


def test_an_existing_database_file_is_never_opened_to_make_it_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Closing a descriptor of a file drops every POSIX lock the process holds on it, the shared lock of an
    # open SQLite connection included: the maintenance child would then delete the -wal and -shm files that
    # the engine still writes to (seen on Linux as "disk I/O error" after a prune).
    path = tmp_path / "home" / "metadata.db"
    lite.create_private_file(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.chmod(0o644)
    opened: list[str] = []  # descriptors made: trying O_EXCL on an existing file makes none
    real_open = os.open

    def recording_open(name: str | os.PathLike[str], *args: object, **kwargs: object) -> int:
        fd = real_open(name, *args, **kwargs)  # type: ignore[arg-type]
        opened.append(str(name))
        return fd

    monkeypatch.setattr(os, "open", recording_open)
    lite.create_private_file(path)
    assert opened == []
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
