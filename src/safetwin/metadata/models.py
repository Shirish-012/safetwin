"""The metadata database as SQLAlchemy models (docs/internals.md).

It stores facts about data, never data (docs/security.md): no row values, no file contents and no
credentials. The columns that hold codes (`error_class`, `exit_reason`) and the audit `details_json` are
size-limited, so they can hold a code but not a row or a long message. They hold codes, never messages that
quote data.

How the tables are built:
- Timestamps are timezone-aware UTC in Python and stored as UTC (`UTCDateTime`). A naive datetime is an error.
- `*_json` columns hold JSON text. `yaml_text` holds the text of the pipeline that ran: a pipeline file as
  it was written, or the pipeline a masking policy compiled to (`safetwin.masking.compile`). That text never
  holds key material: a policy names its key by reference and the compiled pipeline only names methods and
  domains; the subkeys stay in memory.
- An enum is text with a CHECK constraint, so the database refuses a value the code doesn't know.
- A row that means nothing without its parent is deleted with it (`ON DELETE CASCADE`). History that has
  to outlive what it describes (datasets, the audit log) names its subject with a plain column instead of a
  foreign key.
- Every foreign key has a many-to-one `relationship()`. Without one SQLAlchemy inserts tables in the order of
  their class names, not of their foreign keys, so a child added in the same flush as its parent could fail.
- Every constraint and index has a name (`NAMING_CONVENTION`), so that a migration can change it later.

The tables are created by the Alembic migrations in `migrations/`, not by `create_all`.
"""

from datetime import UTC, datetime
from typing import Any, ClassVar

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    MetaData,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

METRIC_RESOLUTIONS = ("raw", "1m", "1h")
LINEAGE_DIRECTIONS = ("input", "output")
RUN_FILE_KINDS = ("data", "manifest")
SHA256_CHECK = "length(sha256) = 64 AND length(CAST(sha256 AS BLOB)) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'"
CODE_MAX_BYTES = 256  # error_class and exit_reason: short codes
AUDIT_DETAILS_MAX_BYTES = 4096  # audit_events.details_json


class UTCDateTime(TypeDecorator[datetime]):
    """A timestamp that is timezone-aware UTC in Python and plain UTC text in SQLite (which sorts by time)."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.utcoffset() is None:
            raise ValueError(f"{value!r} has no timezone: use an aware datetime such as datetime.now(UTC)")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


def _now() -> datetime:
    return datetime.now(UTC)


def _one_of(column: str, values: tuple[str, ...]) -> CheckConstraint:
    """`column IN (...)`. The constraint is named after the column: `ck_<table>_<column>`."""
    listed = ", ".join(f"'{value}'" for value in values)
    return CheckConstraint(f"{column} IN ({listed})", name=column)


def _max_bytes(column: str, limit: int, suffix: str) -> CheckConstraint:
    """The column is at most `limit` bytes long. The constraint is named `ck_<table>_<column>_<suffix>`.

    The text is cast to a BLOB first: `length()` of text counts characters and stops at a NUL character, so
    a limit on characters could be got round with a NUL, and with characters that take several bytes.
    """
    return CheckConstraint(f"length(CAST({column} AS BLOB)) <= {limit}", name=f"{column}_{suffix}")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map: ClassVar[dict[Any, Any]] = {datetime: UTCDateTime}


# --- pipelines ------------------------------------------------------------------------------------


class Pipeline(Base):
    """A pipeline. Its id is the slug of the file (`metadata.name`)."""

    __tablename__ = "pipelines"

    id: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str]
    description: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(default=_now)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)


class PipelineVersion(Base):
    """A saved version of a pipeline, kept so that versions can be compared."""

    __tablename__ = "pipeline_versions"
    __table_args__ = (
        UniqueConstraint("pipeline_id", "version", name="uq_pipeline_versions_pipeline_id_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    pipeline_id: Mapped[str] = mapped_column(ForeignKey("pipelines.id", ondelete="CASCADE"))
    version: Mapped[int]
    yaml_text: Mapped[str] = mapped_column(Text)
    spec_sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=_now)

    pipeline: Mapped[Pipeline] = relationship()


# --- runs -----------------------------------------------------------------------------------------


class Run(Base):
    """One run of one version of a pipeline. `ended_at` is empty while it is going.

    `error_class` is a short code, such as the name of an exception class (at most 256 bytes). It is never
    a message: messages can quote the data.
    """

    __tablename__ = "runs"
    __table_args__ = (
        _max_bytes("error_class", CODE_MAX_BYTES, "length"),
        Index("ix_runs_pipeline_id_started_at", "pipeline_id", "started_at"),
        Index("ix_runs_ended_at", "ended_at"),
    )

    id: Mapped[str] = mapped_column(primary_key=True)
    pipeline_id: Mapped[str] = mapped_column(ForeignKey("pipelines.id", ondelete="CASCADE"))
    pipeline_version_id: Mapped[int] = mapped_column(
        ForeignKey("pipeline_versions.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[str]
    started_at: Mapped[datetime | None]
    ended_at: Mapped[datetime | None]
    error_class: Mapped[str | None]

    pipeline: Mapped[Pipeline] = relationship()
    version: Mapped[PipelineVersion] = relationship()


class TaskInstance(Base):
    """A node of a pipeline in one run."""

    __tablename__ = "task_instances"
    __table_args__ = (UniqueConstraint("run_id", "node_id", name="uq_task_instances_run_id_node_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"))
    node_id: Mapped[str]
    stage_index: Mapped[int]
    state: Mapped[str]
    started_at: Mapped[datetime | None]
    ended_at: Mapped[datetime | None]

    run: Mapped[Run] = relationship()


class TaskAttempt(Base):
    """One try at a task instance. A retry is a new attempt.

    `exit_reason` and `error_class` are short codes (at most 256 bytes each), never messages that quote data.
    """

    __tablename__ = "task_attempts"
    __table_args__ = (
        UniqueConstraint("task_instance_id", "attempt", name="uq_task_attempts_task_instance_id_attempt"),
        _max_bytes("exit_reason", CODE_MAX_BYTES, "length"),
        _max_bytes("error_class", CODE_MAX_BYTES, "length"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    task_instance_id: Mapped[int] = mapped_column(ForeignKey("task_instances.id", ondelete="CASCADE"))
    attempt: Mapped[int]
    state: Mapped[str]
    started_at: Mapped[datetime] = mapped_column(default=_now)
    ended_at: Mapped[datetime | None]
    exit_reason: Mapped[str | None]
    error_class: Mapped[str | None]

    task_instance: Mapped[TaskInstance] = relationship()


class RunFile(Base):
    """A file that a stage of a run committed: a data file, or the manifest that lists them (`kind`).

    Its path, size and SHA-256 (64 lowercase hex characters) only, so that the history says what was written
    and how to check it. It goes with its run.
    """

    __tablename__ = "run_files"
    __table_args__ = (
        _one_of("kind", RUN_FILE_KINDS),
        # 64 characters and 64 bytes (a NUL would end the first count and the GLOB early), all of 0-9 a-f.
        CheckConstraint(SHA256_CHECK, name="sha256"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    stage_index: Mapped[int]
    path: Mapped[str]
    size_bytes: Mapped[int]
    sha256: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str]

    run: Mapped[Run] = relationship()


# --- metrics --------------------------------------------------------------------------------------


class Metric(Base):
    """A measurement: rows in, bytes written, throughput. Old points are replaced by coarser ones."""

    __tablename__ = "metrics"
    __table_args__ = (_one_of("resolution", METRIC_RESOLUTIONS), Index("ix_metrics_name_ts", "name", "ts"))

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    task_instance_id: Mapped[int | None] = mapped_column(
        ForeignKey("task_instances.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str]
    value: Mapped[float] = mapped_column(Float)
    unit: Mapped[str | None]
    ts: Mapped[datetime]
    resolution: Mapped[str] = mapped_column(default="raw")

    run: Mapped[Run | None] = relationship()
    task_instance: Mapped[TaskInstance | None] = relationship()


# --- datasets and lineage -------------------------------------------------------------------------


class Dataset(Base):
    """An output location the app has written, with the hash of its schema (column names and types)."""

    __tablename__ = "datasets"

    id: Mapped[int] = mapped_column(primary_key=True)
    uri: Mapped[str] = mapped_column(unique=True)
    schema_sha256: Mapped[str | None] = mapped_column(String(64))
    last_run_id: Mapped[str | None]  # no foreign key: a dataset must outlive the run that wrote it
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)


class Lineage(Base):
    """A run read (`input`) or wrote (`output`) a dataset."""

    __tablename__ = "lineage"
    __table_args__ = (_one_of("direction", LINEAGE_DIRECTIONS),)

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("runs.id", ondelete="CASCADE"), index=True)
    dataset_id: Mapped[int] = mapped_column(ForeignKey("datasets.id", ondelete="CASCADE"), index=True)
    direction: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(default=_now)

    run: Mapped[Run] = relationship()
    dataset: Mapped[Dataset] = relationship()


# --- audit and settings ---------------------------------------------------------------------------


class AuditEvent(Base):
    """An entry of the hash-chained audit log (see `audit.py` for how the hashes are made).

    The id is AUTOINCREMENT, so an id is never used again after its row is deleted. The principal is text,
    not a foreign key: the log outlives the people in it.

    Audit rows are permanent, so no data values and no secrets may get in: `details_json` is at most 4 KiB,
    and `append_audit_event` refuses details in which a string looks like a secret.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        _max_bytes("details_json", AUDIT_DETAILS_MAX_BYTES, "size"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime]
    principal: Mapped[str]
    action: Mapped[str]
    resource: Mapped[str]
    outcome: Mapped[str]
    details_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class Setting(Base):
    """An app preference."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(primary_key=True)
    value_json: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(default=_now, onupdate=_now)
