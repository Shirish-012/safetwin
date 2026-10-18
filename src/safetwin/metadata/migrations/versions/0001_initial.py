"""The metadata database, version 1: every table of the run history (docs/internals.md).

Revision ID: 0001
Revises:
Create Date: 2026-10-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "pipelines",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pipelines")),
    )

    op.create_table(
        "pipeline_versions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("pipeline_id", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("yaml_text", sa.Text(), nullable=False),
        sa.Column("spec_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["pipeline_id"],
            ["pipelines.id"],
            name=op.f("fk_pipeline_versions_pipeline_id_pipelines"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_pipeline_versions")),
        sa.UniqueConstraint("pipeline_id", "version", name="uq_pipeline_versions_pipeline_id_version"),
    )

    op.create_table(
        "runs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("pipeline_id", sa.String(), nullable=False),
        sa.Column("pipeline_version_id", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("error_class", sa.String(), nullable=True),
        sa.CheckConstraint(
            "length(CAST(error_class AS BLOB)) <= 256", name=op.f("ck_runs_error_class_length")
        ),
        sa.ForeignKeyConstraint(
            ["pipeline_id"], ["pipelines.id"], name=op.f("fk_runs_pipeline_id_pipelines"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["pipeline_version_id"],
            ["pipeline_versions.id"],
            name=op.f("fk_runs_pipeline_version_id_pipeline_versions"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_runs")),
    )
    op.create_index("ix_runs_ended_at", "runs", ["ended_at"], unique=False)
    op.create_index("ix_runs_pipeline_id_started_at", "runs", ["pipeline_id", "started_at"], unique=False)
    op.create_index(op.f("ix_runs_pipeline_version_id"), "runs", ["pipeline_version_id"], unique=False)

    op.create_table(
        "task_instances",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("node_id", sa.String(), nullable=False),
        sa.Column("stage_index", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_task_instances_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_instances")),
        sa.UniqueConstraint("run_id", "node_id", name="uq_task_instances_run_id_node_id"),
    )

    op.create_table(
        "task_attempts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_instance_id", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("ended_at", sa.DateTime(), nullable=True),
        sa.Column("exit_reason", sa.String(), nullable=True),
        sa.Column("error_class", sa.String(), nullable=True),
        sa.CheckConstraint(
            "length(CAST(error_class AS BLOB)) <= 256", name=op.f("ck_task_attempts_error_class_length")
        ),
        sa.CheckConstraint(
            "length(CAST(exit_reason AS BLOB)) <= 256", name=op.f("ck_task_attempts_exit_reason_length")
        ),
        sa.ForeignKeyConstraint(
            ["task_instance_id"],
            ["task_instances.id"],
            name=op.f("fk_task_attempts_task_instance_id_task_instances"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_task_attempts")),
        sa.UniqueConstraint("task_instance_id", "attempt", name="uq_task_attempts_task_instance_id_attempt"),
    )

    op.create_table(
        "run_files",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("stage_index", sa.Integer(), nullable=False),
        sa.Column("path", sa.String(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.CheckConstraint("kind IN ('data', 'manifest')", name=op.f("ck_run_files_kind")),
        sa.CheckConstraint(
            "length(sha256) = 64 AND length(CAST(sha256 AS BLOB)) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'",
            name=op.f("ck_run_files_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_run_files_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_run_files")),
    )
    op.create_index(op.f("ix_run_files_run_id"), "run_files", ["run_id"], unique=False)

    op.create_table(
        "metrics",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=True),
        sa.Column("task_instance_id", sa.Integer(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("value", sa.Float(), nullable=False),
        sa.Column("unit", sa.String(), nullable=True),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("resolution", sa.String(), nullable=False),
        sa.CheckConstraint("resolution IN ('raw', '1m', '1h')", name=op.f("ck_metrics_resolution")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_metrics_run_id_runs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["task_instance_id"],
            ["task_instances.id"],
            name=op.f("fk_metrics_task_instance_id_task_instances"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_metrics")),
    )
    op.create_index("ix_metrics_name_ts", "metrics", ["name", "ts"], unique=False)
    op.create_index(op.f("ix_metrics_run_id"), "metrics", ["run_id"], unique=False)
    op.create_index(op.f("ix_metrics_task_instance_id"), "metrics", ["task_instance_id"], unique=False)

    op.create_table(
        "datasets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("uri", sa.String(), nullable=False),
        sa.Column("schema_sha256", sa.String(length=64), nullable=True),
        sa.Column("last_run_id", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_datasets")),
        sa.UniqueConstraint("uri", name=op.f("uq_datasets_uri")),
    )

    op.create_table(
        "lineage",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("dataset_id", sa.Integer(), nullable=False),
        sa.Column("direction", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("direction IN ('input', 'output')", name=op.f("ck_lineage_direction")),
        sa.ForeignKeyConstraint(
            ["dataset_id"], ["datasets.id"], name=op.f("fk_lineage_dataset_id_datasets"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_lineage_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_lineage")),
    )
    op.create_index(op.f("ix_lineage_dataset_id"), "lineage", ["dataset_id"], unique=False)
    op.create_index(op.f("ix_lineage_run_id"), "lineage", ["run_id"], unique=False)

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(), nullable=False),
        sa.Column("principal", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("resource", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(CAST(details_json AS BLOB)) <= 4096", name=op.f("ck_audit_events_details_json_size")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
        sa.UniqueConstraint("hash", name=op.f("uq_audit_events_hash")),
        sqlite_autoincrement=True,
    )

    op.create_table(
        "settings",
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_settings")),
    )


def downgrade() -> None:
    # Dropping a table drops its indexes. The order is the reverse of upgrade(), children first.
    op.drop_table("settings")
    op.drop_table("audit_events")
    op.drop_table("lineage")
    op.drop_table("datasets")
    op.drop_table("metrics")
    op.drop_table("run_files")
    op.drop_table("task_attempts")
    op.drop_table("task_instances")
    op.drop_table("runs")
    op.drop_table("pipeline_versions")
    op.drop_table("pipelines")
