"""Alembic environment of the metadata database.

Migrations are run by `safetwin.metadata.db`, which hands over its connection (and its transaction), so
there is no alembic.ini and no database URL here. To write the next migration, compare a database at the
latest version with the models: `alembic.command.revision(config, autogenerate=True)` with a `Config` set up
like the one in `db._upgrade`, then read what it wrote. Never import the models from a migration: a migration
describes the database as it was when it was written.
"""

from alembic import context

from safetwin.metadata.models import Base

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("run the migrations through safetwin.metadata.db.open_metadata_db")

context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    compare_type=True,
    render_as_batch=True,  # SQLite can't alter a table in place: a change to a column rebuilds the table
)
with context.begin_transaction():
    context.run_migrations()
