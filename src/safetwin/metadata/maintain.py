"""The maintenance child of the engine: `python -m safetwin.metadata.maintain --database PATH`, with
`--prune-at T` to prune too.

The engine's control plane never imports SQLAlchemy or Alembic (`lite.py`), so what needs them runs here, in a
short-lived process that the engine starts and waits for (`lite.run_maintenance`), while it holds the instance
lock:

1. `open_metadata_db` migrates the database to the latest version (Alembic, only if it is behind).
2. With `--prune-at` (an ISO time with a timezone), `prune` deletes runs that ended more than `--runs-days`
   days before it, and adds its `retention.prune` event to the audit log (pipeline versions and pipelines
   that no run refers to any more go too); then it prints `pruned runs=<n> versions=<n> pipelines=<n>` on
   stdout.

Exit status: 0 when it is done, 1 when it failed, 2 for bad arguments. Nothing it prints on stderr is shown by
the engine (a failure is reported by its exit status), and it prints the type of an error only, never its
text. Nothing is imported until the arguments are checked.
"""

import argparse
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path


def main(argv: Sequence[str] | None = None) -> int:
    """The child, as the module docs say. Its exit status."""
    parser = argparse.ArgumentParser(
        prog="safetwin-maintain", description="Migrate and prune the metadata database."
    )
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--prune-at", type=datetime.fromisoformat)
    parser.add_argument("--runs-days", type=int, default=90)
    options = parser.parse_args(argv)
    if options.prune_at is not None and options.prune_at.utcoffset() is None:
        parser.error("--prune-at needs a timezone")
    try:
        from .db import open_metadata_db, prune, session_factory

        engine = open_metadata_db(options.database)
        try:
            if options.prune_at is not None:
                with session_factory(engine)() as session:
                    result = prune(session, options.prune_at, runs_days=options.runs_days)
                    session.commit()
                print(
                    f"pruned runs={result.runs} versions={result.versions} pipelines={result.pipelines}",
                    flush=True,
                )
        finally:
            engine.dispose()
    except Exception as err:  # its text could say anything: the type only
        print(f"the maintenance failed ({type(err).__name__})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
