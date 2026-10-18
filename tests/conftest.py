"""Fixtures for every test of the engine: a metadata database migrated by the real migrations, made once."""

import os
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from safetwin.metadata import open_metadata_db

# The same plain output on every machine: Typer forces a coloured terminal when one of these is set (GitHub's
# runners set GITHUB_ACTIONS), and colour codes in the output would break the tests that read it. This runs
# before any test imports Typer, which reads them once.
for _name in ("GITHUB_ACTIONS", "FORCE_COLOR", "PY_COLORS"):
    os.environ.pop(_name, None)


@pytest.fixture(scope="session")
def migrated_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A database at the latest migration, made by Alembic from the migrations, with no rows. Copy it with
    `migrated_db` (the engine's store would otherwise start the maintenance child for every new file)."""
    path = tmp_path_factory.mktemp("migrated") / "metadata.db"
    open_metadata_db(path).dispose()  # the last connection to close folds the WAL into the file
    return path


@pytest.fixture
def migrated_db(migrated_template: Path) -> Callable[[Path], Path]:
    """Copies the migrated database to a path (its folder is made 0700, the file is 0600) and returns it."""

    def copy(path: Path) -> Path:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(migrated_template, path)
        path.chmod(0o600)
        return path

    return copy
