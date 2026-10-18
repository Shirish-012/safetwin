"""What a stage that failed may have left in its sink, and how it is removed.

`run_pipeline_local` calls this after a stage fails, and so does the control plane after a stage worker fails,
is cancelled or is killed (`safetwin.executor`): the worker may not have had the chance to clean up itself.
It needs only the paths of the sink, so it imports neither Polars, PyArrow nor DuckDB (the manifest is a
pydantic model, and the writer uses the standard library only).
"""

import re
import stat
from contextlib import suppress
from pathlib import Path

from .manifest import MANIFEST_DIR, Manifest
from .writer import remove_temporaries


def remove_stage_leftovers(
    file: Path, dataset_dir: Path, relative: str, run_id: str, *, existed: bool
) -> None:
    """After a stage failed: the temporary files of its sink, and its data file if no manifest lists it.

    `file` is the data file the stage writes, `dataset_dir` the folder of its dataset (with the `_manifest`
    folder) and `relative` the path of the file below it, as the manifest says it. `existed` says whether the
    file was there before the stage started: then it is not this stage's, and it is left where it is.
    """
    remove_temporary_files(file, dataset_dir, run_id)
    if not existed:
        remove_uncommitted(file, dataset_dir, relative, run_id)


def remove_temporary_files(file: Path, dataset_dir: Path, run_id: str) -> None:
    """The temporary files of the data file and of the manifest of this run, if any are left.

    The stage removes its own, unless it was interrupted at a moment when it could not (`writer.py`), or its
    process was killed. Both names hold the id of the run, so the files of other runs are never touched.
    """
    remove_temporaries(file.parent, re.escape(file.name))
    remove_temporaries(dataset_dir / MANIFEST_DIR, rf"run=[0-9T-]+Z_{re.escape(run_id)}\.json")


def remove_uncommitted(file: Path, dataset_dir: Path, relative: str, run_id: str) -> None:
    """The data file, if it was renamed into place but no manifest of this run lists it.

    That happens when the stage is interrupted between the rename of the file and the end of `finish_stage`,
    which would otherwise remove it. The caller has checked that the file was not there before the stage (its
    name holds the id of the run). Only that path, only a regular file (a link is not followed), and what
    can't be done is left: this runs while another error is on its way.
    """
    with suppress(OSError):
        if not stat.S_ISREG(file.lstat().st_mode) or _listed(dataset_dir, relative, run_id):
            return
        file.unlink()


def _listed(dataset_dir: Path, relative: str, run_id: str) -> bool:
    """Whether a manifest of this run in the dataset lists the file (one that can't be read does: the file is
    then left where it is)."""
    for path in (dataset_dir / MANIFEST_DIR).glob(f"run=*_{run_id}.json"):
        try:
            manifest = Manifest.model_validate_json(path.read_bytes())
        except (OSError, ValueError):
            return True
        if any(entry.path == relative for entry in manifest.files):
            return True
    return False
