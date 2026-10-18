"""The manifest of a dataset run (docs/guide.md, "Manifest"): what a run wrote, checkable without the app.

It is written last, after every data file is committed, and it is the commit marker: a file that no manifest
lists is not part of the dataset. It holds facts about the data (names, types, counts, sizes, hashes), never
values.
"""

from datetime import UTC, timedelta
from pathlib import Path
from typing import Annotated, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator

from .writer import CommitWriter

MANIFEST_DIR = "_manifest"

# A run id becomes part of file names, so it can't hold a path separator, a dot at the start, or much else.
RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"
RunId = Annotated[str, StringConstraints(pattern=RUN_ID_PATTERN)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Column(_Model):
    """A column of the dataset: its name and its type as Arrow writes it, such as `string` or `int64`."""

    name: str
    type: str


class FileEntry(_Model):
    """A data file of the run. `path` is relative to the dataset folder, with `/` between the parts."""

    path: str
    rows: Annotated[int, Field(ge=0)]
    bytes: Annotated[int, Field(ge=0)]
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    compression: str


class Totals(_Model):
    rows: Annotated[int, Field(ge=0)]
    bytes: Annotated[int, Field(ge=0)]


class Lineage(_Model):
    """Where the data came from (URIs of the inputs) and which operators touched it on the way."""

    inputs: list[str]
    operators: list[str]


class Manifest(_Model):
    """The manifest as docs/guide.md shows it ("Manifest"). In JSON the columns are called `schema`."""

    # `schema` is also a method of BaseModel, so the field has another name in Python and this alias in JSON.
    model_config = ConfigDict(populate_by_name=True)

    dataset: str
    run_id: RunId
    pipeline: str
    committed_at: AwareDatetime  # UTC
    columns: list[Column] = Field(alias="schema")
    files: list[FileEntry]
    totals: Totals
    classification: dict[str, str] = Field(default_factory=dict)
    lineage: Lineage

    @model_validator(mode="after")
    def _is_consistent(self) -> Self:
        if self.committed_at.utcoffset() != timedelta(0):
            raise ValueError("committed_at must be in UTC")
        if self.totals != Totals(
            rows=sum(f.rows for f in self.files), bytes=sum(f.bytes for f in self.files)
        ):
            raise ValueError("totals are not the sum of the files")
        return self


def manifest_file_name(manifest: Manifest) -> str:
    """`run=2026-09-29T02-14-07Z_r45.json`: the UTC time (with `-` in the clock, for FAT) and the run id."""
    stamp = manifest.committed_at.astimezone(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")
    return f"run={stamp}_{manifest.run_id}.json"


def write_manifest(dataset_dir: Path, manifest: Manifest) -> Path:
    """Write `_manifest/run=<UTC time>_<run id>.json` in `dataset_dir`, atomically, and return its path.

    Call it after the data files are committed: the manifest is the commit marker. It refuses to replace a
    manifest of the same name.
    """
    text = manifest.model_dump_json(by_alias=True, indent=2) + "\n"
    with CommitWriter(dataset_dir / MANIFEST_DIR / manifest_file_name(manifest)) as writer:
        writer.write(text.encode())
        return writer.commit().path
