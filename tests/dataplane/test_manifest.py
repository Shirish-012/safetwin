"""The manifest: the fields of docs/guide.md ("Manifest"), written atomically into the dataset folder."""

import json
import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from safetwin.dataplane.manifest import (
    Column,
    FileEntry,
    Lineage,
    Manifest,
    Totals,
    manifest_file_name,
    write_manifest,
)

REPO = Path(__file__).resolve().parents[2]
COMMITTED_AT = datetime(2026, 9, 29, 2, 14, 7, tzinfo=UTC)


def a_manifest(**changes: Any) -> Manifest:
    fields: dict[str, Any] = {
        "dataset": "network/flows",
        "run_id": "r45",
        "pipeline": "shop-to-staging",
        "committed_at": COMMITTED_AT,
        "columns": [Column(name="ts", type="timestamp[us, tz=UTC]"), Column(name="src", type="string")],
        "files": [
            FileEntry(
                path="dt=2026-09-29/part-00000-r45.parquet",
                rows=10,
                bytes=200,
                sha256="a" * 64,
                compression="zstd",
            ),
            FileEntry(
                path="dt=2026-09-29/part-00001-r45.parquet",
                rows=5,
                bytes=100,
                sha256="b" * 64,
                compression="zstd",
            ),
        ],
        "totals": Totals(rows=15, bytes=300),
        "lineage": Lineage(inputs=["socket://local-inbox/orders/*.csv"], operators=["transform.filter"]),
    }
    return Manifest(**{**fields, **changes})


def docs_manifest() -> dict[str, Any]:
    """The JSON example of docs/guide.md, "Manifest"."""
    text = (REPO / "docs" / "guide.md").read_text(encoding="utf-8")
    block = re.search(r"### Manifest.*?```json\n(.*?)```", text, re.DOTALL)
    assert block, "the manifest example is gone from docs/guide.md"
    loaded: dict[str, Any] = json.loads(block.group(1))
    return loaded


# --- the fields ----------------------------------------------------------------------------------------


def test_the_json_has_the_fields_of_the_docs_in_their_order() -> None:
    docs = docs_manifest()
    ours = json.loads(a_manifest().model_dump_json(by_alias=True))
    assert list(ours) == list(docs)
    for key in ("schema", "files"):
        assert list(ours[key][0]) == list(docs[key][0]), key
    for key in ("totals", "lineage"):
        assert list(ours[key]) == list(docs[key]), key
    assert "encryption" not in ours


def test_the_values_are_written_the_way_the_docs_write_them() -> None:
    ours = json.loads(a_manifest().model_dump_json(by_alias=True))
    assert ours["committed_at"] == "2026-09-29T02:14:07Z"  # whole seconds, UTC, and a Z
    assert ours["schema"] == [
        {"name": "ts", "type": "timestamp[us, tz=UTC]"},
        {"name": "src", "type": "string"},
    ]
    assert ours["files"][0] == {
        "path": "dt=2026-09-29/part-00000-r45.parquet",
        "rows": 10,
        "bytes": 200,
        "sha256": "a" * 64,
        "compression": "zstd",
    }
    assert ours["totals"] == {"rows": 15, "bytes": 300}
    assert ours["classification"] == {}
    assert ours["lineage"] == {
        "inputs": ["socket://local-inbox/orders/*.csv"],
        "operators": ["transform.filter"],
    }


def test_the_columns_are_called_schema_in_json_and_come_back_from_it() -> None:
    manifest = a_manifest()
    loaded = Manifest.model_validate_json(manifest.model_dump_json(by_alias=True))
    assert loaded == manifest
    assert loaded.columns[0].name == "ts"
    assert Manifest.model_validate(json.loads(manifest.model_dump_json(by_alias=True))) == manifest


# --- what it refuses -------------------------------------------------------------------------------------


def test_totals_must_be_the_sums_of_the_files() -> None:
    with pytest.raises(ValidationError, match="totals are not the sum of the files"):
        a_manifest(totals=Totals(rows=16, bytes=300))
    with pytest.raises(ValidationError, match="totals are not the sum of the files"):
        a_manifest(totals=Totals(rows=15, bytes=299))
    assert a_manifest(files=[], totals=Totals(rows=0, bytes=0)).files == []  # a run that wrote nothing


@pytest.mark.parametrize(
    "when",
    [datetime(2026, 9, 29, 2, 14, 7), datetime(2026, 9, 29, 2, 14, 7, tzinfo=timezone(timedelta(hours=2)))],
    ids=["no timezone", "an offset"],
)
def test_the_commit_time_must_be_utc(when: datetime) -> None:
    with pytest.raises(ValidationError):
        a_manifest(committed_at=when)


@pytest.mark.parametrize(
    "run_id", ["", "../x", "a/b", ".hidden", "-x", "a b", "a" * 65, "r45\n", "é"], ids=repr
)
def test_a_run_id_that_could_not_be_part_of_a_file_name_is_refused(run_id: str) -> None:
    with pytest.raises(ValidationError):
        a_manifest(run_id=run_id)


@pytest.mark.parametrize("run_id", ["r45", "44", "r3f9a1c2d", "a-b_c", "A" * 64])
def test_ordinary_run_ids_are_fine(run_id: str) -> None:
    assert a_manifest(run_id=run_id).run_id == run_id


def test_a_sha256_is_64_lowercase_hex_digits() -> None:
    for bad in ("a" * 63, "A" * 64, "g" * 64, ""):
        with pytest.raises(ValidationError):
            FileEntry(path="x", rows=0, bytes=0, sha256=bad, compression="zstd")


def test_unknown_fields_are_refused() -> None:
    with pytest.raises(ValidationError):
        Manifest.model_validate({**json.loads(a_manifest().model_dump_json(by_alias=True)), "extra": 1})


# --- writing it -----------------------------------------------------------------------------------------


def test_the_file_name_has_the_utc_time_with_dashes_and_the_run_id() -> None:
    assert manifest_file_name(a_manifest()) == "run=2026-09-29T02-14-07Z_r45.json"


def test_write_manifest_puts_it_in_the_manifest_folder_of_the_dataset(tmp_path: Path) -> None:
    manifest = a_manifest()
    path = write_manifest(tmp_path / "flows", manifest)
    assert path == tmp_path / "flows" / "_manifest" / "run=2026-09-29T02-14-07Z_r45.json"
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name]  # no temporary file
    assert path.read_text(encoding="utf-8").endswith("}\n")
    assert Manifest.model_validate_json(path.read_text(encoding="utf-8")) == manifest


def test_write_manifest_does_not_replace_a_manifest(tmp_path: Path) -> None:
    write_manifest(tmp_path, a_manifest())
    with pytest.raises(FileExistsError):
        write_manifest(tmp_path, a_manifest())
    other_second = a_manifest(committed_at=COMMITTED_AT + timedelta(seconds=1))
    assert write_manifest(tmp_path, other_second).exists()  # the same run at another time is another file
    assert len(list((tmp_path / "_manifest").iterdir())) == 2
