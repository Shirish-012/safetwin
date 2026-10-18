"""The fused path and the batch-by-batch path: the same data, the same counts, the same commit discipline."""

import errno
import hashlib
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from safetwin.dataplane import batch, runtime
from safetwin.dataplane.manifest import Manifest
from safetwin.dataplane.operators import ConfigError
from safetwin.dataplane.run import RunResult, run_pipeline_local
from safetwin.dataplane.writer import CommitWriter

PATHS = ["fused", "batch"]
UTC_DATETIME = pl.Datetime("us", "UTC")

# What the signup dates of `conftest.DATES` are once `transform.parse_dates` has read them: in UTC, or null.
PARSED = {
    "2026-01-05 10:00:00": datetime(2026, 1, 5, 10, tzinfo=UTC),
    "2026-01-05T10:00:00Z": datetime(2026, 1, 5, 10, tzinfo=UTC),
    "2026-01-05T10:00:00+05:30": datetime(2026, 1, 5, 4, 30, tzinfo=UTC),
    "2026-02-11": datetime(2026, 2, 11, tzinfo=UTC),
    "2026-03-01 23:59:59.250": datetime(2026, 3, 1, 23, 59, 59, 250000, tzinfo=UTC),
    "not a date": None,
    "2026-13-45": None,
    "": None,
    "05/01/2026": None,
}


def run(pipeline: Any, sockets: Any, path: str, **kwargs: Any) -> RunResult:
    return run_pipeline_local(pipeline, sockets.folders, force_path=path, **kwargs)  # type: ignore[arg-type]


def the_manifest(result: RunResult, stage: int = 0) -> Manifest:
    return Manifest.model_validate_json(result.stages[stage].manifest.read_text(encoding="utf-8"))


@pytest.fixture
def messy_inbox(sockets: Any, data: Any) -> list[list[str]]:
    """Two CSV files with 3,000 messy rows between them. The rows are returned, for the expected values."""
    rows = data.messy_rows(3000)
    data.write_csv(sockets.inbox / "a.csv", rows[:1800])
    data.write_csv(sockets.inbox / "b.csv", rows[1800:])
    return rows  # type: ignore[no-any-return]


# --- the same data on both paths ----------------------------------------------------------------------------


def expected_of(rows: list[list[str]]) -> dict[str, list[Any]]:
    """What the messy pipeline must write for `rows`, worked out in Python without Polars or PyArrow."""
    kept = [row for row in rows if row[0] != ""]  # the filter: one row in ten has no id
    return {
        "id": [int(row[0]) for row in kept],
        "name": [row[1].strip() or None for row in kept],  # an empty field is null
        "city_upper": [row[2].strip().upper() or None for row in kept],
        "amount": [float(row[3]) if row[3] not in ("", "n/a") else None for row in kept],
        "signup": [PARSED[row[4]] for row in kept],
    }


@pytest.mark.parametrize("path", PATHS)
def test_each_path_writes_what_the_pipeline_says_worked_out_independently(
    nodes: Any, data: Any, sockets: Any, messy_inbox: list[list[str]], path: str
) -> None:
    result = run(nodes.messy(), sockets, path)
    written = data.dataset(result.stages[0])
    expected = expected_of(messy_inbox)
    assert written.to_dict(as_series=False) == expected
    # The data was messy enough to matter: every kind of value that has to be dealt with is there.
    for column in ("signup", "amount", "name"):
        assert None in expected[column]
    assert any(name != name.strip() for name in (row[1] for row in messy_inbox))
    assert len(expected["id"]) < len(messy_inbox)


@pytest.mark.parametrize("path", PATHS)
def test_the_types_of_the_columns(nodes: Any, data: Any, sockets: Any, messy_inbox: Any, path: str) -> None:
    result = run(nodes.messy(), sockets, path)
    assert data.dataset(result.stages[0]).schema == pl.Schema(
        {
            "id": pl.Int64,
            "name": pl.String,
            "city_upper": pl.String,
            "amount": pl.Float64,
            "signup": UTC_DATETIME,
        }
    )
    assert [(c.name, c.type) for c in the_manifest(result).columns] == [
        ("id", "int64"),
        ("name", "string"),
        ("city_upper", "string"),
        ("amount", "double"),
        ("signup", "timestamp[us, tz=UTC]"),
    ]


def test_both_paths_write_identical_data_and_count_identical_rows(
    nodes: Any, data: Any, tmp_path: Path, sockets: Any, messy_inbox: list[list[str]]
) -> None:
    results = {}
    for path in PATHS:
        outbox = tmp_path / f"out-{path}"
        outbox.mkdir()
        results[path] = run_pipeline_local(
            nodes.messy(),
            {"inbox": sockets.inbox, "outbox": outbox},
            force_path=path,  # type: ignore[arg-type]
        )
    fused, batched = (results[path].stages[0] for path in PATHS)
    assert (fused.path, batched.path) == ("fused", "batch")
    assert data.dataset(fused).equals(data.dataset(batched))  # the same values, types and order
    assert fused.rows_per_node == batched.rows_per_node
    kept = len(expected_of(messy_inbox)["id"])
    assert fused.rows_per_node == {
        "read": 3000,
        "has_id": kept,
        "tidy": kept,
        "dates": kept,
        "numbers": kept,
        "shout": kept,
        "keep": kept,
        "write": kept,
    }
    first, second = (the_manifest(results[path]) for path in PATHS)
    assert first.columns == second.columns
    assert first.lineage == second.lineage
    assert first.totals.rows == second.totals.rows == kept


@pytest.mark.parametrize("path", PATHS)
def test_the_funnel_is_in_the_order_of_the_nodes_and_ends_with_the_sink(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str
) -> None:
    (stage,) = run(nodes.messy(), sockets, path).stages
    assert list(stage.rows_per_node) == [
        "read",
        "has_id",
        "tidy",
        "dates",
        "numbers",
        "shout",
        "keep",
        "write",
    ]
    counts = list(stage.rows_per_node.values())
    assert counts == sorted(counts, reverse=True)  # a funnel never gets wider
    assert counts[0] > counts[1] == counts[-1]


@pytest.mark.parametrize("path", PATHS)
def test_the_result_of_a_stage(nodes: Any, sockets: Any, messy_inbox: Any, path: str) -> None:
    result = run(nodes.messy(), sockets, path, run_id="r7")
    (stage,) = result.stages
    (file,) = stage.files
    assert result.run_id == "r7"
    assert stage.path == path
    assert stage.duration_s > 0
    assert result.duration_s >= stage.duration_s
    assert file.path == sockets.outbox.resolve() / "messy" / "part-00000-r7.parquet"
    assert stage.manifest.parent == file.path.parent / "_manifest"
    assert re.fullmatch(r"run=\d{4}-\d\d-\d\dT\d\d-\d\d-\d\dZ_r7\.json", stage.manifest.name)
    assert sockets.written() == [
        f"messy/_manifest/{stage.manifest.name}",
        "messy/part-00000-r7.parquet",
    ]  # the two files, and no temporary file


@pytest.mark.parametrize("path", PATHS)
def test_the_manifest_tells_the_truth_about_the_file(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str
) -> None:
    result = run(nodes.messy(), sockets, path, run_id="r7")
    manifest = the_manifest(result)
    (entry,) = manifest.files
    file = result.stages[0].files[0]
    content = file.path.read_bytes()
    assert entry.sha256 == file.sha256 == hashlib.sha256(content).hexdigest()
    assert entry.bytes == file.bytes == len(content)
    assert entry.rows == pq.read_metadata(file.path).num_rows == result.stages[0].rows_per_node["write"]
    assert entry.compression == "zstd"
    assert pq.read_metadata(file.path).row_group(0).column(0).compression == "ZSTD"
    assert (file.path.parent / entry.path).exists()  # `path` is relative to the dataset folder
    assert (manifest.dataset, manifest.run_id, manifest.pipeline) == ("messy", "r7", "test")
    assert manifest.totals.rows == entry.rows
    assert manifest.totals.bytes == entry.bytes
    assert manifest.lineage.inputs == ["socket://local-inbox/*.csv"]
    assert manifest.lineage.operators == [
        "transform.filter",
        "transform.trim",
        "transform.parse_dates",
        "transform.cast",
        "transform.derive",
        "transform.select",
    ]
    assert manifest.classification == {}
    assert abs((datetime.now(UTC) - manifest.committed_at).total_seconds()) < 60


# --- reading CSV: the two readers must agree ----------------------------------------------------------------

READER_CASES: dict[str, tuple[bytes, list[tuple[str | None, str | None]]]] = {
    "an empty field is null, a quoted one is an empty string": (
        b'a,b\n1,""\n2,\n3," "\n',
        [("1", ""), ("2", None), ("3", " ")],
    ),
    "NA and NULL are text": (b"a,b\n1,NA\n2,NULL\n3,null\n", [("1", "NA"), ("2", "NULL"), ("3", "null")]),
    "CRLF line ends": (b"a,b\r\n1,x\r\n2,y\r\n", [("1", "x"), ("2", "y")]),
    "a byte order mark": (b"\xef\xbb\xbfa,b\n1,x\n", [("1", "x")]),
    "no newline at the end": (b"a,b\n1,x\n2,y", [("1", "x"), ("2", "y")]),
    "a line break, quotes and a comma inside quotes": (
        b'a,b\n1,"l1\nl2"\n2,"say ""hi"", ok"\n',
        [("1", "l1\nl2"), ("2", 'say "hi", ok')],
    ),
    "accents and other scripts": ("a,b\n1,héllo\n2,日本語\n".encode(), [("1", "héllo"), ("2", "日本語")]),
    "leading zeros and whitespace are kept": (b"a,b\n1,007\n2,  x  \n", [("1", "007"), ("2", "  x  ")]),
    "only a header": (b"a,b\n", []),
}


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("case", READER_CASES)
def test_the_readers_agree_on_what_a_csv_file_holds(
    nodes: Any, data: Any, sockets: Any, path: str, case: str
) -> None:
    content, expected = READER_CASES[case]
    (sockets.inbox / "x.csv").write_bytes(content)
    result = run(nodes.copy(), sockets, path)
    written = data.dataset(result.stages[0])
    assert written.columns == ["a", "b"]
    assert list(written.iter_rows()) == expected
    assert result.stages[0].rows_per_node == {"read": len(expected), "write": len(expected)}


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("key", ["has_header", "header"])
def test_a_delimiter_and_a_file_without_a_header(
    nodes: Any, data: Any, sockets: Any, path: str, key: str
) -> None:
    (sockets.inbox / "x.csv").write_bytes(b"1;a,b\n2;c\td\n")
    semicolon = run(nodes.copy(delimiter=";", **{key: False}), sockets, path)
    written = data.dataset(semicolon.stages[0])
    assert written.columns == ["column_1", "column_2"]
    assert list(written.iter_rows()) == [("1", "a,b"), ("2", "c\td")]


@pytest.mark.parametrize("path", PATHS)
def test_a_tab_separated_file_with_a_header(nodes: Any, data: Any, sockets: Any, path: str) -> None:
    (sockets.inbox / "x.csv").write_bytes(b"a\tb\n1\t2\n")
    written = data.dataset(run(nodes.copy(delimiter="\t"), sockets, path).stages[0])
    assert list(written.iter_rows()) == [("1", "2")]


@pytest.mark.parametrize("path", PATHS)
def test_files_are_read_in_name_order(nodes: Any, data: Any, sockets: Any, path: str) -> None:
    (sockets.inbox / "b.csv").write_bytes(b"a,b\n3,4\n")
    (sockets.inbox / "a.csv").write_bytes(b"a,b\n1,2\n")
    (sockets.inbox / "ignored.txt").write_bytes(b"x")
    written = data.dataset(run(nodes.copy(), sockets, path).stages[0])
    assert list(written.iter_rows()) == [("1", "2"), ("3", "4")]


# Two files, and the config of the source: the second file has other columns than the first.
OTHER_COLUMNS: dict[str, tuple[bytes, bytes, dict[str, Any]]] = {
    "another name": (b"a,b\n1,2\n", b"a,z\n3,4\n", {}),
    "another order": (b"a,b\n1,2\n", b"b,a\n3,4\n", {}),
    "fewer columns": (b"a,b\n1,2\n", b"a\n3\n", {}),
    "more columns": (b"a,b\n1,2\n", b"a,b,c\n3,4,5\n", {}),
    "no header and another number of columns": (b"1,2\n", b"3,4,5\n", {"has_header": False}),
}


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("case", OTHER_COLUMNS)
def test_a_file_with_other_columns_than_the_first_is_refused_before_anything_is_written(
    nodes: Any, sockets: Any, path: str, case: str
) -> None:
    first, second, config = OTHER_COLUMNS[case]
    (sockets.inbox / "a.csv").write_bytes(first)
    (sockets.inbox / "b.csv").write_bytes(second)
    # The same message from both paths: the check is part of planning the stage, not of reading the data.
    with pytest.raises(ConfigError, match=r"read \(source\.csv\): 'b\.csv' has other columns than 'a\.csv'"):
        run(nodes.copy(**config), sockets, path)
    assert list(sockets.outbox.iterdir()) == []  # nothing was written, and no folder was made
    assert reader_threads() == []


@pytest.mark.parametrize("path", PATHS)
def test_the_check_of_the_columns_is_made_before_the_first_stage_writes(
    nodes: Any, sockets: Any, path: str
) -> None:
    (sockets.inbox / "a.csv").write_bytes(b"a,b\n1,2\n")
    (sockets.inbox / "b.csv").write_bytes(b"a,z\n3,4\n")
    with pytest.raises(ConfigError, match="has other columns"):
        run(two_stages(nodes), sockets, path)
    assert list(sockets.outbox.iterdir()) == []


@pytest.mark.parametrize("path", PATHS)
def test_the_message_about_other_columns_does_not_show_a_column(nodes: Any, sockets: Any, path: str) -> None:
    # A file without a header has a row of data where the names are: the names may be data.
    (sockets.inbox / "a.csv").write_bytes(b"ID,CANARY-7f3a9c2e\n1,2\n")
    (sockets.inbox / "b.csv").write_bytes(b"ID,other\n3,4\n")
    with pytest.raises(ConfigError) as refused:
        run(nodes.copy(), sockets, path)
    assert "CANARY" not in str(refused.value)


@pytest.mark.parametrize("path", PATHS)
def test_an_empty_file_is_refused_by_name(nodes: Any, sockets: Any, path: str) -> None:
    (sockets.inbox / "a.csv").write_bytes(b"a,b\n1,2\n")
    (sockets.inbox / "b.csv").write_bytes(b"")
    with pytest.raises(ConfigError, match=r"read \(source\.csv\): 'b\.csv' is empty"):
        run(nodes.copy(), sockets, path)
    assert list(sockets.outbox.iterdir()) == []


# --- where the two readers differ, as the note in operators.py says -----------------------------------------
# Polars reads a CSV on the fused path and PyArrow on the batch one. These pin what each does with a row that
# is not as long as the header, and with a blank line. If a new version of either library changes one, this
# is where it shows, and the note in operators.py is the thing to change with it.


def test_a_row_with_too_few_fields_is_padded_by_polars_and_refused_by_pyarrow(
    nodes: Any, data: Any, sockets: Any
) -> None:
    (sockets.inbox / "x.csv").write_bytes(b"a,b,c\n1,2\n3,4,5\n")
    fused = run(nodes.copy(), sockets, "fused", run_id="r1")
    assert list(data.dataset(fused.stages[0]).iter_rows()) == [("1", "2", None), ("3", "4", "5")]
    with pytest.raises(pa.ArrowInvalid):
        run(nodes.copy(), sockets, "batch", run_id="r2")
    assert all("r1" in name for name in sockets.written())  # the refused run left nothing
    assert reader_threads() == []


def test_a_blank_line_is_a_row_of_nulls_for_polars_and_skipped_by_pyarrow(
    nodes: Any, data: Any, sockets: Any
) -> None:
    (sockets.inbox / "x.csv").write_bytes(b"a,b\n1,2\n\n3,4\n")
    rows = {
        path: list(data.dataset(run(nodes.copy(), sockets, path, run_id=f"r-{path}").stages[0]).iter_rows())
        for path in PATHS
    }
    assert rows["fused"] == [("1", "2"), (None, None), ("3", "4")]
    assert rows["batch"] == [("1", "2"), ("3", "4")]


@pytest.mark.parametrize("path", PATHS)
def test_a_row_with_too_many_fields_is_refused_by_both(nodes: Any, sockets: Any, path: str) -> None:
    (sockets.inbox / "x.csv").write_bytes(b"a,b\n1,2,3\n")
    with pytest.raises((pl.exceptions.PolarsError, pa.ArrowInvalid)):
        run(nodes.copy(), sockets, path)
    assert sockets.written() == []
    assert reader_threads() == []


# --- empty results ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", PATHS)
def test_a_file_with_only_a_header_gives_an_empty_dataset_with_the_columns(
    nodes: Any, data: Any, sockets: Any, path: str
) -> None:
    data.write_csv(sockets.inbox / "x.csv", [])
    result = run(nodes.messy(), sockets, path)
    (stage,) = result.stages
    assert set(stage.rows_per_node.values()) == {0}
    written = data.dataset(stage)
    assert written.height == 0
    assert written.columns == ["id", "name", "city_upper", "amount", "signup"]
    assert written.schema["signup"] == UTC_DATETIME
    assert the_manifest(result).totals.rows == 0


@pytest.mark.parametrize("path", PATHS)
def test_a_filter_that_drops_everything_gives_an_empty_dataset(
    nodes: Any, data: Any, sockets: Any, messy_inbox: Any, path: str
) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("none", "transform.filter", "read", expr="id = 'there is no such id'"),
        nodes.write("write", "none"),
    )
    (stage,) = run(p, sockets, path).stages
    assert stage.rows_per_node == {"read": 3000, "none": 0, "write": 0}
    assert data.dataset(stage).columns == data.header


# --- the second stage reads what the first committed --------------------------------------------------------


def two_stages(nodes: Any) -> Any:
    return nodes.pipeline(
        nodes.read(),
        nodes.write("raw", "read", path="raw/dt={yyyy}-{MM}-{dd}/"),
        nodes.step("has_amount", "transform.filter", "raw", expr="amount IS NOT NULL"),
        nodes.step("tidy", "transform.trim", "has_amount", columns=["name"]),
        nodes.write("clean", "tidy", path="clean/"),
    )


@pytest.mark.parametrize("path", PATHS)
def test_a_stage_after_a_sink_reads_the_files_the_sink_committed(
    nodes: Any, data: Any, sockets: Any, messy_inbox: list[list[str]], path: str
) -> None:
    result = run(two_stages(nodes), sockets, path, run_id="r1")
    raw, clean = result.stages
    with_amount = [row for row in messy_inbox if row[3] != ""]
    assert raw.rows_per_node == {"read": 3000, "raw": 3000}
    assert clean.rows_per_node == {
        "has_amount": len(with_amount),
        "tidy": len(with_amount),
        "clean": len(with_amount),
    }
    assert [s.path for s in result.stages] == [path, path]
    written = data.dataset(clean)
    assert written.columns == data.header  # no column `dt` from the folder the raw file is in
    assert written["name"].to_list() == [row[1].strip() or None for row in with_amount]
    assert raw.files[0].path.parent.name.startswith("dt=")
    assert the_manifest(result, 1).lineage.inputs == ["socket://local-outbox/raw"]
    assert the_manifest(result, 1).lineage.operators == ["transform.filter", "transform.trim"]
    assert the_manifest(result, 0).dataset == "raw"
    assert the_manifest(result, 1).dataset == "clean"


def test_both_paths_give_the_same_second_stage(
    nodes: Any, data: Any, tmp_path: Path, sockets: Any, messy_inbox: Any
) -> None:
    results = {}
    for path in PATHS:
        outbox = tmp_path / f"out-{path}"
        outbox.mkdir()
        results[path] = run_pipeline_local(
            two_stages(nodes),
            {"inbox": sockets.inbox, "outbox": outbox},
            force_path=path,  # type: ignore[arg-type]
        )
    fused, batched = (results[path].stages[1] for path in PATHS)
    assert data.dataset(fused).equals(data.dataset(batched))
    assert fused.rows_per_node == batched.rows_per_node


# --- a run that fails leaves nothing ------------------------------------------------------------------------


def failing_pipeline(nodes: Any) -> Any:
    # A strict cast of text to a number: it fails on the first name, and Polars' message would quote it.
    return nodes.pipeline(
        nodes.read(),
        nodes.step("boom", "transform.derive", "read", name="n", expr="CAST(name AS INT)"),
        nodes.write("write", "boom"),
    )


def reader_threads() -> list[threading.Thread]:
    return [thread for thread in threading.enumerate() if thread.name == "safetwin-reader"]


@pytest.mark.parametrize("path", PATHS)
def test_an_error_while_the_data_is_written_leaves_no_file_no_temporary_file_and_no_manifest(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str
) -> None:
    with pytest.raises(pl.exceptions.PolarsError):
        run(failing_pipeline(nodes), sockets, path)
    assert sockets.written() == []
    assert not (sockets.outbox / "data" / "_manifest").exists()
    assert reader_threads() == []


@pytest.mark.parametrize("path", PATHS)
def test_a_failing_commit_leaves_nothing_either(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(self: CommitWriter) -> Any:
        self.abort()
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(CommitWriter, "commit", fail)
    with pytest.raises(OSError, match="No space left"):
        run(nodes.messy(), sockets, path)
    assert sockets.written() == []


@pytest.mark.parametrize("path", PATHS)
def test_a_run_whose_id_was_used_is_refused_and_the_first_run_is_not_touched(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str
) -> None:
    first = run(nodes.messy(), sockets, path, run_id="r1")
    before = {name: (sockets.outbox / name).read_bytes() for name in sockets.written()}
    with pytest.raises(FileExistsError):
        run(nodes.messy(), sockets, path, run_id="r1")
    assert {name: (sockets.outbox / name).read_bytes() for name in sockets.written()} == before
    assert first.stages[0].manifest.exists()
    assert reader_threads() == []


@pytest.mark.parametrize("path", PATHS)
def test_the_manifest_is_written_after_the_data_is_committed(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[list[str]] = []
    real = runtime.write_manifest

    def spy(dataset_dir: Path, manifest: Manifest) -> Path:
        seen.append(sorted(p.name for p in dataset_dir.iterdir()))  # what is in the folder when it is written
        return real(dataset_dir, manifest)

    monkeypatch.setattr(runtime, "write_manifest", spy)
    run(nodes.messy(), sockets, path, run_id="r1")
    assert seen == [["part-00000-r1.parquet"]]  # the data file, committed; no temporary file, no manifest yet


@pytest.mark.parametrize("path", PATHS)
def test_if_the_manifest_cannot_be_written_the_data_file_is_removed_again(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(dataset_dir: Path, manifest: Manifest) -> Path:
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(runtime, "write_manifest", fail)
    with pytest.raises(OSError, match="Input/output error"):
        run(nodes.messy(), sockets, path)
    assert sockets.written() == []  # no manifest lists the file, so it is not left where a reader looks


@pytest.mark.parametrize("path", PATHS)
def test_rows_that_were_counted_but_not_written_are_an_error_and_nothing_stays(
    nodes: Any, sockets: Any, messy_inbox: Any, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Short:
        num_rows = 1  # the footer of the file says one row

    monkeypatch.setattr(runtime.pq, "read_metadata", lambda file: Short())
    with pytest.raises(RuntimeError, match=r"1 rows were written but \d+ reached the sink"):
        run(nodes.messy(), sockets, path)
    assert sockets.written() == []


# --- the batch path, bounded --------------------------------------------------------------------------------


def test_the_batch_path_cuts_its_input_into_small_batches_and_writes_row_groups_of_a_set_size(
    nodes: Any, data: Any, sockets: Any, messy_inbox: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(batch, "BATCH_ROWS", 250)  # 12 or more batches...
    monkeypatch.setattr(batch, "QUEUE_BATCHES", 2)  # ...through a queue that holds 2
    monkeypatch.setattr(batch, "ROW_GROUP_ROWS", 1000)
    result = run(nodes.messy(), sockets, "batch")
    kept = len(expected_of(messy_inbox)["id"])
    file = pq.ParquetFile(result.stages[0].files[0].path)
    groups = [file.metadata.row_group(i).num_rows for i in range(file.metadata.num_row_groups)]
    assert groups == [1000] * (kept // 1000) + [kept % 1000]
    monkeypatch.undo()
    assert data.dataset(result.stages[0]).equals(data.dataset(run(nodes.messy(), sockets, "fused").stages[0]))


def test_a_consumer_that_fails_does_not_leave_the_reader_blocked(
    nodes: Any, sockets: Any, messy_inbox: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(batch, "BATCH_ROWS", 100)  # 30 or more batches, and the queue holds 2:
    monkeypatch.setattr(batch, "QUEUE_BATCHES", 2)  # the reader is blocked in `put` when the consumer fails
    outcome: list[BaseException] = []

    def go() -> None:
        try:
            run(failing_pipeline(nodes), sockets, "batch")
        except BaseException as err:
            outcome.append(err)

    thread = threading.Thread(target=go)
    thread.start()
    thread.join(timeout=60)
    assert not thread.is_alive(), "the run did not end: the reader is still blocked"
    assert [type(err).__name__ for err in outcome] == ["InvalidOperationError"]
    assert reader_threads() == []
    assert sockets.written() == []
