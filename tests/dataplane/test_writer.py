"""CommitWriter: a file that only gets its name when it is committed."""

import errno
import hashlib
import os
import re
import stat
from array import array
from pathlib import Path
from typing import IO, cast

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from safetwin.dataplane.writer import CommitWriter, FileCommit, remove_temporaries


def names(folder: Path) -> list[str]:
    return sorted(p.name for p in folder.iterdir())


# --- commit ----------------------------------------------------------------------------------------


def test_commit_gives_the_file_its_name_and_reports_its_size_and_sha256(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    writer = CommitWriter(target)
    writer.write(b"hello ")
    writer.write(b"world")
    commit = writer.commit()
    assert commit == FileCommit(target, 11, hashlib.sha256(b"hello world").hexdigest())
    assert target.read_bytes() == b"hello world"
    assert names(tmp_path) == ["out.bin"]  # no temporary file is left


def test_until_the_commit_only_a_hidden_temporary_file_exists(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    with CommitWriter(target) as writer:
        writer.write(b"half a file")
        (temp,) = tmp_path.iterdir()
        assert re.fullmatch(r"\.out\.bin\.tmp-[0-9a-f]{12}", temp.name)
        assert not target.exists()
        assert temp.read_bytes() == b"half a file"
        writer.commit()


def test_the_final_file_has_the_mode_a_file_created_the_usual_way_has(tmp_path: Path) -> None:
    usual = tmp_path / "usual"
    usual.write_bytes(b"x")
    with CommitWriter(tmp_path / "made") as writer:
        writer.write(b"x")
        writer.commit()
    assert stat.S_IMODE((tmp_path / "made").stat().st_mode) == stat.S_IMODE(usual.stat().st_mode)


def test_the_folders_of_the_target_are_created(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "out.bin"
    with CommitWriter(target) as writer:
        writer.write(b"x")
        writer.commit()
    assert target.read_bytes() == b"x"


def test_an_empty_file_can_be_committed(tmp_path: Path) -> None:
    with CommitWriter(tmp_path / "empty") as writer:
        commit = writer.commit()
    assert commit == FileCommit(tmp_path / "empty", 0, hashlib.sha256(b"").hexdigest())


def test_the_file_is_committed_once(tmp_path: Path) -> None:
    writer = CommitWriter(tmp_path / "out")
    writer.commit()
    with pytest.raises(ValueError, match="committed already"):
        writer.commit()
    with pytest.raises(ValueError, match="committed or aborted"):
        writer.write(b"x")
    writer.abort()  # does nothing to a file that is committed
    writer.close()
    assert (tmp_path / "out").exists()


# --- what is written ---------------------------------------------------------------------------------


def test_write_takes_bytes_a_bytearray_and_a_memoryview_and_returns_how_many_bytes(tmp_path: Path) -> None:
    with CommitWriter(tmp_path / "out") as writer:
        assert writer.write(b"ab") == 2
        assert writer.write(bytearray(b"cd")) == 2
        assert writer.write(memoryview(b"efgh")[1:3]) == 2  # "fg"
        assert writer.write(b"") == 0
        commit = writer.commit()
    assert (tmp_path / "out").read_bytes() == b"abcdfg"
    assert commit.bytes == 6
    assert commit.sha256 == hashlib.sha256(b"abcdfg").hexdigest()


def test_the_size_counts_bytes_not_items(tmp_path: Path) -> None:
    items = array("I", [1, 2, 3])  # 3 items of 4 bytes
    with CommitWriter(tmp_path / "out") as writer:
        assert writer.write(items) == 12
        commit = writer.commit()
    assert commit.bytes == 12 == (tmp_path / "out").stat().st_size


def test_the_progress_callback_gets_the_running_number_of_bytes_after_each_write(tmp_path: Path) -> None:
    seen: list[int] = []
    with CommitWriter(tmp_path / "out", on_progress=seen.append) as writer:
        for chunk in (b"123", b"45678", b"90"):
            writer.write(chunk)
        writer.commit()
    assert seen == [3, 8, 10]


def test_a_large_write_goes_in_whole(tmp_path: Path) -> None:
    payload = os.urandom(5_000_000)
    with CommitWriter(tmp_path / "out") as writer:
        writer.write(payload)
        commit = writer.commit()
    assert (tmp_path / "out").read_bytes() == payload
    assert commit.sha256 == hashlib.sha256(payload).hexdigest()


# --- abort and errors ----------------------------------------------------------------------------------


def test_abort_deletes_the_temporary_file_and_nothing_is_published(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    writer = CommitWriter(target)
    writer.write(b"never seen")
    writer.abort()
    assert names(tmp_path) == []
    with pytest.raises(ValueError, match="committed or aborted"):
        writer.write(b"more")
    with pytest.raises(ValueError, match="aborted"):
        writer.commit()
    writer.abort()  # twice is fine


def test_an_exception_in_the_with_block_leaves_no_file_and_no_temporary_file(tmp_path: Path) -> None:
    def write_and_fail() -> None:
        with CommitWriter(tmp_path / "out.bin") as writer:
            writer.write(b"half")
            raise RuntimeError("disk on fire")

    with pytest.raises(RuntimeError, match="disk on fire"):
        write_and_fail()
    assert names(tmp_path) == []


def test_leaving_the_block_without_a_commit_publishes_nothing(tmp_path: Path) -> None:
    with CommitWriter(tmp_path / "out") as writer:
        writer.write(b"x")
    assert names(tmp_path) == []
    assert writer.closed


def test_closing_a_file_that_was_not_committed_throws_it_away(tmp_path: Path) -> None:
    writer = CommitWriter(tmp_path / "out")
    writer.write(b"x")
    writer.close()
    assert names(tmp_path) == []


def test_a_writer_that_is_dropped_without_a_commit_cleans_up_after_itself(tmp_path: Path) -> None:
    writer = CommitWriter(tmp_path / "out")
    writer.write(b"x")
    del writer
    assert names(tmp_path) == []


def test_a_failing_write_aborts_with_the_with_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def full(fd: int, data: object) -> int:
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    def write_to_a_full_disk() -> None:
        with CommitWriter(tmp_path / "out") as writer:
            monkeypatch.setattr(os, "write", full)
            writer.write(b"x")

    with pytest.raises(OSError, match="No space left"):
        write_to_a_full_disk()
    monkeypatch.undo()
    assert names(tmp_path) == []


def test_a_progress_callback_that_fails_fails_the_write(tmp_path: Path) -> None:
    def cancel(total: int) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt), CommitWriter(tmp_path / "out", on_progress=cancel) as writer:
        writer.write(b"x")
    assert names(tmp_path) == []


# --- an existing target -----------------------------------------------------------------------------


def test_an_existing_target_is_refused_and_left_alone(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"precious")
    with pytest.raises(FileExistsError) as refused:
        CommitWriter(target)
    assert refused.value.filename == str(target)
    assert names(tmp_path) == ["out.bin"]  # no temporary file was made either
    assert target.read_bytes() == b"precious"


def test_overwrite_replaces_the_target(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"old")
    with CommitWriter(target, overwrite=True) as writer:
        writer.write(b"new")
        assert target.read_bytes() == b"old"  # until the commit the old file is still there
        writer.commit()
    assert target.read_bytes() == b"new"
    assert names(tmp_path) == ["out.bin"]


def test_a_target_that_turns_up_while_the_file_is_written_is_not_replaced(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    writer = CommitWriter(target)
    writer.write(b"mine")
    target.write_bytes(b"theirs")
    with pytest.raises(FileExistsError):
        writer.commit()
    assert target.read_bytes() == b"theirs"
    assert names(tmp_path) == ["out.bin"]


def test_a_broken_symlink_with_the_name_of_the_target_is_in_the_way(tmp_path: Path) -> None:
    (tmp_path / "out.bin").symlink_to(tmp_path / "nowhere")
    with pytest.raises(FileExistsError):
        CommitWriter(tmp_path / "out.bin")


# --- durability --------------------------------------------------------------------------------------


def test_the_file_is_fsynced_before_the_rename_and_the_folder_after_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out.bin"
    calls: list[tuple[str, bool]] = []
    real_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        kind = "folder" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
        calls.append((kind, target.exists()))  # was the rename done when this fsync was called?
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    with CommitWriter(target) as writer:
        writer.write(b"x")
        writer.commit()
    assert calls == [("file", False), ("folder", True)]


def test_a_folder_that_cannot_be_synced_is_no_reason_to_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "Invalid argument")  # FAT, some network shares
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with CommitWriter(tmp_path / "out") as writer:
        writer.write(b"x")
        assert writer.commit().bytes == 1
    assert (tmp_path / "out").read_bytes() == b"x"


def test_a_failure_to_sync_the_folder_takes_the_name_away_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "Input/output error")
        real_fsync(fd)

    def write_and_commit() -> None:
        with CommitWriter(tmp_path / "out") as writer:
            writer.write(b"x")
            writer.commit()

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OSError, match="Input/output error"):
        write_and_commit()
    assert names(tmp_path) == []  # commit() raised, so nothing is published


@pytest.mark.parametrize("failing", ["fsync", "replace"])
def test_a_failing_commit_publishes_nothing_and_leaves_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    def fail(*args: object) -> None:
        raise OSError(errno.EIO, "Input/output error")

    writer = CommitWriter(tmp_path / "out")
    writer.write(b"x")
    monkeypatch.setattr(os, failing, fail)
    with pytest.raises(OSError, match="Input/output error"):
        writer.commit()
    monkeypatch.undo()
    assert names(tmp_path) == []
    assert writer.closed


# --- the things that write to it -----------------------------------------------------------------------


def test_polars_can_sink_a_query_into_it_and_the_hash_is_that_of_the_file(tmp_path: Path) -> None:
    seen: list[int] = []
    frame = pl.LazyFrame({"a": list(range(200_000)), "b": ["text"] * 200_000})
    with CommitWriter(tmp_path / "out.parquet", on_progress=seen.append) as writer:
        frame.sink_parquet(cast("IO[bytes]", writer), compression="zstd", compression_level=3)
        assert not writer.closed  # Polars does not close what it was given
        commit = writer.commit()
    content = (tmp_path / "out.parquet").read_bytes()
    assert commit.sha256 == hashlib.sha256(content).hexdigest()
    assert commit.bytes == len(content) == seen[-1]
    assert seen == sorted(seen)
    assert pq.read_metadata(commit.path).num_rows == 200_000


def test_pyarrow_can_write_parquet_into_it(tmp_path: Path) -> None:
    table = pa.table({"a": list(range(1000)), "b": ["x"] * 1000})
    with CommitWriter(tmp_path / "out.parquet") as out:
        with pq.ParquetWriter(out, table.schema, compression="zstd") as writer:
            writer.write_table(table)
        assert not out.closed
        commit = out.commit()
    assert commit.sha256 == hashlib.sha256(commit.path.read_bytes()).hexdigest()
    assert pq.read_table(commit.path).equals(table)


def test_a_failing_query_leaves_no_file_behind(tmp_path: Path) -> None:
    frame = pl.LazyFrame({"a": ["1", "x"]}).with_columns(pl.col("a").cast(pl.Int64))  # strict: "x" fails
    with pytest.raises(pl.exceptions.PolarsError), CommitWriter(tmp_path / "out.parquet") as writer:
        frame.sink_parquet(cast("IO[bytes]", writer))
    assert names(tmp_path) == []


def test_remove_temporaries_deletes_only_the_temporary_files_of_the_target_it_is_given(
    tmp_path: Path,
) -> None:
    mine = ["part-00000-r1.parquet", "part-00000-r1.parquet"]
    names = [
        f".{mine[0]}.tmp-0123456789ab",  # deleted
        f".{mine[1]}.tmp-ba9876543210",  # deleted
        ".part-00000-r2.parquet.tmp-0123456789ab",  # another run
        "part-00000-r1.parquet",  # the committed file
        f".{mine[0]}.tmp-0123",  # not the pattern of a writer
        f".{mine[0]}.tmp-0123456789abX",
    ]
    for name in names:
        (tmp_path / name).write_bytes(b"x")
    (tmp_path / f".{mine[0]}.tmp-cccccccccccc").mkdir()  # a folder is not a file
    removed = remove_temporaries(tmp_path, re.escape(mine[0]))
    assert sorted(path.name for path in removed) == sorted(names[:2])
    assert sorted(path.name for path in tmp_path.iterdir()) == sorted(
        [*names[2:], f".{mine[0]}.tmp-cccccccccccc"]
    )
    assert remove_temporaries(tmp_path / "nowhere", "x") == []  # a folder that is not there: nothing


def test_the_temporary_file_of_a_writer_is_found_by_remove_temporaries(tmp_path: Path) -> None:
    target = tmp_path / "out" / "part-00000-r9.parquet"
    writer = CommitWriter(target)
    (temp,) = list(target.parent.iterdir())
    assert remove_temporaries(target.parent, re.escape(target.name)) == [temp]
    writer.abort()
