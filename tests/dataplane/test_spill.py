"""The DuckDB connection of a stage: its settings, its lock, and the sizes around it.

That it writes no temporary file anywhere, even when a step needs more memory than it has, is tested in
`test_spill_none.py`; that it installs and downloads nothing, in `test_spill_extensions.py`.
"""

import os
import sys
import traceback
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import duckdb
import psutil
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from safetwin.dataplane import spill
from safetwin.dataplane.spill import (
    DUCKDB_SHARE,
    MIN_BYTES_PER_THREAD,
    SpillError,
    SpillSettings,
    close_duckdb,
    default_extension_dir,
    default_memory_limit,
    duckdb_session,
    duckdb_threads,
    format_size,
    open_duckdb,
    out_of_memory,
    parse_size,
    safetwin_home,
)

MB400 = 400 * 1024 * 1024


@pytest.fixture
def duck() -> Iterator[duckdb.DuckDBPyConnection]:
    """A connection as a stage gets it."""
    with duckdb_session(SpillSettings(MB400)) as connection:
        yield connection


def setting(connection: duckdb.DuckDBPyConnection, name: str) -> Any:
    return connection.execute(f"SELECT current_setting('{name}')").fetchone()[0]  # type: ignore[index]


# --- the settings -------------------------------------------------------------------------------------------


def test_the_settings_are_a_memory_limit_and_nothing_else() -> None:
    assert SpillSettings(5).memory_limit_bytes == 5
    assert not hasattr(SpillSettings, "from_spec")  # there is no spill policy to read: DuckDB never spills
    with pytest.raises(AttributeError):
        SpillSettings(5).memory_limit_bytes = 6  # type: ignore[misc]


@pytest.mark.parametrize("limit", [0, -1, -MB400])
def test_a_memory_limit_must_be_at_least_one_byte(limit: int) -> None:
    with pytest.raises(ValueError, match="at least one byte"):
        SpillSettings(limit)


def test_the_message_about_too_little_memory_says_what_to_do() -> None:
    message = str(
        out_of_memory(SpillSettings(60_000_000), "the DuckDB steps of this stage (s (transform.sort))")
    )
    assert message == (
        "the DuckDB steps of this stage (s (transform.sort)) ran out of memory (the limit is 60 MB), and "
        "DuckDB does not spill to disk. Raise the memory limit (--memory-limit), or add a filter before it "
        "or select fewer columns so that less data reaches it."
    )
    assert isinstance(out_of_memory(SpillSettings(1), "x"), SpillError)


# --- memory and threads -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("memory", "cpus", "threads"),
    [
        (150 * 1024 * 1024, 4, 1),  # 150 MB with 4 threads failed with out-of-memory (docs/internals.md)
        (MB400, 10, 2),
        (400_000_000, 10, 2),
        (399_999_999, 10, 1),
        (1_000_000_000, 10, 5),
        (2_000_000_000, 4, 4),  # no more threads than cores
        (64 * 1000**3, 10, 10),
        (1, 10, 1),  # never less than one
        (MIN_BYTES_PER_THREAD - 1, 10, 1),
    ],
)
def test_duckdb_gets_a_thread_for_every_200_mb_but_at_least_one_and_at_most_the_cores(
    memory: int, cpus: int, threads: int
) -> None:
    assert MIN_BYTES_PER_THREAD == 200_000_000
    assert duckdb_threads(memory, cpus) == threads


@pytest.mark.parametrize("memory", [200_000_000, 313_000_000, 400_000_000, 777_000_000, 5 * 1000**3])
def test_every_thread_has_at_least_200_mb_unless_there_is_one_thread(memory: int) -> None:
    threads = duckdb_threads(memory, cpus=64)
    assert memory // threads >= MIN_BYTES_PER_THREAD


def test_the_cores_of_this_machine_are_the_default_cap() -> None:
    assert duckdb_threads(1000**4) == (os.cpu_count() or 1)
    assert duckdb_threads(1000**4, cpus=0) == (os.cpu_count() or 1)  # 0 cores can't be: fall back


def test_duckdb_gets_80_percent_of_the_share_of_the_stage() -> None:
    assert DUCKDB_SHARE == 0.8
    assert SpillSettings(500_000_000).duckdb_memory_bytes == 400_000_000
    assert SpillSettings(60_000_000).duckdb_memory_bytes == 48_000_000
    assert SpillSettings(1).duckdb_memory_bytes == 1  # never 0


def test_an_open_connection_has_the_thread_count_and_the_memory_of_its_settings() -> None:
    reference = duckdb.connect()
    reference.execute("SET memory_limit = '400000000B'")
    with duckdb_session(SpillSettings(500_000_000)) as connection:  # DuckDB gets 400 MB of the 500
        assert setting(connection, "threads") == min(2, os.cpu_count() or 1)
        assert setting(connection, "memory_limit") == setting(reference, "memory_limit")
    with duckdb_session(SpillSettings(150 * 1024 * 1024)) as connection:
        assert setting(connection, "threads") == 1
        assert setting(connection, "memory_limit") != setting(reference, "memory_limit")


# --- the connection -----------------------------------------------------------------------------------------


def test_the_connection_has_no_folder_to_spill_to_and_no_room_in_one(duck: duckdb.DuckDBPyConnection) -> None:
    assert setting(duck, "temp_directory") == ""  # DuckDB would use ./.tmp if this were not set
    assert setting(duck, "max_temp_directory_size") == "0 bytes"
    assert duck.execute("SELECT current_database()").fetchone() == ("memory",)  # no database file either
    assert duck.execute("SELECT count(*) FROM duckdb_databases() WHERE NOT internal").fetchone() == (1,)


def test_the_module_of_duckdb_that_is_not_secure_is_never_switched_on(
    duck: duckdb.DuckDBPyConnection,
) -> None:
    # GHSA-vmp8-hg63-v2hp: its IVs give away the key of the temporary files. Nothing is encrypted, either.
    assert setting(duck, "force_mbedtls_unsafe") is False
    assert setting(duck, "temp_file_encryption") is False
    cursor = duck.cursor()
    assert setting(cursor, "force_mbedtls_unsafe") is False
    with pytest.raises(duckdb.InvalidInputException, match="configuration has been locked"):
        cursor.execute("SET force_mbedtls_unsafe = true")
    cursor.close()


def test_extensions_are_not_installed_or_loaded_by_themselves_and_timestamps_are_in_utc(
    duck: duckdb.DuckDBPyConnection, safetwin_home: Path
) -> None:
    assert setting(duck, "autoinstall_known_extensions") is False
    assert setting(duck, "autoload_known_extensions") is False
    assert setting(duck, "allow_unsigned_extensions") is False  # DuckDB checks what it loads
    assert setting(duck, "allow_community_extensions") is False
    assert setting(duck, "extension_directory") == str(safetwin_home / "duckdb_extensions")  # not ~/.duckdb
    assert setting(duck, "TimeZone") == "UTC"
    # a column of timestamps with a time zone comes out in UTC, not in the zone of this machine
    result = duck.execute("SELECT TIMESTAMPTZ '2026-01-05 10:00:00+05:30' AS t").to_arrow_reader()
    assert str(result.read_all().schema.field("t").type) == "timestamp[us, tz=UTC]"


def test_a_cursor_shares_the_settings_and_the_memory(duck: duckdb.DuckDBPyConnection) -> None:
    cursor = duck.cursor()
    assert setting(cursor, "temp_directory") == ""
    assert setting(cursor, "memory_limit") == setting(duck, "memory_limit")
    assert setting(cursor, "enable_external_access") is False
    assert setting(cursor, "TimeZone") == "UTC"  # a setting of each session: this one is made for all of them
    result = cursor.execute("SELECT TIMESTAMPTZ '2026-01-05 10:00:00+05:30' AS t").to_arrow_reader()
    assert str(result.read_all().schema.field("t").type) == "timestamp[us, tz=UTC]"
    with pytest.raises(duckdb.InvalidInputException, match="configuration has been locked"):
        cursor.execute("SET temp_directory = '/tmp'")
    cursor.close()


# --- what SQL can't do --------------------------------------------------------------------------------------

FILE_ACCESS = {
    "read a CSV file": "SELECT * FROM read_csv('{canary}')",
    "read a CSV file without the function": "SELECT * FROM '{canary}'",
    "read a file as text": "SELECT * FROM read_text('{canary}')",
    "read a file as bytes": "SELECT * FROM read_blob('{canary}')",
    "read a Parquet file": "SELECT * FROM read_parquet('{canary}')",
    "list the files of a folder": "SELECT * FROM glob('{outside}/*')",
    "COPY TO a file": "COPY (SELECT 'CANARY-7f3a9c' AS a) TO '{outside}/out.csv'",
    "COPY TO the current folder": "COPY (SELECT 'CANARY-7f3a9c' AS a) TO 'out.csv'",
    "COPY FROM a file": "CREATE TEMP TABLE t(a VARCHAR, b INT); COPY t FROM '{canary}'",
    "ATTACH a file": "ATTACH '{outside}/other.duckdb' AS other",
    "EXPORT DATABASE": "EXPORT DATABASE '{outside}/export'",
    "read a URL": "SELECT * FROM read_csv('http://127.0.0.1:9/x.csv')",
    "read from S3": "SELECT * FROM read_csv('s3://bucket/x.csv')",
    "INSTALL an extension": "INSTALL json",
    "INSTALL httpfs": "INSTALL httpfs",
    "INSTALL a community extension": "INSTALL quack FROM community",
    "LOAD an extension file": "LOAD '{outside}/evil.duckdb_extension'",
    "LOAD an extension that is not built in": "LOAD httpfs",
}


@pytest.fixture
def outside(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A folder with a file in it that holds the canary. It is the current folder too."""
    folder = tmp_path / "outside"
    folder.mkdir()
    (folder / "canary.csv").write_text("a,b\nCANARY-7f3a9c-in-a-file,1\n", encoding="utf-8")
    monkeypatch.chdir(folder)
    return folder


@pytest.mark.parametrize("sql", FILE_ACCESS.values(), ids=FILE_ACCESS.keys())
def test_sql_can_not_read_or_write_a_file_attach_or_install(
    duck: duckdb.DuckDBPyConnection, outside: Path, sql: str
) -> None:
    with pytest.raises(duckdb.PermissionException) as refused:
        duck.execute(sql.format(outside=outside, canary=outside / "canary.csv"))
    assert "CANARY-7f3a9c" not in str(refused.value)  # whatever it says about the refusal is not the data
    assert sorted(path.name for path in outside.iterdir()) == ["canary.csv"]  # and nothing was made there


SETTINGS = [
    "SET enable_external_access = true",
    "SET lock_configuration = false",
    "SET temp_directory = '{outside}'",
    "SET max_temp_directory_size = '10GB'",
    "RESET temp_directory",
    "SET temp_file_encryption = true",
    "SET force_mbedtls_unsafe = true",
    "SET memory_limit = '10GB'",
    "SET threads = 64",
    "PRAGMA threads = 64",
    "RESET memory_limit",
    "SET autoinstall_known_extensions = true",
    "SET autoload_known_extensions = true",
    "SET extension_directory = '{outside}'",
    "SET allowed_directories = ['{outside}']",
    "SET TimeZone = 'Europe/Berlin'",
]


@pytest.mark.parametrize("sql", SETTINGS)
def test_sql_can_not_change_a_setting(duck: duckdb.DuckDBPyConnection, outside: Path, sql: str) -> None:
    names = ("memory_limit", "threads", "temp_directory", "max_temp_directory_size", "force_mbedtls_unsafe")
    before = [setting(duck, name) for name in names]
    with pytest.raises(duckdb.InvalidInputException, match="the configuration has been locked"):
        duck.execute(sql.format(outside=outside))
    assert [setting(duck, name) for name in names] == before
    assert setting(duck, "enable_external_access") is False


LOCKED_OUT = {
    "read_text of a file that exists": "SELECT * FROM read_text('{folder}/canary.csv')",
    "read_blob of a file that exists": "SELECT * FROM read_blob('{folder}/canary.csv')",
    "glob of the current folder": "SELECT * FROM glob('*')",
    "read_csv of a file that exists": "SELECT * FROM read_csv('{folder}/canary.csv')",
    "read_parquet of a file that exists": "SELECT * FROM read_parquet('{folder}/canary.parquet')",
    "COPY TO a file": "COPY (SELECT 'CANARY-7f3a9c' AS a) TO '{folder}/copied.csv'",
    "ATTACH a database file": "ATTACH '{folder}/other.duckdb' AS other",
    "INSTALL": "INSTALL json",
    "LOAD of an extension that is not built in": "LOAD httpfs",
}


@pytest.fixture
def files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The current folder, with a CSV file and a Parquet file in it that hold the canary."""
    folder = tmp_path / "files"
    folder.mkdir()
    (folder / "canary.csv").write_text("a,b\nCANARY-7f3a9c-in-a-file,1\n", encoding="utf-8")
    pq.write_table(pa.table({"a": ["CANARY-7f3a9c-in-a-file"]}), folder / "canary.parquet")
    monkeypatch.chdir(folder)
    return folder


def connection_or_cursor(duck: duckdb.DuckDBPyConnection, which: str) -> duckdb.DuckDBPyConnection:
    return duck if which == "connection" else duck.cursor()


@pytest.mark.parametrize("which", ["connection", "cursor"])
@pytest.mark.parametrize("sql", LOCKED_OUT.values(), ids=LOCKED_OUT.keys())
def test_the_locked_connection_and_its_cursors_refuse_files_attach_install_and_load(
    duck: duckdb.DuckDBPyConnection, files: Path, which: str, sql: str
) -> None:
    session = connection_or_cursor(duck, which)
    with pytest.raises(duckdb.PermissionException) as refused:
        session.execute(sql.format(folder=files))
    assert "CANARY-7f3a9c" not in str(refused.value)
    assert sorted(path.name for path in files.iterdir()) == ["canary.csv", "canary.parquet"]


@pytest.mark.parametrize("which", ["connection", "cursor"])
def test_the_locked_connection_and_its_cursors_refuse_to_set_any_setting(
    duck: duckdb.DuckDBPyConnection, which: str
) -> None:
    session = connection_or_cursor(duck, which)
    names = [row[0] for row in session.execute("SELECT name FROM duckdb_settings()").fetchall()]
    assert len(names) > 100
    changed, refused = [], []
    for name in names:
        for sql in (f'SET "{name}" TO DEFAULT', f'RESET "{name}"'):
            try:
                session.execute(sql)
            except duckdb.InvalidInputException as err:
                refused.append(str(err))
            else:
                changed.append(name)
    assert refused
    assert all("the configuration has been locked" in message for message in refused)
    # Measured with DuckDB 1.5.6: only the default schema and the search path of the session can still be
    # set. They name schemas of the in-memory database and reach no file and no setting of the lock.
    assert sorted(set(changed)) == ["schema", "search_path"]


def test_what_the_lock_still_allows_reaches_no_file(duck: duckdb.DuckDBPyConnection, files: Path) -> None:
    # An extension that is built in is loaded already (a LOAD of it reads no file), and a database in memory
    # is not a file. Pinned so that a new version of DuckDB that changes either shows up here.
    for name in ("json", "parquet", "icu"):
        duck.execute(f"LOAD {name}")
    duck.execute("ATTACH ':memory:' AS scratch")
    assert duck.execute("SELECT count(*) FROM duckdb_databases() WHERE path IS NOT NULL").fetchone() == (0,)
    assert sorted(path.name for path in files.iterdir()) == ["canary.csv", "canary.parquet"]


def test_a_python_variable_is_not_a_table(duck: duckdb.DuckDBPyConnection) -> None:
    secret_table = pa.table({"a": [1, 2, 3]})  # DuckDB finds a name in the frame of the caller, if it may
    assert secret_table.num_rows == 3
    assert duckdb.connect().execute("SELECT count(*) FROM secret_table").fetchone() == (3,)  # so it can
    with pytest.raises(duckdb.CatalogException):
        duck.execute("SELECT * FROM secret_table")


def test_a_stream_can_still_be_registered_and_read(duck: duckdb.DuckDBPyConnection) -> None:
    reader = pa.RecordBatchReader.from_batches(
        pa.schema([("n", pa.int64())]), (pa.record_batch([pa.array([i, i + 1])], names=["n"]) for i in (1, 3))
    )
    duck.register("numbers", reader)
    assert duck.execute("SELECT sum(n) FROM numbers").fetchone() == (10,)


# --- the statements -----------------------------------------------------------------------------------------


class Spy:
    """A connection that passes everything to a real one and keeps the text of the statements."""

    def __init__(self, real: duckdb.DuckDBPyConnection, seen: list[str]) -> None:
        self.real = real
        self.seen = seen

    def execute(self, query: str, parameters: Any = None) -> Any:
        self.seen.append(query)
        return self.real.execute(query, parameters) if parameters is not None else self.real.execute(query)

    def close(self) -> None:
        self.real.close()


def statements_of(monkeypatch: pytest.MonkeyPatch, extensions: Path) -> list[str]:
    seen: list[str] = []
    real = duckdb.connect(":memory:")
    monkeypatch.setattr(spill.duckdb, "connect", lambda *args, **kwargs: Spy(real, seen))
    with duckdb_session(SpillSettings(MB400), extensions):
        pass
    return seen


def test_the_statements_that_set_up_a_connection_in_their_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    extensions = tmp_path / "extensions"
    assert statements_of(monkeypatch, extensions) == [
        # the extensions first, before anything that could make DuckDB look for one
        "SET autoinstall_known_extensions = false",
        "SET autoload_known_extensions = false",
        "SET allow_community_extensions = false",
        f"SET extension_directory = '{extensions}'",
        "SET GLOBAL TimeZone = 'UTC'",
        f"SET memory_limit = '{int(MB400 * 0.8)}B'",  # 80% of the share
        f"SET threads = {duckdb_threads(int(MB400 * 0.8))}",
        "SET temp_directory = ''",
        "SET max_temp_directory_size = '0KB'",
        # and the lock last
        "SET enable_external_access = false",
        "SET lock_configuration = true",
    ]
    assert not extensions.exists()  # the folder is named, not made


def test_a_setup_that_fails_says_what_kind_of_error_and_nothing_more(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken:
        def execute(self, query: str, parameters: Any = None) -> Any:
            if "memory_limit" in query:
                raise duckdb.InvalidInputException("Invalid Input Error: CANARY-7f3a9c in what DuckDB says")
            return self

        def close(self) -> None:
            pass

    monkeypatch.setattr(spill.duckdb, "connect", lambda *args, **kwargs: Broken())
    with pytest.raises(SpillError) as failed:
        open_duckdb(SpillSettings(MB400))
    assert str(failed.value) == "DuckDB could not be set up for this stage (InvalidInputException)"
    assert "CANARY" not in "".join(traceback.format_exception(failed.value))
    assert failed.value.__suppress_context__


def test_closing_twice_raises_nothing_and_the_session_closes_when_the_block_fails() -> None:
    connection = open_duckdb(SpillSettings(MB400))
    close_duckdb(connection)
    close_duckdb(connection)
    opened: list[duckdb.DuckDBPyConnection] = []

    def fail() -> None:
        with duckdb_session(SpillSettings(MB400)) as session:
            opened.append(session)
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        fail()
    with pytest.raises(duckdb.ConnectionException):
        opened[0].execute("SELECT 1")  # the connection is closed


# --- folders, sizes and the default memory ------------------------------------------------------------------


def test_the_folder_of_the_extensions_is_the_one_in_the_environment_or_a_folder_of_the_app(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SAFETWIN_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SAFETWIN_DUCKDB_EXTENSIONS", raising=False)
    assert default_extension_dir() == tmp_path / "home" / "duckdb_extensions"
    monkeypatch.setenv("SAFETWIN_DUCKDB_EXTENSIONS", str(tmp_path / "bundle" / "extensions"))
    assert default_extension_dir() == tmp_path / "bundle" / "extensions"
    monkeypatch.setenv("SAFETWIN_DUCKDB_EXTENSIONS", "~/extensions")
    assert default_extension_dir() == Path.home() / "extensions"
    monkeypatch.setenv("SAFETWIN_DUCKDB_EXTENSIONS", "")  # empty is not set
    assert default_extension_dir() == tmp_path / "home" / "duckdb_extensions"


def test_a_connection_looks_for_extensions_where_it_is_told_to(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SAFETWIN_DUCKDB_EXTENSIONS", str(tmp_path / "from-the-environment"))
    with duckdb_session(SpillSettings(MB400)) as connection:
        assert setting(connection, "extension_directory") == str(tmp_path / "from-the-environment")
    with duckdb_session(SpillSettings(MB400), tmp_path / "given") as connection:
        assert setting(connection, "extension_directory") == str(tmp_path / "given")


@pytest.mark.parametrize(
    ("text", "size"),
    [
        ("512MB", 512_000_000),
        ("2GB", 2_000_000_000),
        ("2gb", 2_000_000_000),
        ("1.5GB", 1_500_000_000),
        ("400MiB", 400 * 1024 * 1024),
        ("2GiB", 2 * 1024**3),
        ("64 KiB", 64 * 1024),
        ("  100MB  ", 100_000_000),
        ("1TB", 10**12),
        ("1 B", 1),
        ("0.5KB", 500),
        ("1500KB", 1_500_000),
    ],
)
def test_sizes_with_a_unit_are_bytes(text: str, size: int) -> None:
    assert parse_size(text) == size


@pytest.mark.parametrize(
    "text",
    ["", "512", "MB", "5 bananas", "-5MB", "0MB", "0B", "1e3MB", "1,5GB", "5iB", "5XB", "2GB!", "1.GB"],
)
def test_a_text_that_is_not_a_size_says_what_to_write(text: str) -> None:
    with pytest.raises(ValueError, match="is not a size") as refused:
        parse_size(text)
    assert "such as 512MB or 2GB" in str(refused.value) or "more than 0 bytes" in str(refused.value)


def test_sizes_are_written_for_messages() -> None:
    assert format_size(400 * 1000**2) == "400 MB"
    assert format_size(2_500_000_000) == "2.5 GB"
    assert format_size(500) == "500 bytes"
    assert format_size(1_000_000) == "1 MB"


def test_the_folder_of_the_app_is_safetwin_home_or_the_place_of_the_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SAFETWIN_HOME", str(tmp_path / "home"))
    assert safetwin_home() == tmp_path / "home"
    monkeypatch.setenv("SAFETWIN_HOME", "~/somewhere")
    assert safetwin_home() == Path.home() / "somewhere"
    monkeypatch.delenv("SAFETWIN_HOME")
    monkeypatch.setenv("HOME", str(tmp_path / "me"))
    monkeypatch.setattr(sys, "platform", "darwin")
    assert safetwin_home() == tmp_path / "me" / "Library" / "Application Support" / "safetwin"
    monkeypatch.setattr(sys, "platform", "linux")
    assert safetwin_home() == tmp_path / "me" / ".local" / "share" / "safetwin"
    monkeypatch.setenv("SAFETWIN_HOME", "")  # empty is not set
    assert safetwin_home() == tmp_path / "me" / ".local" / "share" / "safetwin"


def test_the_default_memory_limit_is_a_quarter_of_the_physical_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert default_memory_limit() == psutil.virtual_memory().total // 4
    monkeypatch.setattr(spill.psutil, "virtual_memory", lambda: SimpleNamespace(total=16 * 1024**3))
    assert default_memory_limit() == 4 * 1024**3
