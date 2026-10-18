"""DuckDB installs and loads no extension, and downloads nothing: the app needs none, and works offline.

DuckDB downloads the extension of a function it does not have (from extensions.duckdb.org, into
`~/.duckdb/extensions`) and loads it, unless it is told not to. It did that for `httpfs` when the first
version of this code asked for an encrypted database. The connection of a stage is told, before anything
else, where its extensions are (a folder of the app, here a folder of the test that has to stay empty) and
that it may not install or load any. These tests run what a stage can run and see that nothing arrives,
neither in that folder nor in the cache of DuckDB.
"""

from pathlib import Path
from typing import Any

import duckdb
import pytest

from safetwin.dataplane.run import run_pipeline_local
from safetwin.dataplane.spill import SpillSettings, duckdb_session

MB400 = 400 * 1024 * 1024


def files_in(folder: Path) -> dict[str, int]:
    """Every file below `folder` with its size, to see that nothing was added. `{}` if it is not there."""
    if not folder.exists():
        return {}
    return {str(path): path.stat().st_size for path in folder.rglob("*") if path.is_file()}


@pytest.fixture
def extensions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty folder that is where the app's DuckDB looks for extensions, as the environment says."""
    folder = tmp_path / "extensions"
    folder.mkdir()
    monkeypatch.setenv("SAFETWIN_DUCKDB_EXTENSIONS", str(folder))
    return folder


@pytest.fixture
def duckdb_cache() -> dict[str, int]:
    """The files in the cache that DuckDB keeps for the user, before the test. It must not grow."""
    return files_in(Path.home() / ".duckdb")


def nothing_arrived(extensions: Path, before: dict[str, int]) -> None:
    assert list(extensions.iterdir()) == []  # nothing was installed where the app's DuckDB looks
    assert files_in(Path.home() / ".duckdb") == before  # and nothing in the cache of DuckDB: no download


def setting(connection: duckdb.DuckDBPyConnection, name: str) -> Any:
    return connection.execute(f"SELECT current_setting('{name}')").fetchone()[0]  # type: ignore[index]


def test_a_connection_is_told_where_the_extensions_are_and_that_it_may_install_and_load_none(
    extensions: Path, duckdb_cache: dict[str, int]
) -> None:
    with duckdb_session(SpillSettings(MB400)) as connection:
        assert setting(connection, "extension_directory") == str(extensions)
        assert setting(connection, "autoinstall_known_extensions") is False
        assert setting(connection, "autoload_known_extensions") is False
        assert setting(connection, "allow_unsigned_extensions") is False  # DuckDB checks what it loads
        assert setting(connection, "allow_community_extensions") is False
    nothing_arrived(extensions, duckdb_cache)


AT_ZONE = "TIMESTAMPTZ '2026-01-05 10:00:00+05:30'"
FEATURES = {
    "a timestamp with a time zone, as Arrow": f"SELECT {AT_ZONE} AS t",
    "converting a time zone": f"SELECT {AT_ZONE} AT TIME ZONE 'Europe/Berlin' AS t",
    "truncating a date in a time zone": f"SELECT date_trunc('day', {AT_ZONE}) AS d",
    "a part of a timestamp with a time zone": f"SELECT extract(hour FROM {AT_ZONE}) AS h",
    "a timestamp as text": "SELECT strftime(TIMESTAMP '2026-01-05 10:00:00', '%Y-%m-%d') AS s",
    "epoch to a timestamp": "SELECT to_timestamp(1767607200) AS t",
    "an interval between dates": "SELECT age(TIMESTAMP '2026-01-05', TIMESTAMP '2025-01-05') AS a",
    "a collation that ignores case": "SELECT 'a' = 'A' COLLATE NOCASE AS same",
    "an ordering by a language": "SELECT s FROM (VALUES ('b'), ('a'), ('\u00e4')) t(s) ORDER BY s COLLATE de",
    "a regular expression": "SELECT regexp_matches('abc123', '[a-z]+[0-9]+') AS m",
    "JSON": "SELECT json_extract('{\"a\": [1, 2]}', '$.a[1]') AS j, '{}'::JSON AS e",
    "a sort that is not binary": "SELECT s FROM (VALUES ('b'), ('A')) t(s) ORDER BY s COLLATE NOCASE, s",
    "lower and upper": "SELECT lower('ABC') AS l, upper('\u00e4') AS u",
}


@pytest.mark.parametrize("sql", FEATURES.values(), ids=FEATURES.keys())
def test_what_sql_does_with_time_zones_collations_json_and_patterns_needs_no_extension(
    extensions: Path, duckdb_cache: dict[str, int], sql: str
) -> None:
    with duckdb_session(SpillSettings(MB400)) as connection:
        assert connection.execute(sql).to_arrow_reader().read_all().num_rows >= 1
    nothing_arrived(extensions, duckdb_cache)


KNOWN_EXTENSIONS = {
    "delta": "SELECT * FROM delta_scan('/nowhere/table')",
    "iceberg": "SELECT * FROM iceberg_scan('/nowhere/table')",
    "postgres": "SELECT * FROM postgres_scan('dbname=x', 'public', 't')",
    "sqlite": "SELECT * FROM sqlite_scan('/nowhere/x.db', 't')",
    "spatial": "SELECT ST_AsText(ST_Point(1, 2))",
    "httpfs": "SELECT * FROM read_csv('https://example.com/x.csv')",
    "S3": "SELECT * FROM read_parquet('s3://bucket/x.parquet')",
    "full text search": "PRAGMA create_fts_index('t', 'id', 'text')",
    "tpch": "CALL dbgen(sf = 0.01)",
}


@pytest.mark.parametrize("sql", KNOWN_EXTENSIONS.values(), ids=KNOWN_EXTENSIONS.keys())
def test_what_duckdb_would_fetch_an_extension_for_is_an_error_and_nothing_is_fetched(
    extensions: Path, duckdb_cache: dict[str, int], sql: str
) -> None:
    with (
        duckdb_session(SpillSettings(MB400)) as connection,
        pytest.raises(duckdb.Error),
    ):
        connection.execute(sql)
    nothing_arrived(extensions, duckdb_cache)


INSTALLING = [
    "INSTALL httpfs",
    "INSTALL icu",
    "INSTALL json",
    "FORCE INSTALL httpfs",
    "INSTALL httpfs FROM 'http://127.0.0.1:9/repo'",
    "INSTALL quack FROM community",
    "LOAD httpfs",
    "LOAD '/nowhere/evil.duckdb_extension'",
]


@pytest.mark.parametrize("sql", INSTALLING)
def test_sql_can_not_install_or_load_an_extension(
    extensions: Path, duckdb_cache: dict[str, int], sql: str
) -> None:
    session = duckdb_session(SpillSettings(MB400))
    with session as connection, pytest.raises(duckdb.PermissionException):
        connection.execute(sql)
    nothing_arrived(extensions, duckdb_cache)


def test_a_pipeline_with_steps_for_duckdb_runs_with_nothing_installed_and_nothing_fetched(
    nodes: Any, data: Any, sockets: Any, extensions: Path, duckdb_cache: dict[str, int]
) -> None:
    rows = [[str(n), f"n{n % 7}", "x", f"{n % 50}.5"] for n in range(1, 2001)]
    data.write_csv(sockets.inbox / "a.csv", rows, header=["id", "name", "city", "amount"])
    sql = (
        "SELECT name, count(*) AS n, strftime(TIMESTAMP '2026-01-05 10:00:00', '%Y') AS year, "
        "lower(upper(name)) AS same FROM input GROUP BY name"
    )
    pipeline = nodes.pipeline(
        nodes.read(),
        nodes.step("totals", "transform.sql", "read", sql=sql),
        nodes.step("ordered", "transform.sort", "totals", by=[{"column": "n", "descending": True}, "name"]),
        nodes.write("write", "ordered"),
    )
    result = run_pipeline_local(pipeline, sockets.folders)
    assert result.stages[0].path == "hybrid"
    assert data.dataset(result.stages[0]).height == 7
    nothing_arrived(extensions, duckdb_cache)
