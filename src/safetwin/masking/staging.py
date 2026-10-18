"""Sources and targets that aren't folders of CSV or Parquet: Postgres (docs/guide.md) and Excel.

The engine reads and writes folders of files. A Postgres or Excel *source* is copied first, table by table,
to Parquet files in a private staging folder (mode 0700, in the system's per-user temporary folder); the run
reads those, and the folder is removed when the run ends, failed or interrupted included (a folder left by
a crash is removed by the next run after a day). A Postgres or Excel *target* gets the twin from such a
folder once every check has passed: into a new schema, in one transaction, with the source's keys, unique
constraints and foreign keys added at the end; or as one workbook per table.

Postgres goes through the ADBC driver straight into Arrow. The source session is read-only, and no message
holds the connection URL: only the host, port and database.
"""

import os
import secrets
import shutil
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq

STAGE_PREFIX = "safetwin-stage-"
STALE_AFTER_S = 24 * 3600
EXCEL_SAFE_INT = 2**53  # Excel stores numbers as doubles: larger integers are written as text


class StagingError(Exception):
    """A source or target can't be read or written. The message names tables and hosts, never a URL or a
    value."""


# --- the staging folder -------------------------------------------------------------------------------------


@contextmanager
def staging_folder() -> Iterator[Path]:
    """A new private folder for staged tables, removed on the way out."""
    _remove_stale()
    folder = Path(tempfile.mkdtemp(prefix=STAGE_PREFIX))
    os.chmod(folder, 0o700)
    try:
        yield folder
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _remove_stale() -> None:
    """Staging folders a crashed run left behind, older than a day (a newer one may belong to a live run)."""
    root = Path(tempfile.gettempdir())
    now = time.time()
    with suppress(OSError):
        for entry in root.iterdir():
            if entry.name.startswith(STAGE_PREFIX) and entry.is_dir() and not entry.is_symlink():
                with suppress(OSError):
                    if entry.stat().st_uid == os.getuid() and now - entry.stat().st_mtime > STALE_AFTER_S:
                        shutil.rmtree(entry, ignore_errors=True)


# --- Postgres -----------------------------------------------------------------------------------------------


def where(url: str) -> str:
    """`host:port/database` of a URL, for messages: never the user, the password or the options."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or "localhost"
        port = f":{parts.port}" if parts.port else ""
        database = parts.path.lstrip("/") or "?"
    except ValueError:
        return "Postgres (the URL can't be read)"
    return f"Postgres at {host}{port}/{database}"


def quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def connect(url: str, *, read_only: bool) -> Any:
    """An ADBC connection. A read-only one can't write in any transaction it starts."""
    import adbc_driver_postgresql.dbapi as pg  # type: ignore[import-untyped]

    try:
        connection = pg.connect(url)
    except Exception as err:  # its message can hold the URL: name the place, not the error text
        raise StagingError(f"cannot connect to {where(url)} ({type(err).__name__})") from None
    if read_only:
        with connection.cursor() as cur:
            cur.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        connection.commit()
    return connection


@dataclass
class PgFacts:
    """What the database says about a schema's tables: no data, only names."""

    tables: list[str] = field(default_factory=list)
    primary_keys: dict[str, list[str]] = field(default_factory=dict)
    unique: dict[str, list[list[str]]] = field(default_factory=dict)
    foreign_keys: list[tuple[str, str, str, str]] = field(default_factory=list)  # single-column ones
    skipped_foreign_keys: int = 0  # foreign keys of several columns, which the policy can't express


def _rows(connection: Any, sql: str, parameters: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
    with connection.cursor() as cur:
        cur.execute(sql, parameters)
        return list(cur.fetchall())


def read_facts(connection: Any, schema: str) -> PgFacts:
    facts = PgFacts()
    facts.tables = [
        r[0]
        for r in _rows(
            connection,
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = $1 AND table_type = 'BASE TABLE' ORDER BY table_name",
            [schema],
        )
    ]
    constraints = _rows(
        connection,
        """
        SELECT con.contype::text, cl.relname::text, fcl.relname::text,
               array_agg(att.attname::text ORDER BY k.ord), array_agg(fatt.attname::text ORDER BY k.ord)
        FROM pg_constraint con
        JOIN pg_class cl ON cl.oid = con.conrelid
        JOIN pg_namespace ns ON ns.oid = cl.relnamespace
        CROSS JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord)
        JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = k.attnum
        LEFT JOIN pg_class fcl ON fcl.oid = con.confrelid
        LEFT JOIN pg_attribute fatt ON fatt.attrelid = con.confrelid AND fatt.attnum = con.confkey[k.ord]
        WHERE ns.nspname = $1 AND con.contype IN ('p', 'u', 'f')
        GROUP BY con.oid, con.contype, cl.relname, fcl.relname
        ORDER BY cl.relname, con.contype
        """,
        [schema],
    )
    for kind, table, target, columns, target_columns in constraints:
        if kind == "p":
            facts.primary_keys[table] = list(columns)
        elif kind == "u":
            facts.unique.setdefault(table, []).append(list(columns))
        elif len(columns) == 1 and target is not None:
            facts.foreign_keys.append((table, columns[0], target, target_columns[0]))
        else:
            facts.skipped_foreign_keys += 1
    return facts


def count_rows(connection: Any, schema: str, table: str) -> int:
    return int(_rows(connection, f"SELECT count(*) FROM {quote(schema)}.{quote(table)}")[0][0])


def _decimals(connection: Any, schema: str, table: str) -> dict[str, tuple[int, int]]:
    """`numeric(p, s)` columns with p <= 38: (precision, scale), so they can come back as decimals."""
    rows = _rows(
        connection,
        "SELECT column_name::text, numeric_precision, numeric_scale FROM information_schema.columns "
        "WHERE table_schema = $1 AND table_name = $2 AND data_type = 'numeric' "
        "AND numeric_precision IS NOT NULL AND numeric_precision <= 38",
        [schema, table],
    )
    return {name: (int(p), int(sc or 0)) for name, p, sc in rows}


def _select(connection: Any, schema: str, table: str) -> tuple[str, dict[str, tuple[int, int]]]:
    """The query of a table: columns whose Arrow type the driver can't give (numeric, json, intervals,
    arrays of those...) are read as text; `numeric(p, s)` is turned back into a decimal afterwards."""
    with connection.cursor() as cur:
        cur.execute(f"SELECT * FROM {quote(schema)}.{quote(table)} LIMIT 0")
        probe = cur.fetch_record_batch().schema
    connection.commit()
    items = [
        f"{quote(f.name)}::text AS {quote(f.name)}" if _as_text(f.type) else quote(f.name) for f in probe
    ]
    return f"SELECT {', '.join(items) or '*'} FROM {quote(schema)}.{quote(table)}", _decimals(
        connection, schema, table
    )


def _as_text(dtype: pa.DataType) -> bool:
    """Whether a column of this Arrow type is read as text: the driver's opaque types (numeric, json, uuid...)
    and the intervals Polars can't hold, also inside lists."""
    if isinstance(dtype, pa.BaseExtensionType) or pa.types.is_interval(dtype):
        return True
    if pa.types.is_list(dtype) or pa.types.is_large_list(dtype):
        return _as_text(dtype.value_type)
    return False


def stage_postgres(
    connection: Any, schema: str, tables: Sequence[str], folder: Path, *, limit: int | None = None
) -> dict[str, int]:
    """Each table copied to `folder/<table>.parquet` (its first `limit` rows when given; `0` copies the
    columns and types only). Returns the rows copied per table."""
    copied: dict[str, int] = {}
    for table in tables:
        rows = 0
        try:
            sql, decimals = _select(connection, schema, table)
            if limit is not None:
                sql += f" LIMIT {int(limit)}"
            with connection.cursor() as cur:
                cur.execute(sql)
                reader = cur.fetch_record_batch()
                writer: pq.ParquetWriter | None = None
                try:
                    for batch in _batches(reader):
                        frame = pl.from_arrow(batch)
                        assert isinstance(frame, pl.DataFrame)
                        frame = frame.with_columns(
                            pl.col(c).cast(pl.Decimal(p, sc))
                            for c, (p, sc) in decimals.items()
                            if c in frame.columns
                        )
                        arrow = frame.to_arrow()
                        if writer is None:
                            writer = pq.ParquetWriter(
                                folder / f"{table}.parquet", arrow.schema, compression="zstd"
                            )
                        writer.write_table(arrow)
                        rows += frame.height
                finally:
                    if writer is not None:
                        writer.close()
            connection.commit()
        except Exception as err:  # driver messages can quote values: name the table only
            with suppress(Exception):
                connection.rollback()
            raise StagingError(f"cannot read the table {schema}.{table} ({type(err).__name__})") from None
        copied[table] = rows
    return copied


def _batches(reader: Any) -> Iterator[pa.RecordBatch]:
    """The batches of a reader, and one empty batch with its columns when it has none."""
    empty = True
    for batch in reader:
        empty = False
        yield batch
    if empty:
        yield pa.RecordBatch.from_pylist([], schema=reader.schema)


def deliver_postgres(
    twin: Path,
    tables: Sequence[str],
    connection: Any,
    schema: str,
    facts: PgFacts | None,
    *,
    replace: bool,
) -> dict[str, int]:
    """Load the twin's tables (`twin/<table>/*.parquet`) into `schema`, in one transaction: create the schema
    if needed, refuse tables that exist unless `replace` (then they're dropped), create and fill the tables,
    then add the source's primary keys, unique constraints and foreign keys between these tables, for the
    columns the twin still has. Returns the rows loaded per table."""
    loaded: dict[str, int] = {}
    with connection.cursor() as cur:
        try:
            cur.execute(f"CREATE SCHEMA IF NOT EXISTS {quote(schema)}")
            existing = {
                r[0]
                for r in _rows(
                    connection,
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = $1",
                    [schema],
                )
            }
            clash = sorted(set(tables) & existing)
            if clash and not replace:
                raise StagingError(
                    f"the schema {schema} already has the table(s) {', '.join(clash)}: give --replace to "
                    "replace them, or choose another schema"
                )
            for table in clash:
                cur.execute(f"DROP TABLE {quote(schema)}.{quote(table)} CASCADE")
            columns: dict[str, list[str]] = {}
            for table in tables:
                files = sorted((twin / table).glob("*.parquet"))
                arrow = pa.concat_tables([pq.read_table(f) for f in files]) if files else pa.table({})
                columns[table] = arrow.column_names
                cur.adbc_ingest(table, arrow, mode="create", db_schema_name=schema)
                loaded[table] = arrow.num_rows
            for statement in _constraints(schema, tables, columns, facts):
                cur.execute(statement)
            connection.commit()
        except StagingError:
            connection.rollback()
            raise
        except Exception as err:  # driver messages can quote values
            with suppress(Exception):
                connection.rollback()
            raise StagingError(
                f"cannot load the twin into the schema {schema} ({type(err).__name__}); nothing was changed"
            ) from None
    return loaded


def _constraints(
    schema: str, tables: Sequence[str], columns: dict[str, list[str]], facts: PgFacts | None
) -> list[str]:
    if facts is None:
        return []
    out = []
    present = set(tables)

    def has(table: str, names: Sequence[str]) -> bool:
        return table in present and all(n in columns.get(table, []) for n in names)

    for table, key in facts.primary_keys.items():
        if has(table, key):
            out.append(
                f"ALTER TABLE {quote(schema)}.{quote(table)} ADD PRIMARY KEY ({', '.join(map(quote, key))})"
            )
    for table, sets in facts.unique.items():
        for names in sets:
            if has(table, names):
                out.append(
                    f"ALTER TABLE {quote(schema)}.{quote(table)} ADD UNIQUE ({', '.join(map(quote, names))})"
                )
    for table, column, target, target_column in facts.foreign_keys:
        if has(table, [column]) and has(target, [target_column]):
            out.append(
                f"ALTER TABLE {quote(schema)}.{quote(table)} ADD FOREIGN KEY ({quote(column)}) "
                f"REFERENCES {quote(schema)}.{quote(target)} ({quote(target_column)})"
            )
    return out


# --- Excel --------------------------------------------------------------------------------------------------


def excel_tables(folder: Path) -> dict[str, tuple[Path, str]]:
    """Table name → (workbook, sheet) of the `.xlsx` files of a folder: a workbook with one sheet is one table
    named after the file; one with several gives `<file>_<sheet>` per sheet."""
    import fastexcel

    from .scan import table_name

    out: dict[str, tuple[Path, str]] = {}
    for path in sorted(folder.glob("*.xlsx")):
        if path.name.startswith(("~$", ".")):  # Excel's lock files and hidden files
            continue
        try:
            sheets = fastexcel.read_excel(path).sheet_names
        except Exception as err:
            raise StagingError(f"cannot read the workbook {path.name} ({type(err).__name__})") from None
        for sheet in sheets:
            name = table_name(path.stem if len(sheets) == 1 else f"{path.stem}_{sheet}")
            if name in out:
                raise StagingError(f"two sheets would both be the table {name}: rename one")
            out[name] = (path, sheet)
    return out


def stage_excel(
    folder: Path, out: Path, *, tables: Sequence[str] | None = None, limit: int | None = None
) -> dict[str, int]:
    """Each sheet (of `tables`, else all) copied to `out/<table>.parquet`, with the types Excel holds."""
    copied: dict[str, int] = {}
    for name, (path, sheet) in excel_tables(folder).items():
        if tables is not None and name not in tables:
            continue
        try:
            frame = pl.read_excel(path, sheet_name=sheet, engine="calamine")
        except Exception as err:
            raise StagingError(
                f"cannot read the sheet {sheet} of {path.name} ({type(err).__name__})"
            ) from None
        if frame.width == 0:
            continue
        if limit is not None:
            frame = frame.head(limit)
        frame.write_parquet(out / f"{name}.parquet", compression="zstd")
        copied[name] = frame.height
    return copied


def for_excel(frame: pl.DataFrame) -> pl.DataFrame:
    """A frame Excel can hold without changing a value: integers beyond 2^53, decimals and bytes as text,
    datetimes with a time zone in UTC without the zone."""
    columns = []
    for series in frame.get_columns():
        dtype = series.dtype
        if dtype.is_integer():
            values = series.drop_nulls()
            if values.len() and (int(values.max()) >= EXCEL_SAFE_INT or int(values.min()) <= -EXCEL_SAFE_INT):  # type: ignore[arg-type]
                series = series.cast(pl.String)
        elif isinstance(dtype, pl.Decimal):
            series = series.cast(pl.String)
        elif dtype == pl.Binary:
            series = series.bin.encode("hex")
        elif isinstance(dtype, pl.Datetime) and dtype.time_zone is not None:
            series = series.dt.convert_time_zone("UTC").dt.replace_time_zone(None)
        columns.append(series)
    return pl.DataFrame(columns)


def deliver_excel(twin: Path, tables: Sequence[str], out: Path) -> list[Path]:
    """`out/<table>.xlsx` for each table of the twin, written under a temporary name and renamed into
    place."""
    token = secrets.token_hex(4)
    pending: list[tuple[Path, Path]] = []
    try:
        for table in tables:
            files = sorted((twin / table).glob("*.parquet"))
            frame = pl.concat([pl.read_parquet(f) for f in files]) if files else pl.DataFrame()
            temporary = out / f".{table}.xlsx.{token}"
            pending.append((temporary, out / f"{table}.xlsx"))
            try:
                for_excel(frame).write_excel(temporary, worksheet=table[:31], autofit=True)
            except Exception as err:
                raise StagingError(f"cannot write {table}.xlsx ({type(err).__name__})") from None
        for temporary, final in pending:
            os.replace(temporary, final)
    finally:
        for temporary, _ in pending:
            temporary.unlink(missing_ok=True)
    return [final for _, final in pending]
