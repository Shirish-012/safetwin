"""The operators of the data plane as Polars steps (and two as SQL for DuckDB), and the local folders that
act as their sockets.

An operator's config is checked when its stage is planned, before any data moves: a wrong config is a
`ConfigError` whose message is safe to show (names, paths and settings, never data).

Every step is a function from one Polars `LazyFrame` to another. The fused path chains them into one
query, and the batch-by-batch path applies the same functions to one batch at a time, so the two paths
cannot disagree about what an operator means. The steps are row by row: a row comes out the same whatever
rows come before or after it. That is also why nothing here guesses from the data: the CSV source reads every
column as text, `transform.parse_dates` without a format tries a fixed list of formats (Polars' own guess
comes from the first value of each chunk it is handed, so one file could parse differently from one run to
the next), and a value that can't be converted becomes null.

The SQL of `transform.filter` and `transform.derive` is checked against an allow-list before Polars sees it
(`expressions.py` says why): no query, no table function, only plain row-by-row scalar functions.

`transform.sql` and `transform.sort` need all the rows, so they are not Polars steps: each is a `SqlStep`, a
query over the table `input` that DuckDB runs (`hybrid.py`). The SQL is checked when the stage is planned:
it must be exactly one `SELECT` statement, so that SQL can do nothing but read its input (and the connection
is locked as well, see `spill.py`).

Known differences between the readers of `source.csv` (Polars on the fused path, PyArrow on the batch one)
that are not removed: Polars reads a blank line as a row of nulls where PyArrow skips it, and a row with too
few fields is padded with nulls by Polars and an error for PyArrow. Both refuse a row with too many fields.
`tests/dataplane/test_paths.py` pins all three, so a new version of either library shows up there.
"""

import glob
import itertools
import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Final, Literal

import duckdb
import polars as pl
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from safetwin.spec.models import Node

from .expressions import check_expression

Transform = Callable[[pl.LazyFrame], pl.LazyFrame]

PARQUET_COMPRESSION: Final = "zstd"
PARQUET_COMPRESSION_LEVEL = 3
PLACEHOLDERS = ("yyyy", "MM", "dd", "run_id")


class ConfigError(ValueError):
    """A node's config, or a socket or a path it names, can't be used.

    The message is safe to show: it holds names, paths and settings, never data.
    """


class Unsupported(NotImplementedError):
    """The pipeline uses something that can't run yet. The message is safe to show, like a `ConfigError`'s."""


def operator_key(operator: str) -> str:
    """`transform.filter@1` (a pinned version) is the operator `transform.filter`."""
    return operator.partition("@")[0]


# --- configs -------------------------------------------------------------------------------------------


class _Config(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class CsvSource(_Config):
    """`source.csv`: the CSV files that `path` (a path or a glob below the socket root) names.

    `header` is another name for `has_header`, which is what `tests/fixtures/csv-clean.yaml` says. Giving both
    is an error.
    """

    path: str
    has_header: bool = True
    delimiter: Annotated[str, StringConstraints(pattern=r"^[\t -~]$")] = ","  # one ASCII character

    @model_validator(mode="before")
    @classmethod
    def _header_is_has_header(cls, config: Any) -> Any:
        if isinstance(config, dict) and "header" in config:
            if "has_header" in config:
                raise ValueError("header is another name for has_header: give one of them")
            config = {("has_header" if key == "header" else key): value for key, value in config.items()}
        return config


class ParquetSource(_Config):
    """`source.parquet`: the Parquet files that `path` (a path or a glob below the socket root) names. They
    must have the same columns."""

    path: str


class ColumnsConfig(_Config):
    columns: Annotated[list[str], Field(min_length=1)]

    @field_validator("columns")
    @classmethod
    def _unique(cls, columns: list[str]) -> list[str]:
        if len(set(columns)) != len(columns):
            raise ValueError("must not repeat")
        return columns


class FilterConfig(_Config):
    expr: str


class DeriveConfig(_Config):
    name: Annotated[str, Field(min_length=1)]
    expr: str


class ParseDatesConfig(ColumnsConfig):
    format: str | None = None


class CastConfig(_Config):
    columns: Annotated[dict[str, Literal["string", "int", "float", "date"]], Field(min_length=1)]


class SqlConfig(_Config):
    """`transform.sql`: `sql` is one SELECT statement that reads the rows of the node before it as `input`."""

    sql: str


class SortKey(_Config):
    column: Annotated[str, Field(min_length=1)]
    descending: bool = False


class SortConfig(_Config):
    """`transform.sort`: `by` lists the columns (a name, or `{column, descending}`) in order of importance.

    `nulls` says where the nulls go for every column: `last` (the default) or `first`. Rows that are equal in
    every column of `by` come out in no promised order.
    """

    by: Annotated[list[SortKey], Field(min_length=1)]
    nulls: Literal["first", "last"] = "last"

    @field_validator("by", mode="before")
    @classmethod
    def _a_name_is_a_key(cls, by: Any) -> Any:
        if isinstance(by, list):
            return [{"column": key} if isinstance(key, str) else key for key in by]
        return by

    @field_validator("by")
    @classmethod
    def _unique(cls, by: list[SortKey]) -> list[SortKey]:
        if len({key.column for key in by}) != len(by):
            raise ValueError("must not repeat a column")
        return by


class ParquetSink(_Config):
    """`sink.parquet`: a dataset folder below the socket root, with Parquet files in it."""

    path: str
    compression: Literal["zstd"] = PARQUET_COMPRESSION


class CsvSink(_Config):
    """`sink.csv`: a dataset folder below the socket root, with CSV files in it (a header row, UTF-8)."""

    path: str


def parse_config[C: _Config](model: type[C], node: Node) -> C:
    """The node's config as `model`, or a `ConfigError` that says what is wrong with it."""
    try:
        return model.model_validate(node.config)
    except ValidationError as err:
        problems = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'config'}: {e['msg'].removeprefix('Value error, ')}"
            for e in err.errors(include_url=False, include_input=False, include_context=False)
        )
        raise ConfigError(f"{node.id} ({node.operator}): {problems}") from None


# --- sockets that are folders --------------------------------------------------------------------------


class LocalSocketResolver:
    """Sockets that are folders on this machine.

    `mapping` says which folder a socket is: its keys are the aliases of the pipeline (`inbox`) or socket
    URIs (`socket://local-inbox`). `aliases` is `spec.sockets` of the pipeline (alias to URI). A node names
    its socket by alias or by URI, and either is found whichever of the two the mapping is keyed by.

    Whatever a config says, it stays inside the folder of its socket: a path can't be absolute or contain
    `..`, and can't lead out through a symlink. The folder itself must exist (a missing one is usually a
    disk that is not mounted, and creating it would write to the wrong disk); the folders below it are
    created when something is written.
    """

    def __init__(self, mapping: Mapping[str, Path], aliases: Mapping[str, str] | None = None) -> None:
        self._mapping = dict(mapping)
        self._aliases = dict(aliases or {})

    def uri(self, reference: str) -> str:
        """The socket URI for an alias, or the reference itself when it is one already."""
        return self._aliases.get(reference, reference)

    def root(self, reference: str) -> Path:
        """The folder of the socket, with symlinks resolved."""
        uri = self.uri(reference)
        aliases_of_uri = [alias for alias, target in self._aliases.items() if target == uri]
        for key in (reference, uri, *aliases_of_uri):
            if key in self._mapping:
                folder = Path(os.path.realpath(self._mapping[key]))
                if not folder.is_dir():
                    raise ConfigError(f"socket '{reference}' is not a folder: {self._mapping[key]}")
                return folder
        known = ", ".join(sorted(self._mapping)) or "none"
        raise ConfigError(f"socket '{reference}' has no folder (folders were given for: {known})")

    def resolve(self, reference: str, relative: str) -> Path:
        """A path below the socket's folder, which need not exist yet. It may not lead out of the socket."""
        root = self.root(reference)
        return self._inside(root, reference, relative, root / _relative(relative))

    def glob(self, reference: str, pattern: str) -> list[Path]:
        """The files that `pattern` (`*`, `?`, `**`) names below the socket's folder, in name order."""
        root = self.root(reference)
        _relative(pattern)
        found = []
        for name in sorted(glob.glob(pattern, root_dir=root, recursive=True)):  # not hidden files
            path = self._inside(root, reference, name, root / name)
            if path.is_file():
                found.append(path)
        return found

    @staticmethod
    def _inside(root: Path, reference: str, relative: str, candidate: Path) -> Path:
        real = Path(os.path.realpath(candidate))  # follows symlinks, also in a path that doesn't exist yet
        if not real.is_relative_to(root):
            raise ConfigError(f"'{relative}' leads out of socket '{reference}' (through a symlink)")
        return real


def _relative(path: str) -> PurePosixPath:
    """`path` as a relative path, or a `ConfigError` if it is absolute or goes up with `..`."""
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or ".." in parsed.parts or "\x00" in path:
        raise ConfigError(f"'{path}' must be a path below the socket: no leading '/', no '..'")
    return parsed


# --- the source ----------------------------------------------------------------------------------------


def csv_files(node: Node, config: CsvSource | ParquetSource, resolver: LocalSocketResolver) -> list[Path]:
    """The files of a `source.csv` or `source.parquet` node. There must be at least one."""
    files = resolver.glob(socket_of(node), config.path)
    if not files:
        raise ConfigError(f"{node.id} ({node.operator}): no file matches '{config.path}' in its socket")
    return files


def csv_columns(node: Node, config: CsvSource, files: Sequence[Path]) -> list[str]:
    """The columns that every one of `files` has, named as Polars names them: by the header row, or
    `column_1`, `column_2`... when there is none.

    A file whose columns are not those of the first (other names, another order, another number) is a
    `ConfigError`, for both paths and before anything is read. The message names the files and never a column:
    where a file has no header, the names are a row of data.
    """
    columns = _header(node, config, files[0])
    for path in files[1:]:
        if _header(node, config, path) != columns:
            raise ConfigError(
                f"{node.id} ({node.operator}): '{path.name}' has other columns than '{files[0].name}'"
            )
    return columns


def _header(node: Node, config: CsvSource, path: Path) -> list[str]:
    try:
        return scan_csv([path], config).collect_schema().names()
    except pl.exceptions.NoDataError:
        raise ConfigError(f"{node.id} ({node.operator}): '{path.name}' is empty") from None


def parquet_columns(node: Node, files: Sequence[Path]) -> list[str]:
    """The columns of a `source.parquet` node's files: every file must have the same names, in order."""
    try:
        first = pl.scan_parquet(files[0]).collect_schema()
        for path in files[1:]:
            if pl.scan_parquet(path).collect_schema() != first:
                raise ConfigError(
                    f"{node.id} ({node.operator}): '{path.name}' has other columns than '{files[0].name}'"
                )
    except pl.exceptions.PolarsError as err:
        raise ConfigError(
            f"{node.id} ({node.operator}): a file can't be read as Parquet ({type(err).__name__})"
        ) from None
    return first.names()


def scan_parquet_files(files: Sequence[Path]) -> pl.LazyFrame:
    """The Parquet files as one lazy frame, in name order."""
    return pl.scan_parquet(list(files), glob=False, hive_partitioning=False)


def scan_csv(files: Sequence[Path], config: CsvSource) -> pl.LazyFrame:
    """The files as one lazy frame with every column read as text. Empty fields (unquoted) are null."""
    return pl.scan_csv(
        list(files),
        has_header=config.has_header,
        separator=config.delimiter,
        infer_schema=False,
        glob=False,
    )


# --- the steps -----------------------------------------------------------------------------------------


def _require_columns(
    frame: pl.LazyFrame, node: Node, names: Sequence[str], dtype: pl.DataType | None = None
) -> None:
    """Every name must be a column of `frame` (and of type `dtype` if that is given)."""
    schema = frame.collect_schema()
    missing = [name for name in names if name not in schema]
    if missing:
        raise no_such_columns(node, missing, schema.names())
    wrong = [name for name in names if dtype is not None and schema[name] != dtype]
    if wrong:
        raise ConfigError(f"{node.id} ({node.operator}): {', '.join(map(repr, wrong))} must be text")


def no_such_columns(node: Node, missing: Sequence[str], have: Sequence[str]) -> ConfigError:
    """The error for names that are not among the columns `have`. It lists the first 30 of them."""
    listed = ", ".join(have[:30]) + (f", ... ({len(have)} in all)" if len(have) > 30 else "")
    what = ", ".join(map(repr, missing))
    return ConfigError(f"{node.id} ({node.operator}): no column {what}; the columns are: {listed}")


def _expression(node: Node, text: str) -> pl.Expr:
    """`text` as a Polars expression: SQL, but only the part of it that `expressions.py` allows."""
    try:
        check_expression(text)  # first: Polars would open the files of a subquery while it parses the text
    except ValueError as err:
        raise ConfigError(f"{node.id} ({node.operator}): {err}") from None
    try:
        return pl.sql_expr(text)
    except pl.exceptions.PolarsError as err:  # a problem with the text: the data has not been looked at
        reason = (str(err).splitlines() or [type(err).__name__])[0]
        raise ConfigError(f"{node.id} ({node.operator}): the expression can't be used: {reason}") from None


def _select(node: Node) -> Transform:
    columns = parse_config(ColumnsConfig, node).columns

    def apply(frame: pl.LazyFrame) -> pl.LazyFrame:
        _require_columns(frame, node, columns)
        return frame.select(columns)

    return apply


def _filter(node: Node) -> Transform:
    predicate = _expression(node, parse_config(FilterConfig, node).expr)
    return lambda frame: frame.filter(predicate)


def _derive(node: Node) -> Transform:
    config = parse_config(DeriveConfig, node)
    expression = _expression(node, config.expr).alias(config.name)
    return lambda frame: frame.with_columns(expression)


def _trim(node: Node) -> Transform:
    columns = parse_config(ColumnsConfig, node).columns

    def apply(frame: pl.LazyFrame) -> pl.LazyFrame:
        _require_columns(frame, node, columns, pl.String())
        return frame.with_columns(pl.col(columns).str.strip_chars())

    return apply


# What `transform.parse_dates` accepts when it is given no format: ISO 8601 with a date and, optionally, a
# time, `T` or a space between them, optional fractions of a second, and an optional offset or `Z`. The first
# that fits a value wins. A value with an offset is converted to UTC, one without is taken to be UTC.
_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%.f%z",
    "%Y-%m-%d %H:%M:%S%.f%z",
    "%Y-%m-%dT%H:%M:%S%.fZ",
    "%Y-%m-%d %H:%M:%S%.fZ",
    "%Y-%m-%dT%H:%M:%S%.f",
    "%Y-%m-%d %H:%M:%S%.f",
    "%Y-%m-%d",
)


def _parse_datetime(column: str, format: str | None) -> pl.Expr:
    formats = (format,) if format is not None else _ISO_FORMATS
    return pl.coalesce(
        [
            pl.col(column).str.to_datetime(format=f, time_zone="UTC", time_unit="us", strict=False)
            for f in formats
        ]
    )


def _parse_dates(node: Node) -> Transform:
    config = parse_config(ParseDatesConfig, node)

    def apply(frame: pl.LazyFrame) -> pl.LazyFrame:
        _require_columns(frame, node, config.columns, pl.String())
        return frame.with_columns(_parse_datetime(column, config.format) for column in config.columns)

    return apply


_CASTS: dict[str, Callable[[str], pl.Expr]] = {
    "string": lambda column: pl.col(column).cast(pl.String),
    "int": lambda column: pl.col(column).cast(pl.Int64, strict=False),
    "float": lambda column: pl.col(column).cast(pl.Float64, strict=False),
    "date": lambda column: pl.col(column).str.to_date(format="%Y-%m-%d", strict=False),
}


def _cast(node: Node) -> Transform:
    columns = parse_config(CastConfig, node).columns

    def apply(frame: pl.LazyFrame) -> pl.LazyFrame:
        _require_columns(frame, node, list(columns))
        _require_columns(frame, node, [c for c, kind in columns.items() if kind == "date"], pl.String())
        return frame.with_columns(_CASTS[kind](column) for column, kind in columns.items())

    return apply


@dataclass(frozen=True)
class SqlStep:
    """A step that DuckDB runs: `sql` reads the table `input` and gives the rows that leave the node.

    `needs` are the columns that `input` must have. The stage checks them before it runs `sql`, so a wrong
    name is an error that says which columns there are, and not whatever DuckDB would say about it.
    """

    sql: str
    needs: tuple[str, ...] = ()


Step = Transform | SqlStep


def quote_name(name: str) -> str:
    """`name` as a double-quoted SQL identifier."""
    return '"' + name.replace('"', '""') + '"'


def _check_query(sql: str) -> None:
    """Raise `ValueError` unless `sql` is exactly one `SELECT` statement that DuckDB can parse.

    Nothing is run and no data has been looked at (the connection that parses it has no tables and no
    access to files), so the message may say what DuckDB says about the text. Like the connection of a stage,
    it is told that its extensions are in the app's folder (`spill.default_extension_dir`), not `~/.duckdb`.
    """
    from .spill import default_extension_dir  # here: spill.py imports this module

    if "\x00" in sql:  # DuckDB reads the text as a C string, and what comes after a NUL would not be parsed
        raise ValueError("the SQL can't be parsed: it contains a NUL character")
    parser = duckdb.connect(
        ":memory:",
        config={
            "threads": 1,
            "enable_external_access": False,
            "autoinstall_known_extensions": False,
            "autoload_known_extensions": False,
            "extension_directory": str(default_extension_dir()),
        },
    )
    try:
        statements = parser.extract_statements(sql)
    except duckdb.Error as err:
        reason = (str(err).splitlines() or [type(err).__name__])[0]
        raise ValueError(f"the SQL can't be parsed: {reason}") from None
    finally:
        parser.close()
    kinds = [statement.type for statement in statements]
    if kinds != [duckdb.StatementType.SELECT]:
        found = ", ".join(kind.name for kind in kinds) or "none"
        raise ValueError(f"the SQL must be exactly one SELECT statement that reads `input` (found: {found})")


def _sql(node: Node) -> SqlStep:
    config = parse_config(SqlConfig, node)
    try:
        _check_query(config.sql)
    except ValueError as err:
        raise ConfigError(f"{node.id} ({node.operator}): {err}") from None
    return SqlStep(config.sql)


def _sort(node: Node) -> SqlStep:
    config = parse_config(SortConfig, node)
    order = ", ".join(
        f"{quote_name(key.column)} {'DESC' if key.descending else 'ASC'} NULLS {config.nulls.upper()}"
        for key in config.by
    )
    return SqlStep(f"SELECT * FROM input ORDER BY {order}", tuple(key.column for key in config.by))


_TRANSFORMS: dict[str, Callable[[Node], Transform]] = {
    "transform.select": _select,
    "transform.filter": _filter,
    "transform.derive": _derive,
    "transform.trim": _trim,
    "transform.parse_dates": _parse_dates,
    "transform.cast": _cast,
}
_DUCKDB_STEPS: dict[str, Callable[[Node], SqlStep]] = {
    "transform.sql": _sql,
    "transform.sort": _sort,
}
_SOURCES = frozenset({"source.csv", "source.parquet"})
_SINKS = frozenset({"sink.parquet", "sink.csv"})
# Operators that only the fused path runs: their input or output is not what the batch and hybrid paths read
# and write (CSV in, Parquet out), or they need what only the run context holds (the masking subkeys).
FUSED_ONLY = frozenset({"source.parquet", "sink.csv", "transform.mask"})


def has_polars_builder(operator: str) -> bool:
    """Whether a stage can run this operator inside a Polars query."""
    key = operator_key(operator)
    return key in _TRANSFORMS or key in _SOURCES or key in _SINKS or key == "transform.mask"


def is_duckdb_operator(operator: str) -> bool:
    """Whether DuckDB runs this operator: the stage then takes the hybrid path."""
    return operator_key(operator) in _DUCKDB_STEPS


def build_transform(node: Node) -> Transform:
    """The Polars step of a transform node. Raises `ConfigError` for a wrong config."""
    key = operator_key(node.operator)
    if key in _DUCKDB_STEPS:
        raise Unsupported(f"{node.operator} runs in DuckDB, which only the hybrid path uses")
    try:
        build = _TRANSFORMS[key]
    except KeyError:
        raise Unsupported(f"{node.operator} can't be run yet") from None
    return build(node)


def build_step(node: Node, ctx: Any = None) -> Step:
    """The step of a transform node: a Polars step, or a `SqlStep` for DuckDB.

    `transform.mask` needs the run context (`runtime.RunContext`): its subkeys and its counters. Raises
    `ConfigError` for a wrong config.
    """
    if operator_key(node.operator) == "transform.mask":
        from safetwin.masking.step import build_mask_step  # here: masking imports this module

        return build_mask_step(node, ctx)
    build = _DUCKDB_STEPS.get(operator_key(node.operator))
    return build(node) if build is not None else build_transform(node)


# --- the sink ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SinkPlan:
    """Where a `sink.parquet` node writes.

    `dataset_dir` holds the `_manifest` folder, and `relative` is the path of the data file below it (with
    `/`, as the manifest says it). The dataset is the part of the path before the first placeholder, so
    `sales/dt={yyyy}-{MM}-{dd}/` is the dataset `sales` with a folder `dt=2026-09-30` in it for each day.
    """

    file: Path
    dataset_dir: Path
    relative: str
    dataset: str
    uri: str


def plan_sink(node: Node, resolver: LocalSocketResolver, run_id: str, now: datetime) -> SinkPlan:
    """Work out where the sink writes: fill in the placeholders and check the path stays in the socket.

    `now` (in UTC) gives `{yyyy}`, `{MM}` and `{dd}`.
    """
    extension = "csv" if operator_key(node.operator) == "sink.csv" else "parquet"
    config: ParquetSink | CsvSink = (
        parse_config(CsvSink, node) if extension == "csv" else parse_config(ParquetSink, node)
    )
    if config.path.endswith(f".{extension}"):
        raise ConfigError(
            f"{node.id} ({node.operator}): path is a folder, not a file: "
            f"the file in it is named part-00000-<run id>.{extension}"
        )
    values = {"yyyy": f"{now:%Y}", "MM": f"{now:%m}", "dd": f"{now:%d}", "run_id": run_id}
    socket = socket_of(node)
    try:
        filled = PurePosixPath(_fill(config.path, values))
        fixed = list(itertools.takewhile(lambda part: "{" not in part, _relative(config.path).parts))
        directory = resolver.resolve(socket, str(filled))
        dataset_dir = resolver.resolve(socket, "/".join(fixed))
    except ConfigError as err:
        raise ConfigError(f"{node.id} ({node.operator}): {err}") from None
    name = f"part-00000-{run_id}.{extension}"
    dataset = "/".join(fixed) or "."
    return SinkPlan(
        file=directory / name,
        dataset_dir=dataset_dir,
        relative="/".join((*filled.parts[len(fixed) :], name)),
        dataset=dataset,
        uri=resolver.uri(socket) if not fixed else f"{resolver.uri(socket)}/{dataset}",
    )


def _fill(template: str, values: Mapping[str, str]) -> str:
    def value(match: re.Match[str]) -> str:
        if match.group(1) not in values:
            known = ", ".join(f"{{{name}}}" for name in PLACEHOLDERS)
            raise ConfigError(f"unknown placeholder {{{match.group(1)}}}; the known ones are {known}")
        return values[match.group(1)]

    return re.sub(r"\{([^{}]*)\}", value, template)


def socket_of(node: Node) -> str:
    """The socket (alias or URI) that a source or sink node names."""
    if node.socket is None:  # the validator reports this first; this is for a caller that skipped it
        raise ConfigError(f"{node.id} ({node.operator}): needs a socket")
    return node.socket
