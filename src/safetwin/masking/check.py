"""The checks of a policy against its source (`safetwin check`, and the start of `safetwin mask`).

Every table must have files, every column the policy names must exist, every source column must be named (or
`unknown_columns` says what happens to it), and every method must fit its column's type (docs/guide.md).
Only the schemas are read, never a row. Messages name tables, columns, files, methods and types: no values.
"""

import os
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import polars as pl

from safetwin.spec.policy import (
    DateShift,
    Encrypt,
    Fake,
    Generalize,
    MaskingPolicy,
    Method,
    Pseudonymize,
    Redact,
    engine_format,
)
from safetwin.spec.validate import Problem, redacted

from ..dataplane.operators import ConfigError, LocalSocketResolver

SOURCE_SOCKET = "source"
TARGET_SOCKET = "target"


@dataclass(frozen=True)
class SourceTable:
    """A table of the source: the glob that finds it (below the source folder), its files and its schema."""

    name: str
    glob: str
    files: list[Path]
    schema: pl.Schema


def _error(code: str, message: str) -> Problem:
    return Problem("error", code, message)


def kind_of(dtype: pl.DataType) -> str:
    """A column type as the type rules see it."""
    if dtype.is_integer():
        return "integer"
    if dtype.is_float():
        return "float"
    if isinstance(dtype, pl.Decimal):
        return "decimal"
    if dtype in (pl.String, pl.Categorical, pl.Enum) or isinstance(dtype, pl.Categorical | pl.Enum):
        return "text"
    if dtype == pl.Date:
        return "date"
    if isinstance(dtype, pl.Datetime):
        return "datetime"
    if dtype == pl.Boolean:
        return "boolean"
    if dtype == pl.Binary:
        return "binary"
    return "other"


def table_glob(policy: MaskingPolicy, table: str) -> str:
    mapped = (policy.spec.source.tables or {}).get(table)
    return mapped if mapped is not None else f"{table}.{engine_format(policy.spec.source)}"


def discover(policy: MaskingPolicy, folder: Path) -> tuple[dict[str, SourceTable], list[Problem]]:
    """The tables of the policy found in the source folder, and the problems found on the way."""
    problems: list[Problem] = []
    if not folder.is_dir():
        return {}, [_error("source_folder", f"the source folder {folder} is not a folder")]
    resolver = LocalSocketResolver({SOURCE_SOCKET: folder})
    found: dict[str, SourceTable] = {}
    for table in policy.spec.tables:
        pattern = table_glob(policy, table)
        try:
            files = resolver.glob(SOURCE_SOCKET, pattern)
        except ConfigError as err:
            problems.append(_error("source_path", f"table '{table}': {err}"))
            continue
        if not files:
            problems.append(
                _error("unknown_table", f"table '{table}': no file matches '{redacted(pattern)}' in {folder}")
            )
            continue
        try:
            schema = _schema(policy, files)
        except (ConfigError, pl.exceptions.PolarsError, OSError) as err:
            reason = str(err) if isinstance(err, ConfigError) else type(err).__name__
            problems.append(_error("source_schema", f"table '{table}': the files can't be read ({reason})"))
            continue
        found[table] = SourceTable(table, pattern, files, schema)
    problems.extend(_unnamed_files(policy, folder))
    return found, problems


def _schema(policy: MaskingPolicy, files: list[Path]) -> pl.Schema:
    if engine_format(policy.spec.source) == "parquet":
        first = pl.scan_parquet(files[0]).collect_schema()
        if any(pl.scan_parquet(path).collect_schema() != first for path in files[1:]):
            raise ConfigError("its files don't all have the same columns and types")
        return first
    names: list[str] | None = None
    for path in files:
        header = (
            pl.scan_csv(path, separator=policy.spec.source.delimiter, infer_schema=False)
            .collect_schema()
            .names()
        )
        if names is not None and header != names:
            raise ConfigError("its files don't all have the same header")
        names = header
    return pl.Schema(dict.fromkeys(names or [], pl.String()))


def _unnamed_files(policy: MaskingPolicy, folder: Path) -> Iterator[Problem]:
    """A warning for each file of the source format at the top of the folder that no table claims."""
    if policy.spec.source.tables:
        return
    extension = f".{engine_format(policy.spec.source)}"
    for name in sorted(os.listdir(folder)):
        stem = name.removesuffix(extension)
        if name.endswith(extension) and not name.startswith(".") and stem not in policy.spec.tables:
            yield Problem(
                "warning",
                "unnamed_table",
                f"'{name}' is in the source but not in the policy: it is not copied",
            )


def _fits(spec: Method, kind: str, dtype: pl.DataType) -> str | None:
    """Why `spec` can't run on a column of `kind`, or None when it can."""
    numeric = ("integer", "float")
    match spec:
        case Pseudonymize(format="int") if kind != "integer":
            return "pseudonymize format int needs an integer column"
        case Pseudonymize(format="uuid") if kind not in ("text", "binary"):
            return "pseudonymize format uuid needs a text (UUID) or binary column"
        case Pseudonymize() if kind == "other":
            return "pseudonymize needs a column of a plain type"
        case Encrypt(algorithm="ff1") if kind != "text":
            return "encrypt with ff1 needs a text column (it keeps the format of text)"
        case Encrypt() if kind == "other" and dtype != pl.Time:
            return "encrypt needs a column of a plain type (not a list or a struct)"
        case Fake() if kind != "text":
            return "fake needs a text column"
        case DateShift() if kind not in ("date", "datetime"):
            return "date_shift needs a date or datetime column"
        case Redact() if kind != "text":
            return "redact needs a text column"
        case Generalize(to=to) if to is not None and kind not in ("date", "datetime"):
            return "generalize to needs a date or datetime column"
        case Generalize(keep_chars=n) if n is not None and kind != "text":
            return "generalize keep_chars needs a text column"
        case Generalize(ip=True) if kind != "text":
            return "generalize ip needs a text column"
        case Generalize(bucket=b) if b is not None and (
            kind not in numeric or (kind == "integer" and not isinstance(b, int))
        ):
            return "generalize bucket needs a number column (and a whole bucket for an integer column)"
        case Generalize(bins=bins) if bins is not None and (
            kind not in numeric or (kind == "integer" and not all(isinstance(b, int) for b in bins))
        ):
            return "generalize bins needs a number column (and whole bins for an integer column)"
    return None


def check_against_source(policy: MaskingPolicy, tables: Mapping[str, SourceTable]) -> list[Problem]:
    """The problems of the policy given the source's tables (found by `discover`)."""
    problems: list[Problem] = []
    for table, source in tables.items():
        columns = policy.spec.tables[table]
        for column, spec in columns.items():
            where = f"{table}.{redacted(column)}"
            if column not in source.schema:
                problems.append(_error("unknown_column", f"{where}: the source table has no such column"))
                continue
            dtype = source.schema[column]
            kind = kind_of(dtype)
            if (why := _fits(spec, kind, dtype)) is not None:
                problems.append(_error("method_type", f"{where}: {why}, but the column is {kind} ({dtype})"))
            if isinstance(spec, DateShift) and spec.entity not in source.schema:
                problems.append(
                    _error(
                        "unknown_column",
                        f"{where}: the entity column '{redacted(spec.entity)}' is not in the source",
                    )
                )
        unnamed = [name for name in source.schema.names() if name not in columns]
        if unnamed and policy.spec.unknown_columns == "fail":
            listed = ", ".join(f"'{redacted(name)}'" for name in unnamed)
            problems.append(
                _error(
                    "unknown_column",
                    f"table '{table}': the policy names no method for {listed} (unknown_columns: fail). Name "
                    "each column, with keep if it is safe to copy",
                )
            )
        elif unnamed:
            problems.append(
                Problem(
                    "warning",
                    "unknown_column",
                    f"table '{table}': {len(unnamed)} column(s) the policy doesn't name will be "
                    f"{'nulled' if policy.spec.unknown_columns == 'null' else 'dropped'}",
                )
            )
    return problems
