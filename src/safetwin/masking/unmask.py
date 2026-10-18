"""`safetwin unmask`: the columns that `encrypt` masked, back to their values, with the access key.

The input is masked files: a twin folder that `safetwin mask` wrote (a folder per table, with its part
files), a folder of CSV, Parquet or Excel files, or single files. Every text column whose values all look
encrypted (`st1.…` for aes-siv, `sg1.…` for aes-gcm) is decrypted, with its type back (as
`portable.decrypt_series` says); every other column is copied as it is (one-way masked columns stay masked:
nothing can read them back). A CSV file is read as text, so the columns that weren't encrypted are written
back exactly as they were.

Columns encrypted with ff1 look like any others, so they are learnt from the run's `report.json` (in a
folder given, or given itself). Its access key fingerprint must be the key's: ff1 isn't authenticated, and a
wrong key would give wrong values rather than an error.

Every output file is written under a temporary name and renamed into place only when every table has been
decrypted: a wrong key or a changed file leaves nothing behind. Messages name tables and columns and count
values, never show one.
"""

import json
import os
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import polars as pl

from safetwin.spec.validate import redacted

from .portable import (
    SEALED_RANDOM,
    Sealer,
    SealProblem,
    decrypt_ff1_series,
    decrypt_series,
    encrypt_series,
    is_sealed,
)

Ff1Columns = dict[str, dict[str, tuple[str, str | None]]]  # table → column → (alphabet, domain)

FORMATS = {".parquet": "parquet", ".csv": "csv", ".xlsx": "xlsx"}
_SKIP = {"report.json", "report.html", "failed-report.json", "failed-report.html"}


class UnmaskError(Exception):
    """Unmasking can't go on. The message names files, tables and columns, never a value."""


@dataclass(frozen=True)
class Table:
    name: str
    format: str  # parquet or csv
    files: tuple[Path, ...]


@dataclass(frozen=True)
class Unmasked:
    table: str
    output: Path
    rows: int
    decrypted: tuple[str, ...]  # the columns that were encrypted, now readable
    copied: tuple[str, ...]  # the others, as they were
    ciphers: tuple[str, ...] = ()  # the algorithm of each decrypted column: aes-siv, aes-gcm or ff1


def _format(path: Path) -> str | None:
    return FORMATS.get(path.suffix.lower())


def _visible(path: Path) -> bool:
    return not path.name.startswith((".", "_")) and path.name not in _SKIP


def find_tables(paths: Sequence[Path]) -> list[Table]:
    """The tables in `paths`. A file is a table (named by its stem). In a folder, every CSV or Parquet file is
    a table, and so is every sub-folder that holds such files (a twin's table: named by the folder)."""
    found: dict[str, Table] = {}

    def add(name: str, files: list[Path]) -> None:
        formats = {_format(f) for f in files}
        if len(formats) != 1 or None in formats:
            raise UnmaskError(f"the table {name} mixes CSV, Parquet and Excel files")
        if name in found:
            raise UnmaskError(f"two inputs are both called {name}: give them different names")
        found[name] = Table(name, str(formats.pop()), tuple(sorted(files)))

    for path in paths:
        if path.is_file():
            if _format(path) is None:
                raise UnmaskError(f"{path.name} is not a CSV, Parquet or Excel file")
            add(path.stem, [path])
        elif path.is_dir():
            for entry in sorted(p for p in path.iterdir() if _visible(p)):
                if entry.is_file() and _format(entry) is not None:
                    add(entry.stem, [entry])
                elif entry.is_dir():
                    parts = [p for p in sorted(entry.iterdir()) if p.is_file() and _visible(p) and _format(p)]
                    if parts:
                        add(entry.name, parts)
        else:
            raise UnmaskError(f"{path} doesn't exist")
    if not found:
        raise UnmaskError("no CSV, Parquet or Excel files to unmask")
    return list(found.values())


def _read(table: Table) -> pl.DataFrame:
    try:
        if table.format == "parquet":
            return pl.read_parquet(list(table.files))
        if table.format == "xlsx":
            return pl.concat([pl.read_excel(f, engine="calamine") for f in table.files])
        return pl.concat([pl.read_csv(f, infer_schema=False) for f in table.files])
    except Exception as err:  # a library error can quote data: say what kind, no more
        raise UnmaskError(f"cannot read the table {table.name} ({type(err).__name__})") from None


def _reports(paths: Sequence[Path]) -> list[Path]:
    """The `report.json` files among `paths`, or in their folders."""
    reports = [p for p in paths if p.is_file() and p.name == "report.json"]
    return reports + [p / "report.json" for p in paths if p.is_dir() and (p / "report.json").is_file()]


def ff1_columns(paths: Sequence[Path], sealer: Sealer) -> Ff1Columns:
    """The ff1 columns that the `report.json` files among `paths` (or in their folders) name. Raises
    `UnmaskError` when a report says another access key made them."""
    found: Ff1Columns = {}
    reports = _reports(paths)
    for path in reports:
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError):
            raise UnmaskError(f"cannot read {path.name}") from None
        columns = {
            (table, column): entry.get("params") or {}
            for table, info in (report.get("tables") or {}).items()
            for column, entry in (info.get("columns") or {}).items()
            if entry.get("method") == "encrypt" and (entry.get("params") or {}).get("algorithm") == "ff1"
        }
        expected = report.get("access_fingerprint")
        if columns and expected and expected != sealer.fingerprint:
            raise UnmaskError(
                f"these files were masked with the access key {expected}, not with this one "
                f"({sealer.fingerprint}): nothing was written"
            )
        for (table, column), params in columns.items():
            found.setdefault(table, {})[column] = (params.get("alphabet") or "digits", params.get("domain"))
    return found


def unmask_table(
    frame: pl.DataFrame,
    sealer: Sealer,
    name: str,
    *,
    to: Sealer | None = None,
    ff1: dict[str, tuple[str, str | None]] | None = None,
) -> tuple[pl.DataFrame, dict[str, str]]:
    """`frame` with its encrypted columns decrypted (or, with `to`, encrypted again with that key and the same
    algorithm: what masking with the new key would have made), and those columns with the algorithm each was
    found to have: a value's prefix says aes-siv (`st1.`) or aes-gcm (`sg1.`); `ff1` names the columns
    encrypted with ff1 (from the report), with their alphabet and domain. Nothing to choose by hand."""
    decrypted: dict[str, str] = {}
    columns = []
    for series in frame.get_columns():
        try:
            if series.name in (ff1 or {}):
                alphabet, domain = (ff1 or {})[series.name]
                plain = decrypt_ff1_series(series, sealer, alphabet, domain)
                algorithm = "ff1"
                again = None if to is None else encrypt_series(plain, to, "ff1", alphabet, domain)
            elif is_sealed(series):
                plain = decrypt_series(series, sealer)
                first = series.drop_nulls().cast(pl.String)[0]
                algorithm = "aes-gcm" if first.startswith(SEALED_RANDOM) else "aes-siv"
                again = None if to is None else encrypt_series(plain, to, algorithm)
            else:
                columns.append(series)
                continue
        except SealProblem as err:
            raise UnmaskError(f"{name}.{redacted(series.name)}: {err}") from None
        columns.append(plain if again is None else again.alias(series.name))
        decrypted[series.name] = algorithm
    return pl.DataFrame(columns), decrypted


def _write(frame: pl.DataFrame, path: Path, fmt: str) -> None:
    try:
        if fmt == "parquet":
            frame.write_parquet(path, compression="zstd")
        elif fmt == "xlsx":
            from .staging import for_excel

            for_excel(frame).write_excel(path, autofit=True)
        else:
            frame.write_csv(path)
    except Exception as err:
        raise UnmaskError(f"cannot write {path.name} ({type(err).__name__})") from None


def unmask(
    paths: Sequence[Path], out: Path, sealer: Sealer, *, replace: bool = False, to: Sealer | None = None
) -> list[Unmasked]:
    """Decrypt the tables of `paths` into the folder `out`, one file per table (`<table>.csv`,
    `<table>.parquet` or `<table>.xlsx`, the format it came in). `out` must be empty or new, unless `replace`
    is given; then only the files of these tables are replaced. With `to`, the encrypted columns are encrypted
    again with that access key instead (`safetwin rekey`): nothing readable is written."""
    ff1 = ff1_columns(paths, sealer)
    tables = find_tables([p for p in paths if not (p.is_file() and p.name == "report.json")])
    finals = {t.name: out / f"{t.name}.{t.format}" for t in tables}
    if out.exists() and not out.is_dir():
        raise UnmaskError(f"{out} is not a folder")
    if out.exists() and any(_visible(p) for p in out.iterdir()) and not replace:
        raise UnmaskError(f"the folder {out} is not empty: choose an empty folder, or give --replace")
    for table in tables:
        for file in table.files:
            if file.resolve() == finals[table.name].resolve():
                raise UnmaskError(f"{file.name} would be written over itself: choose another folder")
    out.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(4)
    written: list[tuple[Path, Path]] = []
    results = []
    try:
        for table in tables:
            frame, decrypted = unmask_table(_read(table), sealer, table.name, to=to, ff1=ff1.get(table.name))
            temporary = out / f".{table.name}.unmask-{token}"
            written.append((temporary, finals[table.name]))
            _write(frame, temporary, table.format)
            copied = tuple(c for c in frame.columns if c not in decrypted)
            results.append(
                Unmasked(
                    table.name,
                    finals[table.name],
                    frame.height,
                    tuple(decrypted),
                    copied,
                    tuple(decrypted.values()),
                )
            )
        if to is not None and (reports := _reports(paths)):
            # The report goes with the rekeyed files, naming the new access key (ff1 columns are learnt from
            # it); the files it listed are the old ones, so it lists none.
            report = json.loads(reports[0].read_text(encoding="utf-8"))
            report.update(access_fingerprint=to.fingerprint, rekeyed_from=sealer.fingerprint, files=[])
            temporary = out / f".report.json.unmask-{token}"
            written.append((temporary, out / "report.json"))
            temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for temporary, final in written:
            os.replace(temporary, final)
    finally:
        for temporary, _ in written:
            temporary.unlink(missing_ok=True)
    return results
