"""The runner of an exported Polars job (docs/guide.md): what the generated code calls, and its `main`.

`safetwin export --to polars` copies the code below the marker line into the exported script, after the
portable core (`safetwin/masking/portable.py`). It is importable here so the tests can run it in process; in
the script it uses the core's names as globals, which is why it imports them above the marker.

The generated code describes the job (`Job`, one `Table` per table, with a function that masks it) and
calls `main`, which reads every table, checks it has the columns and types the export saw, selects the
subset, masks, writes every table under a temporary name, checks the relationships (0 orphans) and the
columns that must stay unique, and only then renames the files into place. A failure or Ctrl-C removes what
the run wrote. Messages name tables, columns and files, never a value.
"""

import argparse
import glob
import os
import secrets
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

import polars as pl

from safetwin.masking.portable import (
    TRUNCATE,
    KeyProblem,
    Keys,
    Mac,
    Relationship,
    Sealer,
    bins_expr,
    bucket_expr,
    date_offsets,
    encrypt_series,
    fake_series,
    ip_networks,
    orphans,
    pseudonymize_series,
    read_key,
    redact_expr,
    subset_columns,
    subset_filters,
)

# --- exported below this line -------------------------------------------------------------------------------


# --- the column methods, as Polars expressions --------------------------------------------------------------


def _mapped(name: str, function: Callable[[pl.Series], pl.Series], dtype: pl.DataType) -> pl.Expr:
    return pl.col(name).map_batches(function, return_dtype=dtype, is_elementwise=True).alias(name)


def pseudonymize(name: str, mac: Mac, fmt: str, prefix: str = "", *, binary: bool = False) -> pl.Expr:
    """Keyed pseudonyms: equal inputs give equal outputs within a domain (`fmt`: int, hex or uuid)."""
    dtype = pl.Int64() if fmt == "int" else pl.Binary() if binary else pl.String()
    return _mapped(name, lambda s: pseudonymize_series(s, mac, fmt, prefix), dtype)


def encrypt(
    name: str, sealer: Sealer, algorithm: str = "aes-siv", alphabet: str = "digits", domain: str | None = None
) -> pl.Expr:
    """The column encrypted (aes-siv, aes-gcm or ff1), as text: whoever holds the access key reads it back."""
    return _mapped(name, lambda s: encrypt_series(s, sealer, algorithm, alphabet, domain), pl.String())


def fake(name: str, kind: str, mac: Mac | None) -> pl.Expr:
    """Fake values of `kind`: one per distinct input with a `mac`, a fresh one per row without."""
    return _mapped(name, lambda s: fake_series(s, kind, mac), pl.String())


def nulled(name: str) -> pl.Expr:
    """Every value null; the column and its type stay."""
    return pl.when(pl.lit(False)).then(pl.col(name)).alias(name)


def truncate(name: str, to: str) -> pl.Expr:
    return pl.col(name).dt.truncate(TRUNCATE[to]).alias(name)


def bucket(name: str, width: float, dtype: pl.DataType) -> pl.Expr:
    return bucket_expr(pl.col(name), width, dtype.is_integer()).cast(dtype).alias(name)


def bins(name: str, edges: Sequence[float], dtype: pl.DataType) -> pl.Expr:
    return bins_expr(pl.col(name), edges).cast(dtype).alias(name)


def keep_chars(name: str, count: int) -> pl.Expr:
    return pl.col(name).cast(pl.String).str.slice(0, count).alias(name)


def ip_network_of(name: str) -> pl.Expr:
    return _mapped(name, ip_networks, pl.String())


def date_shift(name: str, entity: str, mac: Mac, max_days: int, dtype: pl.DataType) -> pl.Expr:
    """Every date moved by the keyed offset of its row's entity, so intervals within an entity stay."""
    offsets = pl.col(entity).map_batches(
        lambda s: date_offsets(s, mac, max_days), return_dtype=pl.Int64(), is_elementwise=True
    )
    return (pl.col(name) + pl.duration(days=offsets)).cast(dtype).alias(name)


def redact(
    name: str,
    *,
    keep_last: int | None = None,
    keep_first: int | None = None,
    char: str = "*",
    with_: str | None = None,
) -> pl.Expr:
    expr = redact_expr(pl.col(name), keep_last=keep_last, keep_first=keep_first, char=char, with_=with_)
    return expr.alias(name)


# --- the job ------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Table:
    """A table of the job: its files (a glob below the source folder), the columns and types the export
    saw, the function that masks it, and the columns that must stay unique if they were in the input."""

    name: str
    glob: str
    columns: dict[str, str]
    mask: Callable[[pl.LazyFrame, Keys], pl.LazyFrame]
    unique: tuple[str, ...] = ()


@dataclass(frozen=True)
class Subset:
    root: str
    key: str
    fraction: float
    include_children: bool


@dataclass(frozen=True)
class Job:
    """What the policy says, as the export saw it. Folders are relative to the script's folder."""

    name: str
    key: str  # a reference: env://NAME or file://PATH
    source: str
    source_format: str
    delimiter: str
    target: str
    target_format: str
    tables: tuple[Table, ...]
    relationships: tuple[Relationship, ...] = ()
    subset: Subset | None = None


class JobFailed(Exception):
    """The job can't run or a check failed. The message is safe to show."""


def _scan(files: Sequence[Path], fmt: str, delimiter: str) -> pl.LazyFrame:
    if fmt == "parquet":
        return pl.scan_parquet(list(files), glob=False, hive_partitioning=False)
    return pl.scan_csv(list(files), separator=delimiter, infer_schema=False, glob=False)


def _files(folder: Path, pattern: str) -> list[Path]:
    """The files `pattern` names below `folder`, in name order (hidden files are left out)."""
    found = sorted(glob.glob(pattern, root_dir=folder, recursive=True))
    return [folder / name for name in found if (folder / name).is_file()]


def run(job: Job, source: Path, target: Path, *, replace: bool, written: list[Path]) -> list[str]:
    """Run the job; return the summary lines. Every file it writes is in `written` until it is in place."""
    keys = Keys(read_key(job.key))
    if not source.is_dir():
        raise JobFailed(f"the source folder {source} is not a folder")
    if os.path.realpath(source) == os.path.realpath(target):
        raise JobFailed("the target folder must not be the source folder")
    ext = job.target_format
    finals = {t.name: target / f"{t.name}.{ext}" for t in job.tables}
    existing = [p.name for p in finals.values() if p.exists()]
    if existing and not replace:
        raise JobFailed(f"{target} has {', '.join(existing)} already: give --replace to replace them")

    inputs: dict[str, pl.LazyFrame] = {}
    for t in job.tables:
        files = _files(source, t.glob)
        if not files:
            raise JobFailed(f"table '{t.name}': no file matches '{t.glob}' in {source}")
        frame = _scan(files, job.source_format, job.delimiter)
        if {c: str(d) for c, d in frame.collect_schema().items()} != t.columns:
            raise JobFailed(
                f"table '{t.name}': its columns or types are not those of the export: export the policy again"
            )
        inputs[t.name] = frame
    rows_in: dict[str, int] = {}
    unique_in: dict[tuple[str, str], bool] = {}
    for t in job.tables:
        exprs = [pl.len().alias("rows")]
        for i, c in enumerate(t.unique):
            exprs += [pl.col(c).n_unique().alias(f"u{i}"), pl.col(c).null_count().alias(f"n{i}")]
        row = inputs[t.name].select(exprs).collect(engine="streaming").row(0, named=True)
        rows_in[t.name] = int(row["rows"])
        for i, c in enumerate(t.unique):
            unique_in[(t.name, c)] = row[f"n{i}"] == 0 and row[f"u{i}"] == rows_in[t.name]

    filters: dict[str, pl.Expr] = {}
    if job.subset is not None:
        s = job.subset
        columns = subset_columns(s.root, s.key, job.relationships)
        frames = {t: inputs[t].select(cs).collect(engine="streaming") for t, cs in columns.items()}
        mac = keys.mac("subset", s.root)
        filters, _ = subset_filters(
            frames, s.root, s.key, s.fraction, s.include_children, job.relationships, mac
        )

    target.mkdir(parents=True, exist_ok=True)
    temps: dict[str, Path] = {}
    for t in job.tables:
        frame = inputs[t.name]
        if t.name in filters:
            frame = frame.filter(filters[t.name])
        temp = target / f".{t.name}.{ext}.tmp-{secrets.token_hex(4)}"
        written.append(temp)
        masked = t.mask(frame, keys)
        if ext == "csv":
            masked.sink_csv(temp)
        else:
            masked.sink_parquet(temp, compression="zstd", compression_level=3)
        temps[t.name] = temp

    if ext == "csv":
        outputs = {name: pl.scan_csv(path, infer_schema=False) for name, path in temps.items()}
    else:
        outputs = {name: pl.scan_parquet(path) for name, path in temps.items()}
    failures: list[str] = []
    rows_out: dict[str, int] = {}
    checked_unique = 0
    for t in job.tables:
        exprs = [
            pl.len().alias("rows"),
            *(pl.col(c).n_unique().alias(f"u{i}") for i, c in enumerate(t.unique)),
        ]
        row = outputs[t.name].select(exprs).collect(engine="streaming").row(0, named=True)
        rows_out[t.name] = int(row["rows"])
        for i, c in enumerate(t.unique):
            if unique_in[(t.name, c)]:
                checked_unique += 1
                if row[f"u{i}"] != rows_out[t.name]:
                    failures.append(f"{t.name}.{c} was unique in the input but not after masking")
    total_orphans = 0
    for a, ac, b, bc in job.relationships:
        found = orphans(outputs[a], ac, outputs[b], bc)
        total_orphans += found
        if found:
            failures.append(f"{a}.{ac} -> {b}.{bc}: {found} row(s) point at no row after masking")
    if failures:
        raise JobFailed("a check failed, so nothing was written: " + "; ".join(failures))
    for name, temp in temps.items():
        os.replace(temp, finals[name])
        written.remove(temp)

    width = max(len(t.name) for t in job.tables)
    lines = [f"{t.name:<{width}}  {rows_in[t.name]:,} → {rows_out[t.name]:,} rows" for t in job.tables]
    lines.append(
        f"relationships: {len(job.relationships)} checked, {total_orphans} orphans · "
        f"unique columns: {checked_unique} checked, all unique"
    )
    lines.append(f"key fingerprint {keys.fingerprint} · wrote {len(finals)} file(s) to {target}")
    return lines


def main(job: Job, here: Path, argv: Sequence[str] | None = None) -> int:
    """The command line of the exported script. Exit status: 0 done, 1 failed (nothing written), 130
    interrupted (nothing written)."""
    parser = argparse.ArgumentParser(description=f"Write the safe twin of {job.name}.")
    parser.add_argument("--source", type=Path, help=f"the source folder (default: {job.source})")
    parser.add_argument("--target", type=Path, help=f"the target folder (default: {job.target})")
    parser.add_argument("--replace", action="store_true", help="replace the twin's files if they exist")
    args = parser.parse_args(argv)
    source = args.source if args.source is not None else here / Path(job.source).expanduser()
    target = args.target if args.target is not None else here / Path(job.target).expanduser()
    written: list[Path] = []
    try:
        lines = run(job, source, target, replace=args.replace, written=written)
    except BaseException as err:
        for path in written:
            path.unlink(missing_ok=True)
        if isinstance(err, KeyboardInterrupt):
            print("interrupted: nothing was written", file=sys.stderr)
            return 130
        if isinstance(err, JobFailed | KeyProblem):
            print(f"ERROR {err}", file=sys.stderr)
            return 1
        if isinstance(err, Exception):  # a library error can quote data: say what kind, no more
            print(
                f"ERROR the job failed with {type(err).__name__} (not shown: it can quote data)",
                file=sys.stderr,
            )
            return 1
        raise
    print("\n".join(lines))
    return 0
