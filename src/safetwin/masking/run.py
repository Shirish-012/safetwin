"""`safetwin check` and `safetwin mask`, in process (docs/internals.md).

    load masking.yaml → validate → resolve the key reference → read the source schemas → every column named?
    → compile → run every stage (source → transform.mask → commit writer) → uniqueness, relationships,
    residual scan, quasi-identifiers → report.json + report.html → exit status

The run uses the data plane's per-stage functions (`plan_pipeline`, `run_planned_stage`), so it knows what
every finished stage committed. A failure or an interrupt (Ctrl-C) in any stage or check removes everything
the run wrote: no partial twin is left. A check that fails (a collision, an orphan, a residual finding in a
masked column, or with `strict` a warning) also removes the data files and manifests; the report is still
written, with the reason, so you can see why. The report holds names, counts, classes, hashes and settings,
never a value, and paths relative to the output folder.

The target folder must be empty, or hold an earlier twin and the run is given `replace`. The new twin's files
land next to the earlier one's (their names hold the run id); only once every check has passed is the earlier
twin removed: the files its report.json lists, its manifests and its reports. A run that fails leaves the
earlier twin as it was, and writes its own report as `failed-report.json` and `failed-report.html`.

The two report files are written under temporary names first and renamed into place at the end, HTML then
JSON, so a report.json is there only when the whole run is; an error or Ctrl-C before that removes both.
"""

import hashlib
import json
import os
import secrets
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import polars as pl

from safetwin.detect.exprs import DETECTORS, Finding, residual_scan
from safetwin.keys import KeyRefError, MasterKey, resolve_key, resolve_secret
from safetwin.spec.io import SpecError
from safetwin.spec.policy import (
    DateShift,
    Drop,
    Encrypt,
    Fake,
    Generalize,
    Keep,
    MaskingPolicy,
    Method,
    Pseudonymize,
    column_class,
    engine_format,
    load_policy_file,
    method_params,
    relationships,
    staged_source,
    staged_target,
    validate_policy,
)
from safetwin.spec.validate import Problem, redacted

from ..dataplane.cleanup import remove_temporary_files
from ..dataplane.manifest import MANIFEST_DIR
from ..dataplane.run import plan_pipeline, run_planned_stage
from ..dataplane.runtime import ProgressEvent, StageResult
from ..dataplane.writer import CommitWriter
from .check import SOURCE_SOCKET, TARGET_SOCKET, SourceTable, check_against_source, discover
from .compile import CompiledPolicy, compile_policy
from .hmacs import Subkeys
from .methods import output_space
from .portable import Sealer
from .portable import orphans as count_orphans
from .report import render_html
from .staging import (
    PgFacts,
    StagingError,
    connect,
    deliver_excel,
    deliver_postgres,
    read_facts,
    stage_excel,
    stage_postgres,
    staging_folder,
    where,
)
from .subset import SubsetPlan, select

# Quasi-identifiers (docs/guide.md): a kept or generalized column of a table with at least 100 rows whose
# (approximate) number of distinct values is at least 2 and at most 20% of the rows. Such a column doesn't
# identify a row by itself but narrows it down (a city, a birth year, a postcode prefix); a column with more
# distinct values is close to unique (an amount, a kept id) and one with a single value says nothing.
QI_MIN_ROWS = 100
QI_MAX_DISTINCT_SHARE = 0.20
REPORTS = ("report.html", "report.json")
FAILED_REPORTS = ("failed-report.html", "failed-report.json")
_IGNORED_ENTRIES = {".DS_Store"}


class MaskFailed(Exception):
    """The policy can't run: `problems` say why (errors and warnings, safe to show)."""

    def __init__(self, problems: list[Problem]) -> None:
        self.problems = problems
        super().__init__("; ".join(p.message for p in problems if p.severity == "error"))


@dataclass
class Prepared:
    policy: MaskingPolicy
    policy_bytes: bytes
    key: MasterKey | None
    source: Path
    tables: dict[str, SourceTable]
    problems: list[Problem] = field(default_factory=list)


@dataclass(frozen=True)
class MaskOutcome:
    report: dict[str, Any]
    out: Path
    ok: bool
    error: str | None  # the first failure, for the one ERROR line


def folder_of(base: Path, text: str) -> Path:
    path = Path(text).expanduser()
    return path if path.is_absolute() else base / path


def prepare(
    policy_path: Path,
    *,
    source: Path | None = None,
    environ: Mapping[str, str] | None = None,
    need_key: bool = True,
) -> Prepared:
    """Load and check a policy against its source. Raises `MaskFailed` when there is an error.

    Relative folders in the policy are relative to the policy file's folder; `source` overrides the source
    folder. Without `need_key` (an export, which never touches the key) the key reference isn't resolved.
    """
    try:
        data = policy_path.read_bytes()
        policy = load_policy_file(policy_path)
    except SpecError as err:
        raise MaskFailed(err.problems) from None
    except (OSError, UnicodeDecodeError) as err:
        reason = os.strerror(err.errno) if isinstance(err, OSError) and err.errno else type(err).__name__
        raise MaskFailed([Problem("error", "file_error", f"cannot read {policy_path}: {reason}")]) from None
    problems = validate_policy(policy)
    key: MasterKey | None = None
    if need_key and not any(p.severity == "error" for p in problems):
        try:
            key = resolve_key(policy.spec.key, environ)
        except KeyRefError as err:
            problems.append(Problem("error", "key", str(err)))
    if source is None and policy.spec.source.folder is None:  # a staged source: `opened` gives the folder
        raise MaskFailed([Problem("error", "source", "a postgres source needs safetwin mask or check")])
    folder = source if source is not None else folder_of(policy_path.parent, str(policy.spec.source.folder))
    tables: dict[str, SourceTable] = {}
    if not any(p.code in ("unknown_table", "unknown_column") for p in problems if p.severity == "error"):
        tables, found = discover(policy, folder)
        problems += found
        problems += check_against_source(policy, tables)
    if any(p.severity == "error" for p in problems):
        raise MaskFailed(problems)
    return Prepared(policy, data, key, folder, tables, problems)


def check_policy(
    policy_path: Path, *, source: Path | None = None, environ: Mapping[str, str] | None = None
) -> list[Problem]:
    """Every problem of a policy and its source (an empty list: it can run). A Postgres or Excel source is
    staged without its rows: the check needs the columns and types only."""
    try:
        with opened_source(policy_path, source=source, environ=environ, schema_only=True) as opened:
            return prepare(policy_path, source=opened.folder, environ=environ).problems
    except MaskFailed as err:
        return err.problems


# --- staged sources and targets (Postgres, Excel: `staging.py`) -----------------------------------------


@dataclass
class Opened:
    """The source as the engine reads it: `folder` (None: the policy's own folder), and for Postgres the
    names the database gave (keys, foreign keys) and where it is, for messages and the report."""

    folder: Path | None
    facts: PgFacts | None = None
    where: str | None = None


def _load(policy_path: Path) -> MaskingPolicy:
    try:
        return load_policy_file(policy_path)
    except SpecError as err:
        raise MaskFailed(err.problems) from None
    except (OSError, UnicodeDecodeError) as err:
        reason = os.strerror(err.errno) if isinstance(err, OSError) and err.errno else type(err).__name__
        raise MaskFailed([Problem("error", "file_error", f"cannot read {policy_path}: {reason}")]) from None


@contextmanager
def opened_source(
    policy_path: Path,
    *,
    source: Path | None = None,
    environ: Mapping[str, str] | None = None,
    schema_only: bool = False,
) -> Iterator[Opened]:
    """The policy's source, staged to Parquet in a private folder when it is Postgres or Excel (only the
    columns and types with `schema_only`); the folder is removed on the way out. Raises `MaskFailed`."""
    policy = _load(policy_path)
    spec = policy.spec.source
    if not staged_source(spec):
        yield Opened(source)
        return
    tables = list(policy.spec.tables)
    limit = 0 if schema_only else None
    with staging_folder() as folder:
        if spec.postgres is not None:
            if source is not None:
                raise MaskFailed(
                    [Problem("error", "source", "--source is for a folder source, not postgres")]
                )
            try:
                url = resolve_secret(spec.postgres, "source database URL", environ)
                connection = connect(url, read_only=True)
            except (KeyRefError, StagingError) as err:
                raise MaskFailed([Problem("error", "source_postgres", str(err))]) from None
            try:
                facts = read_facts(connection, spec.pg_schema)
                missing = [t for t in tables if t not in facts.tables]
                if missing:
                    raise MaskFailed(
                        [
                            Problem(
                                "error",
                                "unknown_table",
                                f"table '{t}' is not in the schema {spec.pg_schema} of {where(url)}",
                            )
                            for t in missing
                        ]
                    )
                stage_postgres(connection, spec.pg_schema, tables, folder, limit=limit)
            except StagingError as err:
                raise MaskFailed([Problem("error", "source_postgres", str(err))]) from None
            finally:
                connection.close()
            yield Opened(folder, facts, f"{where(url)}, schema {spec.pg_schema}")
            return
        base = source if source is not None else folder_of(policy_path.parent, str(spec.folder))
        try:
            stage_excel(base, folder, limit=limit)
        except StagingError as err:
            raise MaskFailed([Problem("error", "source_excel", str(err))]) from None
        yield Opened(folder)


def mask(
    policy_path: Path,
    *,
    source: Path | None = None,
    out: Path | None = None,
    strict: bool = False,
    replace: bool = False,
    environ: Mapping[str, str] | None = None,
    on_event: Callable[[ProgressEvent], None] | None = None,
    memory_limit_bytes: int | None = None,
) -> MaskOutcome:
    """Mask the source as the policy says (`_mask_files` does the run). A Postgres or Excel source is staged
    first; a Postgres or Excel target gets the twin only after every check has passed, and its report goes
    to the target folder. Raises `MaskFailed` as `_mask_files` does."""
    policy = _load(policy_path)
    target = policy.spec.target
    with opened_source(policy_path, source=source, environ=environ) as opened:
        run = partial(
            _mask_files,
            policy_path,
            strict=strict,
            environ=environ,
            on_event=on_event,
            memory_limit_bytes=memory_limit_bytes,
            source_label=opened.where,
        )
        if not staged_target(target):
            return run(source=opened.folder, out=out, replace=replace)
        final = out if out is not None else folder_of(policy_path.parent, target.folder)
        _deliverable(final, replace)
        connection = None
        url = ""
        if target.postgres is not None:
            try:
                url = resolve_secret(target.postgres, "target database URL", environ)
            except KeyRefError as err:
                raise MaskFailed([Problem("error", "target_postgres", str(err))]) from None
            if (
                policy.spec.source.postgres is not None
                and opened.where == f"{where(url)}, schema {target.pg_schema}"
            ):
                raise MaskFailed(
                    [Problem("error", "target_postgres", "the target schema must not be the source schema")]
                )
        with staging_folder() as staged:
            outcome = run(source=opened.folder, out=staged / "twin", replace=False)
            report = outcome.report
            delivered: dict[str, Any] = {}
            if outcome.ok:
                tables = sorted(report["tables"])
                try:
                    if target.postgres is not None:
                        assert target.pg_schema is not None
                        connection = connect(url, read_only=False)
                        try:
                            rows = deliver_postgres(
                                staged / "twin",
                                tables,
                                connection,
                                target.pg_schema,
                                opened.facts,
                                replace=replace,
                            )
                        finally:
                            connection.close()
                        delivered = {"to": where(url), "schema": target.pg_schema, "tables": rows}
                        report["files"] = []
                    else:
                        final.mkdir(parents=True, exist_ok=True)
                        files = deliver_excel(staged / "twin", tables, final)
                        report["files"] = [_file_entry(path, final) for path in files]
                        delivered = {
                            "to": "Excel workbooks",
                            "tables": {t: report["tables"][t]["rows_out"] for t in tables},
                        }
                except (StagingError, OSError) as err:
                    message = (
                        str(err)
                        if isinstance(err, StagingError)
                        else f"cannot write the twin ({type(err).__name__})"
                    )
                    report["status"] = "failed"
                    report["files"] = []
                    report["errors"].append(message)
            else:
                report["files"] = []
            if delivered:
                report["delivered"] = delivered
            report["ended_at"] = _now()
            final.mkdir(parents=True, exist_ok=True)
            failed = report["status"] != "ok"
            for name, text in zip(
                REPORTS,
                (render_html(report), json.dumps(report, indent=2, ensure_ascii=False) + "\n"),
                strict=True,
            ):
                _write_text(final / name, text)
            return MaskOutcome(report, final, not failed, report["errors"][0] if failed else None)


def _deliverable(final: Path, replace: bool) -> None:
    """The folder that gets an Excel twin or a Postgres twin's report: empty, or `replace` is given."""
    if final.exists() and not final.is_dir():
        raise MaskFailed([Problem("error", "target_folder", f"{final} is not a folder")])
    if final.exists() and not replace:
        entries = [p for p in final.iterdir() if p.name not in _IGNORED_ENTRIES]
        if entries:
            raise MaskFailed(
                [
                    Problem(
                        "error",
                        "target_folder",
                        f"the target folder {final} is not empty: choose an empty folder, or give --replace",
                    )
                ]
            )


def _file_entry(path: Path, base: Path) -> dict[str, Any]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"path": str(path.relative_to(base)), "bytes": path.stat().st_size, "sha256": digest}


# --- facts and checks ----------------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _scan_input(policy: MaskingPolicy, table: SourceTable) -> pl.LazyFrame:
    if engine_format(policy.spec.source) == "parquet":
        return pl.scan_parquet(table.files, glob=False, hive_partitioning=False)
    return pl.scan_csv(table.files, separator=policy.spec.source.delimiter, infer_schema=False, glob=False)


def _scan_output(fmt: str, files: list[Path]) -> pl.LazyFrame:
    if fmt == "csv":
        return pl.scan_csv(files, infer_schema=False, glob=False)
    return pl.scan_parquet(files, glob=False, hive_partitioning=False)


def uniqueness_candidates(policy: MaskingPolicy, compiled: CompiledPolicy) -> dict[str, list[str]]:
    """Per table, the columns to check for uniqueness: pseudonymized ones, fake emails and relationship
    targets. (Other fake kinds have small value spaces on purpose: a unique name column gets repeats.)"""
    out: dict[str, list[str]] = {}
    targets = {(r.to_table, r.to_column) for r in relationships(policy)}
    for table, steps in compiled.columns.items():
        for column, step in steps.items():
            if isinstance(step.spec, Drop):
                continue
            if (
                isinstance(step.spec, Pseudonymize)
                or (isinstance(step.spec, Fake) and step.spec.kind == "email")
                or (table, column) in targets
            ):
                out.setdefault(table, []).append(column)
    return out


def _input_facts(
    policy: MaskingPolicy, tables: Mapping[str, SourceTable], candidates: Mapping[str, list[str]]
) -> tuple[dict[str, int], dict[tuple[str, str], bool]]:
    """Rows of each input table, and whether each candidate column is unique and has no null."""
    rows: dict[str, int] = {}
    unique: dict[tuple[str, str], bool] = {}
    for table, source in tables.items():
        columns = candidates.get(table, [])
        exprs = [pl.len().alias("rows")]
        for i, column in enumerate(columns):
            exprs += [pl.col(column).n_unique().alias(f"u{i}"), pl.col(column).null_count().alias(f"n{i}")]
        row = _scan_input(policy, source).select(exprs).collect(engine="streaming").row(0, named=True)
        rows[table] = int(row["rows"])
        for i, column in enumerate(columns):
            unique[(table, column)] = row[f"n{i}"] == 0 and row[f"u{i}"] == rows[table]
    return rows, unique


def expected_detectors(spec: Method) -> set[str]:
    """Detectors a method's own output triggers on purpose, which the residual scan doesn't look for there."""
    match spec:
        case Encrypt(algorithm="ff1", alphabet="alphanumeric"):
            return set(DETECTORS)  # it keeps every shape on purpose
        case Encrypt(algorithm="ff1"):
            # Digits only: numbers keep their shape on purpose; letters stay, so emails are still looked for.
            return {"phone", "card", "iban", "ipv4", "birth_date"}
        case DateShift():
            return {"birth_date"}
        case Generalize(to=to) if to is not None:
            return {"birth_date"}
    return set()


def _remove_outputs(results: list[StageResult], out: Path, run_id: str) -> None:
    """Remove every data file and manifest of the run, and the folders it left empty."""
    paths = [commit.path for result in results for commit in result.files]
    _remove_files(paths + [result.manifest for result in results], out)


def _remove_files(paths: list[Path], out: Path) -> None:
    """Remove `paths`, then the folders below `out` they leave empty."""
    folders: set[Path] = set()
    for path in paths:
        path.unlink(missing_ok=True)
        folders.add(path.parent)
    real_out = Path(os.path.realpath(out))
    for folder in sorted(folders, key=lambda p: len(p.parts), reverse=True):
        current = folder
        while current != real_out and current.is_relative_to(real_out):
            try:
                current.rmdir()  # only when empty
            except OSError:
                break
            current = current.parent


def _refuse(code: str, message: str) -> MaskFailed:
    return MaskFailed([Problem("error", code, message)])


def _previous_twin(target: Path, replace: bool) -> list[Path] | None:
    """The files of the earlier twin in `target` (data, manifests, reports), or None when it is empty. Raises
    `MaskFailed` when it isn't empty and can't be replaced."""
    entries = [name for name in os.listdir(target) if name not in _IGNORED_ENTRIES]
    if not entries:
        return None
    if not replace:
        raise _refuse(
            "target_folder",
            f"the target folder {target} is not empty: choose an empty folder, or give --replace to replace "
            "the twin in it",
        )
    real = Path(os.path.realpath(target))
    try:
        report = json.loads((target / "report.json").read_text(encoding="utf-8"))
        run_id = report["run_id"]
        listed = [real / f["path"] for f in report["files"]]
        tables = list(report["tables"])
    except (OSError, ValueError, KeyError, TypeError):
        raise _refuse(
            "target_folder",
            f"--replace: {target} has no readable safetwin report.json, so nothing in it is replaced. "
            "Choose an empty folder",
        ) from None
    if not isinstance(run_id, str) or not run_id.isalnum():
        raise _refuse("target_folder", f"--replace: the report.json in {target} has no valid run_id")
    paths: list[Path] = []
    for path in listed:
        if not Path(os.path.realpath(path)).is_relative_to(real) or path == real:
            raise _refuse("target_folder", f"--replace: the report.json in {target} lists a file outside it")
        paths.append(path)
    for table in tables:
        folder = real / str(table) / MANIFEST_DIR
        if folder.is_relative_to(real) and folder.is_dir():
            paths += sorted(folder.glob(f"run=*_{run_id}.json"))
    return paths + [real / name for name in (*FAILED_REPORTS, *REPORTS)]


def _write_text(path: Path, text: str) -> None:
    with CommitWriter(path, overwrite=True) as writer:
        writer.write(text.encode("utf-8"))
        writer.commit()


def engine_version() -> str:
    try:
        return version("safetwin")
    except PackageNotFoundError:
        return "unknown"


# --- the run -----------------------------------------------------------------------------------------------


def _mask_files(
    policy_path: Path,
    *,
    source: Path | None = None,
    out: Path | None = None,
    strict: bool = False,
    replace: bool = False,
    environ: Mapping[str, str] | None = None,
    on_event: Callable[[ProgressEvent], None] | None = None,
    memory_limit_bytes: int | None = None,
    source_label: str | None = None,
) -> MaskOutcome:
    """Mask a folder source into a folder target (`source_label` names a staged source in the report).
    Raises `MaskFailed` before anything is written when the policy or source has an error, or the target
    folder isn't empty (without `replace`); other errors (and Ctrl-C) propagate after the run's output is
    removed."""
    started_at = _now()
    prepared = prepare(policy_path, source=source, environ=environ)
    policy, key = prepared.policy, prepared.key
    assert key is not None  # prepare raises when the key can't be resolved
    target = out if out is not None else folder_of(policy_path.parent, policy.spec.target.folder)
    target_format = "parquet" if staged_target(policy.spec.target) else policy.spec.target.format
    if os.path.realpath(target) == os.path.realpath(prepared.source):
        raise MaskFailed(
            [Problem("error", "target_folder", "the target folder must not be the source folder")]
        )
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        reason = os.strerror(err.errno) if err.errno else type(err).__name__
        raise MaskFailed([Problem("error", "target_folder", f"cannot create {target}: {reason}")]) from None
    previous = _previous_twin(target, replace)

    subset: SubsetPlan | None = None
    if policy.spec.subset is not None:
        subset = select(policy, key, lambda t: _scan_input(policy, prepared.tables[t]))
    filtered = frozenset(t for t, f in (subset.filters.items() if subset else ()) if f is not None)
    compiled = compile_policy(policy, prepared.tables, subset_tables=filtered)
    candidates = uniqueness_candidates(policy, compiled)
    rows_in, unique_in = _input_facts(policy, prepared.tables, candidates)
    subkeys = Subkeys(key, compiled.subkey_uses)
    run_id = f"r{secrets.token_hex(4)}"
    plan = plan_pipeline(
        compiled.pipeline,
        {SOURCE_SOCKET: prepared.source, TARGET_SOCKET: target},
        run_id=run_id,
        on_event=on_event,
        memory_limit_bytes=memory_limit_bytes,
        subkeys=subkeys,
        subset_filters={t: f for t, f in (subset.filters.items() if subset else ()) if f is not None},
    )
    del subkeys  # the plan's context holds them for the run, in memory
    results: list[StageResult] = []
    pending: list[Path] = []  # this run's report files not yet in place
    placed: list[Path] = []  # this run's report files in place, while the run can still fail
    try:
        for planned in plan.stages:
            results.append(run_planned_stage(plan, planned))
        report = _checks_and_report(
            prepared, compiled, results, plan.ctx.mask_stats, rows_in, unique_in, candidates,
            target, target_format, run_id, started_at, strict, subset,
        )  # fmt: skip
        if source_label is not None:
            report["source"] = source_label
        failed = report["status"] != "ok"
        names = REPORTS
        if failed:
            _remove_outputs(results, target, run_id)
            report["files"] = []
            if previous is None:
                report["errors"].append(
                    "the output was removed because a check failed; only this report is left"
                )
            else:
                names = FAILED_REPORTS
                report["errors"].append(
                    "the output of this run was removed because a check failed; the earlier twin in the "
                    "folder is untouched"
                )
        report["ended_at"] = _now()
        texts = (render_html(report), json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        for name, text in zip(names, texts, strict=True):
            pending.append(target / f".{name}.{run_id}.pending")
            _write_text(pending[-1], text)
        if not failed and previous is not None:
            # The earlier report.json goes first, so no report claims files that are being removed.
            _remove_files([target / "report.json", *previous], target)
        for temp, name in zip(list(pending), names, strict=True):
            os.replace(temp, target / name)
            pending.remove(temp)
            placed.append(target / name)
        placed.clear()
    except BaseException:
        _remove_outputs(results, target, run_id)
        for path in pending + placed:
            path.unlink(missing_ok=True)
        for name in (*REPORTS, *FAILED_REPORTS):
            remove_temporary_files(target / f".{name}.{run_id}.pending", target, run_id)
        raise
    return MaskOutcome(report, target, not failed, report["errors"][0] if failed else None)


def _checks_and_report(
    prepared: Prepared,
    compiled: CompiledPolicy,
    results: list[StageResult],
    stats: Mapping[str, Any],
    rows_in: Mapping[str, int],
    unique_in: Mapping[tuple[str, str], bool],
    candidates: Mapping[str, list[str]],
    out: Path,
    target_format: str,
    run_id: str,
    started_at: str,
    strict: bool,
    subset: SubsetPlan | None = None,
) -> dict[str, Any]:
    policy = prepared.policy
    real_out = Path(os.path.realpath(out))
    outputs = {
        table: _scan_output(target_format, [f.path for f in r.files])
        for table, r in zip(compiled.columns, results, strict=True)
    }
    errors: list[str] = []
    warnings = [p.message for p in prepared.problems if p.severity == "warning"]
    tables: dict[str, Any] = {}
    uniqueness: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for (table, steps), result in zip(compiled.columns.items(), results, strict=True):
        frame = outputs[table]
        classes = {c: column_class(s.spec) for c, s in steps.items() if not isinstance(s.spec, Drop)}
        rows_out = next(reversed(result.rows_per_node.values()))
        # Distinct counts after masking: exact for uniqueness, approximate (bounded memory) for the
        # quasi-identifiers.
        qi_columns = [c for c, s in steps.items() if isinstance(s.spec, Keep | Generalize)]
        exprs = [pl.col(c).n_unique().alias(f"u{i}") for i, c in enumerate(candidates.get(table, []))]
        exprs += [pl.col(c).approx_n_unique().alias(f"q{i}") for i, c in enumerate(qi_columns)]
        facts = frame.select(exprs).collect(engine="streaming").row(0, named=True) if exprs else {}
        for i, column in enumerate(candidates.get(table, [])):
            if not unique_in[(table, column)]:
                continue
            unique_out = facts[f"u{i}"] == rows_out
            uniqueness.append({"column": f"{table}.{column}", "unique_in": True, "unique_out": unique_out})
            if not unique_out:
                errors.append(_not_unique(table, column, steps[column].spec))
        columns: dict[str, Any] = {}
        for column, step in steps.items():
            entry: dict[str, Any] = {"method": step.spec.method, "class": column_class(step.spec)}
            params = method_params(step.spec)
            if params:
                entry["params"] = params
            if column in qi_columns:
                distinct = int(facts[f"q{qi_columns.index(column)}"] or 0)
                if rows_out >= QI_MIN_ROWS and 2 <= distinct <= QI_MAX_DISTINCT_SHARE * rows_out:
                    entry["quasi_identifier"] = True
            columns[column] = entry
        tables[table] = {"rows_in": rows_in[table], "rows_out": rows_out, "columns": columns}
        expected = {c: expected_detectors(s.spec) for c, s in steps.items()}
        schema = prepared.tables[table].schema
        spaces = {c: p for c, s in steps.items() if c in classes and (p := output_space(s.spec, schema[c]))}
        findings += residual_scan(table, frame, classes, expected=expected, output_space=spaces)
        table_stats = stats.get(f"mask_{table}")
        for column, reasons in table_stats.snapshot().items() if table_stats is not None else ():
            for reason, count in reasons.items():
                warnings.append(_stat_warning(table, column, reason, count))

    checked_relationships = []
    for rel in relationships(policy):
        orphans = count_orphans(
            outputs[rel.from_table], rel.from_column, outputs[rel.to_table], rel.to_column
        )
        checked_relationships.append(
            {
                "from": f"{rel.from_table}.{rel.from_column}",
                "to": f"{rel.to_table}.{rel.to_column}",
                "orphans": orphans,
            }
        )
        if orphans:
            errors.append(f"{redacted(rel.text)}: {orphans} row(s) point at no row after masking")

    for finding in findings:
        where = f"{finding.table}.{redacted(finding.column)}"
        what = f"{where}: {finding.count} value(s) look like {finding.detector}"
        if finding.detector == "outside_output_space":
            errors.append(
                f"residual scan: {where}: {finding.count} value(s) are not what its method makes, so input "
                "values may have been let through"
            )
        elif finding.level == "error":
            errors.append(f"residual scan: {what}, in a column that was masked")
        else:
            warnings.append(f"residual scan: {what}, in a kept column")
    if strict and warnings and not errors:
        errors.append(f"--strict: {len(warnings)} warning(s): {warnings[0]}")

    files = [
        {"path": str(commit.path.relative_to(real_out)), "bytes": commit.bytes, "sha256": commit.sha256}
        for result in results
        for commit in result.files
    ]
    return {
        "report_version": 1,
        "run_id": run_id,
        "status": "failed" if errors else "ok",
        "policy": {"name": policy.metadata.name, "sha256": hashlib.sha256(prepared.policy_bytes).hexdigest()},
        "key_fingerprint": prepared.key.fingerprint if prepared.key else None,
        # The access key's, when a column is encrypted: `unmask` checks it before it decrypts ff1, which
        # (not being authenticated) would turn a wrong key into wrong values rather than an error.
        "access_fingerprint": (
            Sealer(prepared.key.access_key()).fingerprint
            if prepared.key
            and any(isinstance(s.spec, Encrypt) for c in compiled.columns.values() for s in c.values())
            else None
        ),
        "engine_version": engine_version(),
        "started_at": started_at,
        "ended_at": None,
        "subset": subset.summary() if subset is not None else None,
        "tables": tables,
        "relationships": checked_relationships,
        "uniqueness": uniqueness,
        "residual_scan": {"findings": [f.as_dict() for f in findings]},
        "files": files,
        "warnings": warnings,
        "errors": errors,
    }


def _stat_warning(table: str, column: str, reason: str, count: int) -> str:
    where = f"{table}.{redacted(column)}"
    if reason == "below_first_bin":
        return f"{where}: {count} value(s) were below the first bin and became its lower bound"
    if reason == "invalid_ip":
        return f"{where}: {count} value(s) were not IP addresses and became null"
    if reason == "null_entity":
        return f"{where}: {count} date(s) had no entity (a null entity column) and became null"
    if reason == "too_short":
        return (
            f"{where}: {count} value(s) were too short for ff1 (6 digits, or 4 letters or digits) and became "
            "null"
        )
    return f"{where}: {count} value(s): {reason}"


def _not_unique(table: str, column: str, spec: Method) -> str:
    where = f"{table}.{redacted(column)} was unique in the input but not after masking"
    if isinstance(spec, Pseudonymize):
        return f"{where}: two values got the same pseudonym. Use format: hex or format: uuid (128-bit)"
    if isinstance(spec, Fake):
        return f"{where}: two values got the same fake {spec.kind}. Use pseudonymize for a unique column"
    return (
        f"{where}: it is a relationship target, and {spec.method} doesn't keep its values distinct. Keep or "
        "pseudonymize the columns of a relationship"
    )
