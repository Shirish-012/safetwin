"""`safetwin demo`, `key`, `scan`, `check`, `mask`, `unmask` and `export` (docs/guide.md).

Exit codes: 0 success; 1 the job failed (one `ERROR` line on stderr saying what and where); 2 bad usage; 130
interrupted (nothing half-written). Progress and problems go to stderr, the summary to stdout. No output ever
holds a data value or a key: only names, counts, settings and the key's fingerprint. The data libraries are
imported when a command runs, not when `safetwin` starts.
"""

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, NoReturn

import typer

from safetwin.keys import (
    KeyRefError,
    MasterKey,
    is_reference,
    new_key,
    new_key_file,
    resolve_key,
    write_key_file,
)
from safetwin.spec.io import SpecError
from safetwin.spec.policy import load_policy_file
from safetwin.spec.validate import Problem, redacted

if TYPE_CHECKING:
    from safetwin.masking.portable import Sealer
    from safetwin.masking.unmask import Unmasked

key_app = typer.Typer(
    help="Make a masking key or an access key, or show the fingerprint of the key a policy refers to.",
    no_args_is_help=True,
    rich_markup_mode="markdown",
    pretty_exceptions_show_locals=False,
)

PolicyFile = Annotated[
    Path, typer.Argument(exists=True, dir_okay=False, readable=False, help="The masking policy (YAML).")
]


def _fail(message: str, status: int = 1) -> NoReturn:
    typer.echo(f"ERROR {message}", err=True)
    raise typer.Exit(status)


def _problem_lines(problems: list[Problem]) -> list[str]:
    return [f"{'ERROR' if p.severity == 'error' else 'WARN'} [{p.code}] {p.message}" for p in problems]


def _os_reason(err: OSError) -> str:
    reason = os.strerror(err.errno) if err.errno else type(err).__name__
    return f"{reason}: {err.filename}" if err.filename else reason


# --- safetwin key ----------------------------------------------------------------------------------------


@key_app.command("new")
def key_new(
    file: Annotated[
        Path | None,
        typer.Option("--file", metavar="PATH", help="Write the key to this new file (mode 0600)."),
    ] = None,
    print_key: Annotated[
        bool, typer.Option("--print", help="Print the key on stdout instead, for a CI secret store.")
    ] = False,
) -> None:
    """Make a new 32-byte key from the operating system's random source and say how to use it."""
    if (file is None) == (not print_key):
        raise typer.BadParameter("give either --file PATH or --print", param_hint="--file / --print")
    if print_key:
        key = new_key()
        typer.echo(
            f"WARN the key is printed on stdout (fingerprint {key.fingerprint}): put it straight into a "
            "secret store and refer to it with env://NAME; don't leave it in a file others can read",
            err=True,
        )
        typer.echo(key.hex_for_key_file())
        return
    assert file is not None
    try:
        key = new_key_file(file)
    except KeyRefError as err:
        _fail(str(err))
    shown = file.expanduser()
    reference = str(file) if str(file).startswith("~") or file.is_absolute() else str(shown.resolve())
    typer.echo(f"key written to {shown} (mode 0600); fingerprint {key.fingerprint}")
    typer.echo(f"use it with:  key: file://{reference}")


@key_app.command("from-passphrase")
def key_from_passphrase_command(
    file: Annotated[
        Path | None,
        typer.Option("--file", metavar="PATH", help="Write the key to this new file (mode 0600)."),
    ] = None,
    print_key: Annotated[
        bool, typer.Option("--print", help="Print the key on stdout instead, for a CI secret store.")
    ] = False,
    from_env: Annotated[
        str | None,
        typer.Option(
            "--from-env", metavar="NAME", help="Read the passphrase from this environment variable."
        ),
    ] = None,
) -> None:
    """Make the key of a passphrase (asked twice, not shown), the same on every computer.

    scrypt turns the passphrase into the key, with a fixed salt so that the same passphrase always gives the
    same key: a weak passphrase can be guessed, so use several words (at least 12 characters). A key file
    from `safetwin key new` is stronger.
    """
    from safetwin.keys import key_from_passphrase, write_key_file

    if (file is None) == (not print_key):
        raise typer.BadParameter("give either --file PATH or --print", param_hint="--file / --print")
    if from_env is not None:
        passphrase = os.environ.get(from_env, "")
        if not passphrase:
            _fail(f"the environment variable {from_env} is not set")
    else:
        passphrase = typer.prompt("Passphrase", hide_input=True, confirmation_prompt=True, err=True)
    try:
        key = key_from_passphrase(passphrase)
    except KeyRefError as err:
        _fail(str(err))
    if print_key:
        typer.echo(f"WARN the key is printed on stdout (fingerprint {key.fingerprint})", err=True)
        typer.echo(key.hex_for_key_file())
        return
    assert file is not None
    try:
        write_key_file(file, key.hex_for_key_file())
    except KeyRefError as err:
        _fail(str(err))
    typer.echo(f"key written to {file.expanduser()} (mode 0600); fingerprint {key.fingerprint}")


@key_app.command("fingerprint")
def key_fingerprint(policy: PolicyFile) -> None:
    """Show the fingerprint of the key that the policy refers to (never the key)."""
    try:
        reference = load_policy_file(policy).spec.key
        key = resolve_key(reference)
    except SpecError as err:
        _fail("; ".join(f"[{p.code}] {p.message}" for p in err.problems))
    except KeyRefError as err:
        _fail(str(err))
    except OSError as err:
        _fail(f"cannot read {policy}: {_os_reason(err)}")
    typer.echo(key.fingerprint)


def _policy_key(policy: Path) -> MasterKey:
    try:
        return resolve_key(load_policy_file(policy).spec.key)
    except SpecError as err:
        _fail("; ".join(f"[{p.code}] {p.message}" for p in err.problems))
    except KeyRefError as err:
        _fail(str(err))
    except OSError as err:
        _fail(f"cannot read {policy}: {_os_reason(err)}")


@key_app.command("access")
def key_access(
    policy: PolicyFile,
    file: Annotated[
        Path | None,
        typer.Option("--file", metavar="PATH", help="Write the access key to this new file (mode 0600)."),
    ] = None,
    print_key: Annotated[
        bool, typer.Option("--print", help="Print the access key on stdout instead, for a secret store.")
    ] = False,
) -> None:
    """Make the access key of the key a policy refers to, for the people who may read encrypted columns.

    The access key reads back every column that `encrypt` masked with this key, in every twin, and nothing
    else: one-way columns stay unreadable, and the masking key can't be found from it.
    """
    from safetwin.masking.portable import Sealer

    if (file is None) == (not print_key):
        raise typer.BadParameter("give either --file PATH or --print", param_hint="--file / --print")
    access = _policy_key(policy).access_key()
    fingerprint = Sealer(access).fingerprint
    if print_key:
        typer.echo(
            f"WARN the access key is printed on stdout (fingerprint {fingerprint}): whoever has it can read "
            "every encrypted column; share it only through a secret store or a password manager",
            err=True,
        )
        typer.echo(access.hex())
        return
    assert file is not None
    try:
        write_key_file(file, access.hex())
    except KeyRefError as err:
        _fail(str(err))
    shown = file.expanduser()
    typer.echo(f"access key written to {shown} (mode 0600); fingerprint {fingerprint}")
    typer.echo(f"to read a twin:  safetwin unmask SAFE_FOLDER --key file://{shown.resolve()} --out readable")


# --- safetwin demo -----------------------------------------------------------------------------------------


def demo(
    folder: Annotated[Path, typer.Argument(help="Where to write it: the tables go to FOLDER/data.")],
    csv: Annotated[bool, typer.Option("--csv", help="Also write the tables as CSV.")] = False,
) -> None:
    """Write a made-up shop to try safetwin on: customers and orders with planted personal data."""
    from safetwin.demo import write

    data = folder / "data"
    if data.exists() and any(data.iterdir()):
        _fail(f"{data} is not empty: choose another folder")
    try:
        customers, orders = write(data, csv=csv)
    except OSError as err:
        _fail(f"cannot write {data}: {_os_reason(err)}")
    typer.echo(f"wrote {data}: customers ({customers:,} rows) and orders ({orders:,} rows), all made up")
    typer.echo(f"next:  cd {folder} && safetwin scan data -o masking.yaml")


# --- safetwin scan ---------------------------------------------------------------------------------------


def scan(
    source: Annotated[
        Path | None,
        typer.Argument(exists=True, file_okay=False, help="The folder of CSV, Parquet or Excel files."),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("-o", "--output", metavar="FILE", help="Write the draft policy here (else stdout)."),
    ] = None,
    fmt: Annotated[
        str | None,
        typer.Option(
            "--format", metavar="csv|parquet|xlsx", help="Which files to scan (default: Parquet, then CSV)."
        ),
    ] = None,
    delimiter: Annotated[str, typer.Option("--delimiter", help="The CSV delimiter.")] = ",",
    key: Annotated[
        str, typer.Option("--key", metavar="REF", help="The key reference the draft names.")
    ] = "env://SAFETWIN_KEY",
    target: Annotated[
        str, typer.Option("--target", metavar="DIR", help="The target folder the draft names.")
    ] = "./safe",
    force: Annotated[bool, typer.Option("--force", help="Replace the output file if it exists.")] = False,
    reversible: Annotated[
        bool,
        typer.Option(
            "--reversible", help="Draft encrypt for every column to mask, so the access key reads it back."
        ),
    ] = False,
    algorithm: Annotated[
        str,
        typer.Option(
            "--algorithm",
            metavar="NAME",
            help="With --reversible: aes-siv (every column; the default), aes-gcm (hides repeats; linked "
            "columns stay aes-siv) or auto (ff1 for phone and card numbers, so they keep their format).",
        ),
    ] = "aes-siv",
    postgres: Annotated[
        str | None,
        typer.Option(
            "--postgres",
            metavar="REF",
            help="Scan a Postgres schema instead: its URL as env://NAME or file://PATH.",
        ),
    ] = None,
    pg_schema: Annotated[str, typer.Option("--schema", help="The Postgres schema to scan.")] = "public",
) -> None:
    """Profile every table in a folder and draft a masking policy, with the reasons as comments.

    The draft and the summary hold names, types, counts and shares, never a value. Review every column before
    you mask: detection only suggests.
    """
    from safetwin.dataplane.writer import CommitWriter
    from safetwin.keys import resolve_secret
    from safetwin.masking.scan import ScanError, make_reversible, policy_name, render, scan_postgres
    from safetwin.masking.scan import scan as run_scan

    if (source is None) == (postgres is None):
        raise typer.BadParameter("give a SOURCE folder or --postgres REF", param_hint="SOURCE / --postgres")
    if postgres is not None and (
        not is_reference(postgres) or not postgres.startswith(("env://", "file://"))
    ):
        raise typer.BadParameter(
            "give env://NAME or file://PATH, never the URL itself", param_hint="--postgres"
        )
    if fmt not in (None, "csv", "parquet", "xlsx"):
        raise typer.BadParameter("give csv, parquet or xlsx", param_hint="--format")
    if algorithm not in ("aes-siv", "aes-gcm", "auto"):
        raise typer.BadParameter("give aes-siv, aes-gcm or auto", param_hint="--algorithm")
    if algorithm != "aes-siv" and not reversible:
        raise typer.BadParameter("--algorithm goes with --reversible", param_hint="--algorithm")
    if len(delimiter) != 1:
        raise typer.BadParameter("give one character", param_hint="--delimiter")
    if not is_reference(key) or not key.startswith(("env://", "file://")):
        raise typer.BadParameter("give env://NAME or file://PATH, never the key itself", param_hint="--key")
    if output is not None and output.exists() and not force:
        _fail(f"{output} exists already: give --force to replace it")
    try:
        if postgres is not None:
            result = scan_postgres(resolve_secret(postgres, "database URL"), pg_schema)
            folder, name = "", f"{pg_schema.replace('_', '-')}-masking"
        else:
            assert source is not None
            result = run_scan(source, fmt=fmt, delimiter=delimiter)
            folder, name = str(source.resolve()), policy_name(source)
            if output is not None:
                folder = os.path.relpath(source.resolve(), output.resolve().parent)
                folder = folder if folder.startswith(".") else f"./{folder}"
        if reversible:
            make_reversible(result, algorithm=algorithm)
        text = render(
            result,
            source=folder,
            name=name,
            target=target,
            key=key,
            delimiter=delimiter,
            postgres=postgres,
            pg_schema=pg_schema,
        )
    except ScanError as err:
        _fail(str(err))
    except KeyRefError as err:
        _fail(str(err))
    except Exception as err:  # a library error can quote data: say what kind, no more
        _fail(f"the scan failed with {type(err).__name__} (its message can quote data, so it is not shown)")
    for note in result.notes:
        typer.echo(f"NOTE {note}", err=True)
    suggestions = [s for t in result.tables.values() for s in t.suggestions.values()]
    kept = sum(1 for s in suggestions if s.method["method"] == "keep")
    tables = ", ".join(f"{t.name} ({t.rows:,} rows)" for t in result.tables.values())
    typer.echo(
        f"scanned {tables}: {len(suggestions)} columns, {len(suggestions) - kept} masked, {kept} kept; "
        f"{len(result.relationships)} relationship{'' if len(result.relationships) == 1 else 's'}",
        err=True,
    )
    if output is None:
        typer.echo(text, nl=False)
        return
    try:
        with CommitWriter(output, overwrite=force) as writer:
            writer.write(text.encode("utf-8"))
            writer.commit()
    except OSError as err:
        _fail(f"cannot write {output}: {_os_reason(err)}")
    typer.echo(f"wrote {output}: review every column, then run  safetwin check {output}", err=True)


# --- safetwin check --------------------------------------------------------------------------------------


def check(
    policy: PolicyFile,
    source: Annotated[
        Path | None,
        typer.Option("--source", metavar="DIR", help="Read the source here instead of source.folder."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the problems as JSON.")] = False,
) -> None:
    """Check a policy against its source: every table and column named, methods that fit, the key."""
    from safetwin.masking.run import check_policy

    try:
        problems = check_policy(policy, source=source)
    except Exception as err:  # a library error can quote data: say what kind, no more
        _fail(f"the check failed with {type(err).__name__} (its message can quote data, so it is not shown)")
    failed = any(p.severity == "error" for p in problems)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "ok": not failed,
                    "problems": [
                        {"severity": p.severity, "code": p.code, "message": p.message} for p in problems
                    ],
                },
                indent=2,
            )
        )
    else:
        for line in _problem_lines(problems):
            typer.echo(line, err=line.startswith(("ERROR", "WARN")))
        if not failed:
            typer.echo(f"{policy}: ok")
    if failed:
        raise typer.Exit(1)


# --- safetwin export -------------------------------------------------------------------------------------


def export(
    policy: PolicyFile,
    to: Annotated[str, typer.Option("--to", metavar="polars", help="What to export to.")] = "polars",
    output: Annotated[
        Path | None,
        typer.Option("-o", "--output", metavar="FILE", help="Write the code here (else stdout)."),
    ] = None,
    source: Annotated[
        Path | None,
        typer.Option(
            "--source", metavar="DIR", help="Read the source's schemas here instead of source.folder."
        ),
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Replace the output file if it exists.")] = False,
) -> None:
    """Write the policy as a standalone script that does what `safetwin mask` does, without safetwin.

    Reads the source's schemas, never a row, and never the key: the script reads the key itself, from the
    policy's reference. Re-export after changing the policy.
    """
    import hashlib

    from safetwin.dataplane.writer import CommitWriter
    from safetwin.export.to_polars import TARGETS, ExportError, export_polars
    from safetwin.masking.run import MaskFailed, prepare

    if to not in TARGETS:
        raise typer.BadParameter(
            f"give {' or '.join(TARGETS)} (sql, airflow and dagster come later)", param_hint="--to"
        )
    if output is not None and output.exists() and not force:
        _fail(f"{output} exists already: give --force to replace it")
    try:
        from safetwin.spec.policy import staged_source, staged_target

        spec = load_policy_file(policy).spec
        if staged_source(spec.source) or staged_target(spec.target):
            raise ExportError(
                "the Polars export reads and writes CSV or Parquet folders: a Postgres or Excel source or "
                "target can't be exported yet (use safetwin mask for it)"
            )
    except SpecError:
        pass  # prepare says what is wrong
    except ExportError as err:
        _fail(str(err))
    try:
        prepared = prepare(policy, source=source, need_key=False)
        text = export_polars(prepared, policy, hashlib.sha256(prepared.policy_bytes).hexdigest(), output)
    except MaskFailed as err:
        for line in _problem_lines(err.problems):
            typer.echo(line, err=True)
        raise typer.Exit(1) from None
    except ExportError as err:
        _fail(str(err))
    except Exception as err:  # a library error can quote data: say what kind, no more
        _fail(f"the export failed with {type(err).__name__} (its message can quote data, so it is not shown)")
    if output is None:
        typer.echo(text, nl=False)
        return
    try:
        with CommitWriter(output, overwrite=force) as writer:
            writer.write(text.encode("utf-8"))
            writer.commit()
    except OSError as err:
        _fail(f"cannot write {output}: {_os_reason(err)}")
    typer.echo(f"wrote {output}: run it with  python {output} --help", err=True)


# --- safetwin mask ---------------------------------------------------------------------------------------


def _summary(report: dict[str, Any], out: Path) -> list[str]:
    tables = report["tables"]
    width = max((len(name) for name in tables), default=0)
    lines = [f"{name:<{width}}  {t['rows_in']:,} → {t['rows_out']:,} rows" for name, t in tables.items()]
    orphans = sum(r["orphans"] for r in report["relationships"])
    not_unique = sum(1 for u in report["uniqueness"] if not u["unique_out"])
    findings = report["residual_scan"]["findings"]
    masked = sum(1 for f in findings if f["level"] == "error")
    lines.append(
        f"relationships: {len(report['relationships'])} checked, {orphans} orphans · unique columns: "
        f"{len(report['uniqueness'])} checked, {f'{not_unique} not unique' if not_unique else 'all unique'}"
        f" · residual scan: {len(findings)} finding{'' if len(findings) == 1 else 's'}"
        f" ({masked} in masked columns)"
    )
    lines.append(f"report: {out / 'report.html'}")
    return lines


def mask(
    policy: PolicyFile,
    out: Annotated[
        Path | None, typer.Option("--out", metavar="DIR", help="Write here instead of target.folder.")
    ] = None,
    source: Annotated[
        Path | None,
        typer.Option("--source", metavar="DIR", help="Read the source here instead of source.folder."),
    ] = None,
    strict: Annotated[
        bool, typer.Option("--strict", help="Also fail on warnings (a kept column with emails).")
    ] = False,
    replace: Annotated[
        bool,
        typer.Option(
            "--replace", help="Replace the twin already in the target folder, once the new one passes."
        ),
    ] = False,
    memory_limit: Annotated[
        str | None,
        typer.Option("--memory-limit", metavar="SIZE", help="The memory a table may use, such as 2GB."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print report.json on stdout.")] = False,
) -> None:
    """Write the safe twin, report.json and report.html.

    Exits with 1 if the policy doesn't fit the source or a check fails (a collision, an orphan, a residual
    finding in a masked column; with --strict, a warning): then the output is removed and only the report is
    left. Exits with 130 if interrupted: nothing is left. The target folder must be empty, or hold an earlier
    twin and --replace is given: a failed run leaves that twin as it was.
    """
    from safetwin.dataplane.operators import ConfigError, Unsupported
    from safetwin.dataplane.run import PipelineInvalid
    from safetwin.dataplane.spill import SpillError, parse_size
    from safetwin.dataplane.watchdog import MemoryLimitReached
    from safetwin.masking.run import MaskFailed
    from safetwin.masking.run import mask as run_mask

    try:
        limit = None if memory_limit is None else parse_size(memory_limit)
    except ValueError as err:
        raise typer.BadParameter(str(err), param_hint="--memory-limit") from None
    try:
        from safetwin.cli.main import _Progress  # here: main imports this module

        outcome = run_mask(
            policy,
            source=source,
            out=out,
            strict=strict,
            replace=replace,
            memory_limit_bytes=limit,
            on_event=_Progress(),
        )
    except MaskFailed as err:
        errors = [p for p in err.problems if p.severity == "error"]
        more = f" ({len(errors) - 1} more: run safetwin check {policy})" if len(errors) > 1 else ""
        _fail(f"[{errors[0].code}] {errors[0].message}{more}" if errors else "the policy can't run")
    except PipelineInvalid as err:
        _fail("; ".join(f"[{p.code}] {redacted(p.message)}" for p in err.problems if p.severity == "error"))
    except (ConfigError, Unsupported, SpillError, MemoryLimitReached) as err:  # these name things, no data
        _fail(str(err))
    except KeyboardInterrupt:
        _fail("the run was interrupted: nothing was left in the output folder", 130)
    except OSError as err:
        _fail(_os_reason(err))
    except Exception as err:  # Polars and PyArrow messages can quote a row: say what kind of error, no more
        _fail(f"the run failed with {type(err).__name__} (its message can quote data, so it is not shown)")
    report = outcome.report
    for warning in report["warnings"]:
        typer.echo(f"WARN {warning}", err=True)
    if as_json:
        typer.echo(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        for line in _summary(report, outcome.out):
            typer.echo(line)
    if not outcome.ok:
        _fail(outcome.error or "a check failed")


# --- safetwin unmask ---------------------------------------------------------------------------------------


def unmask(
    paths: Annotated[
        list[Path],
        typer.Argument(
            exists=True, help="Masked files, or folders of them (a twin that safetwin mask wrote)."
        ),
    ],
    out: Annotated[Path, typer.Option("--out", metavar="DIR", help="Write the readable files here.")],
    key: Annotated[
        str | None,
        typer.Option("--key", metavar="REF", help="The access key: env://NAME or file://PATH."),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option(
            "--policy", metavar="FILE", exists=True, dir_okay=False, help="Use the key this policy refers to."
        ),
    ] = None,
    replace: Annotated[bool, typer.Option("--replace", help="Replace files already in the folder.")] = False,
) -> None:
    """Read encrypted columns back: write the files with every column that `encrypt` masked decrypted.

    Give the access key (`safetwin key access` makes it), or `--policy` to use the masking key itself. One-way
    columns stay as they are: nothing can read them back. A wrong key or a changed file writes nothing.
    """
    from safetwin.masking.unmask import UnmaskError
    from safetwin.masking.unmask import unmask as run_unmask

    sealer = _sealer(key, policy, "--key", "--policy")
    try:
        results = run_unmask(paths, out, sealer, replace=replace)
    except UnmaskError as err:
        _fail(str(err))
    except OSError as err:
        _fail(f"cannot unmask: {_os_reason(err)}")
    width = max(len(r.table) for r in results)
    for r in results:
        typer.echo(
            f"{r.table:<{width}}  {r.rows:,} rows: {len(r.decrypted)} column(s) decrypted"
            + (f" ({_found(r)})" if r.decrypted else "")
            + f", {len(r.copied)} as they were"
        )
    if not any(r.decrypted for r in results):
        typer.echo(
            "WARN no column was encrypted, so nothing was decrypted (columns encrypted with ff1 look like "
            "any others: give the twin's folder, or its report.json too)",
            err=True,
        )
    typer.echo(f"access key fingerprint {sealer.fingerprint} · wrote {len(results)} file(s) to {out}")


def _sealer(key: str | None, policy: Path | None, key_option: str, policy_option: str) -> "Sealer":
    """The sealer of an access key reference, or of the masking key a policy refers to (exactly one)."""
    from safetwin.masking.portable import KeyProblem, Sealer

    if (key is None) == (policy is None):
        raise typer.BadParameter(
            f"give either {key_option} REF or {policy_option} FILE",
            param_hint=f"{key_option} / {policy_option}",
        )
    if key is not None and (not is_reference(key) or not key.startswith(("env://", "file://"))):
        raise typer.BadParameter(
            "give env://NAME or file://PATH, never the key itself", param_hint=key_option
        )
    try:
        access = (
            _policy_key(policy).access_key() if policy is not None else resolve_key(str(key)).as_access_key()
        )
        return Sealer(access)
    except (KeyRefError, KeyProblem) as err:
        _fail(str(err))


def _found(result: "Unmasked") -> str:
    """`email: aes-gcm, phone: ff1`: each decrypted column and the algorithm found for it."""
    from safetwin.spec.validate import redacted

    return ", ".join(f"{redacted(c)}: {a}" for c, a in zip(result.decrypted, result.ciphers, strict=True))


# --- safetwin rekey ----------------------------------------------------------------------------------------


def rekey(
    paths: Annotated[
        list[Path],
        typer.Argument(
            exists=True, help="Masked files, or folders of them (a twin that safetwin mask wrote)."
        ),
    ],
    out: Annotated[Path, typer.Option("--out", metavar="DIR", help="Write the re-encrypted files here.")],
    old: Annotated[
        str | None,
        typer.Option("--from", metavar="REF", help="The old access key: env://NAME or file://PATH."),
    ] = None,
    new: Annotated[
        str | None, typer.Option("--to", metavar="REF", help="The new access key: env://NAME or file://PATH.")
    ] = None,
    old_policy: Annotated[
        Path | None,
        typer.Option(
            "--from-policy", metavar="FILE", exists=True, dir_okay=False, help="Use this policy's key."
        ),
    ] = None,
    new_policy: Annotated[
        Path | None,
        typer.Option(
            "--to-policy", metavar="FILE", exists=True, dir_okay=False, help="Use this policy's key."
        ),
    ] = None,
    replace: Annotated[bool, typer.Option("--replace", help="Replace files already in the folder.")] = False,
) -> None:
    """Rotate a key: encrypt the encrypted columns again with a new access key, without showing a value.

    The output is what masking with the new key would have made for these columns, so the old access key no
    longer reads it. One-way columns are copied as they are: to change them, mask the source again with the
    new key. A wrong old key or a changed file writes nothing.
    """
    from safetwin.masking.unmask import UnmaskError
    from safetwin.masking.unmask import unmask as run_unmask

    before = _sealer(old, old_policy, "--from", "--from-policy")
    after = _sealer(new, new_policy, "--to", "--to-policy")
    if before.fingerprint == after.fingerprint:
        _fail("the old and the new key are the same")
    try:
        results = run_unmask(paths, out, before, replace=replace, to=after)
    except UnmaskError as err:
        _fail(str(err))
    except OSError as err:
        _fail(f"cannot rekey: {_os_reason(err)}")
    width = max(len(r.table) for r in results)
    for r in results:
        typer.echo(f"{r.table:<{width}}  {r.rows:,} rows: {len(r.decrypted)} column(s) re-encrypted")
    if not any(r.decrypted for r in results):
        typer.echo(
            "WARN no column was encrypted, so nothing changed (for ff1 columns, give the twin's folder, or "
            "its report.json too)",
            err=True,
        )
    typer.echo(
        f"access key {before.fingerprint} → {after.fingerprint} · wrote {len(results)} file(s) to {out}"
    )


# --- safetwin ui -------------------------------------------------------------------------------------------


def ui(
    no_browser: Annotated[
        bool, typer.Option("--no-browser", help="Print the address, don't open the browser.")
    ] = False,
) -> None:
    """Open the page to mask files and read reversible ones back, in your browser (on this computer only).

    It runs until Ctrl-C; the files you add are removed then. Its key is a key file in safetwin's folder,
    made the first time.
    """
    from safetwin.ui.server import serve

    try:
        serve(open_browser=not no_browser)
    except KeyRefError as err:
        _fail(str(err))
    except OSError as err:
        _fail(f"cannot start the page: {_os_reason(err)}")
