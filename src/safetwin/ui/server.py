"""`safetwin ui`: a page in the browser to mask files and to read encrypted ones back.

It runs the same code as the CLI (`scan`, `mask`, `unmask`) on files you add in the page:

1. **Mask**: add CSV, Parquet or Excel files; safetwin scans them and suggests a method per column. For
   each file you choose *reversible* (masked columns are encrypted: whoever has the access key reads them
   back) or *one-way* (nothing can read them back), and for each column what to do with it. A preview shows
   the first rows as they will come out. Then it masks them (with progress), shows the report and gives you
   a zip of the masked files.
2. **Unmask**: add masked files and give the access key (or use this computer's key); you get the readable
   files.
3. **History**: the reports of earlier runs (names, counts and methods: never a value).
4. **Keys**: the masking key the page uses, and the access key to download for the people who may read the
   reversible files.

For a reversible file, each column is encrypted with aes-siv, ff1 (keeping its format) or aes-gcm (hiding
repeats), or kept, emptied or removed. After masking, *Save to a folder* copies the zip into a folder of this
computer, such as one that Google Drive, Dropbox, OneDrive or iCloud keeps in sync (`sync_folders`).

The page's default key is a key file in safetwin's folder (`paths.safetwin_home()/ui.key`, mode 0600), made
the first time; the Keys tab can switch to a new key, one you give, or a passphrase's. The key in use stays
in memory: a run gets it in its environment (`KEY_ENV`), never in a file. The history is next to the key
file (`ui-history/`, mode 0700). The files you add, and what is made
of them, stay in a private temporary folder (mode 0700) that is removed when a job is cleared and when the
server stops.

Safety of a local server: it listens on 127.0.0.1 only, on a port the system picks. The browser gets a
random token in the address's fragment (never sent over the network), trades it for an HttpOnly,
SameSite=Strict cookie, and every API call needs that cookie; calls that change something also need the
header `X-Safetwin: 1`, which another site can't send. The Host header must be this address (no DNS
rebinding). Nothing is logged but one line at start; no message holds a data value.
"""

import copy
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import tempfile
import threading
import webbrowser
import zipfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from safetwin.keys import KeyRefError, MasterKey, key_from_passphrase, new_key, new_key_file, resolve_key
from safetwin.paths import safetwin_home

STATIC = Path(__file__).parent / "static"
HOST = "127.0.0.1"
COOKIE = "safetwin_ui"
FILE_NAME = re.compile(r"^(?:[\w][\w .()-]{0,120}\.(?:csv|parquet|xlsx)|report\.json)$", re.IGNORECASE)
KEY_ENV = "SAFETWIN_UI_KEY"  # how a run gets the page's key: in the environment it is given, never in a file
KEY_SOURCES = {
    "computer": "this computer's key",
    "generate": "a new key",
    "hex": "your own key",
    "passphrase": "the key of your passphrase",
}
JOB_ID = re.compile(r"^[a-z0-9]{12}$")
HISTORY_ID = re.compile(r"^\d{8}-\d{6}-[a-z0-9]{12}$")
HISTORY_KEEP = 200  # the newest runs kept in the history
PREVIEW_ROWS = 5
PREVIEW_CHARS = 60
FORMATS = ("csv", "parquet", "xlsx")
PAGE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "frame-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
)
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox; frame-ancestors 'self'"


class UiError(Exception):
    """A problem to show in the page: it names files, tables and columns, never a value."""


@dataclass
class Job:
    folder: Path
    scanned: Any = None  # the ScanResult of the files, once scanned
    options: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)  # table, column → id → method
    rev_options: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)  # for a reversible file
    rev_defaults: dict[str, dict[str, str]] = field(default_factory=dict)  # table, column → its default id
    progress: dict[str, Any] = field(default_factory=dict)  # how far the running mask has got
    lock: threading.Lock = field(default_factory=threading.Lock)

    @property
    def data(self) -> Path:
        return self.folder / "data"


class Workspace:
    """The jobs of this server, each in a folder of a private temporary folder."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="safetwin-ui-"))
        os.chmod(self.root, 0o700)
        self.jobs: dict[str, Job] = {}

    def new(self) -> str:
        job_id = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
        folder = self.root / job_id
        (folder / "data").mkdir(parents=True, mode=0o700)
        self.jobs[job_id] = Job(folder)
        return job_id

    def get(self, job_id: str) -> Job:
        if not JOB_ID.fullmatch(job_id) or job_id not in self.jobs:
            raise HTTPException(404, "no such job: it was cleared, or the server restarted")
        return self.jobs[job_id]

    def remove(self, job_id: str) -> None:
        job = self.jobs.pop(job_id, None)
        if job is not None:
            shutil.rmtree(job.folder, ignore_errors=True)

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def ui_key_path() -> Path:
    return safetwin_home() / "ui.key"


def load_or_make_key(path: Path) -> MasterKey:
    """The page's key: the key file at `path`, made (mode 0600) when there is none."""
    if not path.exists():
        return new_key_file(path)
    return resolve_key(f"file://{path}")


# --- the jobs -----------------------------------------------------------------------------------------------


def _format_of(folder: Path) -> str:
    kinds = {p.suffix.lower() for p in folder.iterdir() if p.is_file() and p.name.lower() != "report.json"}
    if not kinds:
        raise UiError("add at least one CSV, Parquet or Excel file first")
    if len(kinds) > 1:
        raise UiError("add files of one kind in a job: CSV, Parquet or Excel, not a mix")
    return kinds.pop().removeprefix(".")


def scan_job(job: Job) -> dict[str, Any]:
    """Scan the job's files: the tables with every column's suggestion, for the page."""
    from safetwin.masking.check import kind_of
    from safetwin.masking.scan import ScanError, scan

    fmt = _format_of(job.data)
    try:
        job.scanned = scan(job.data, fmt=fmt)
    except ScanError as err:
        raise UiError(str(err)) from None
    linked = {
        tuple(side.strip().split(".", 1)) for text in job.scanned.relationships for side in text.split("->")
    }
    job.options, job.rev_options, job.rev_defaults = {}, {}, {}
    tables = []
    for t in job.scanned.tables.values():
        columns = []
        job.options[t.name], job.rev_options[t.name], job.rev_defaults[t.name] = {}, {}, {}
        for name, s in t.suggestions.items():
            profile = t.columns[name]
            # CSV is read as text: the methods are the ones a text column takes, whatever the values look like
            kind = "text" if fmt == "csv" else kind_of(profile.dtype)
            options, default = _options(kind, s.method, (t.name, name) in linked)
            reversible, rev_default = _rev_options(kind, s.method, (t.name, name) in linked)
            job.options[t.name][name] = dict(options)
            job.rev_options[t.name][name] = dict(reversible)
            job.rev_defaults[t.name][name] = rev_default
            columns.append(
                {
                    "name": name,
                    "type": kind_of(profile.dtype),
                    "options": [{"id": i, "label": _label(m), "suggested": i == default} for i, m in options],
                    "default": default,
                    "rev_options": [
                        {"id": i, "label": _label(m), "suggested": i == rev_default} for i, m in reversible
                    ],
                    "rev_default": rev_default,
                    "reasons": s.reasons,
                }
            )
        tables.append({"name": t.name, "file": t.file, "rows": t.rows, "columns": columns})
    return {"format": fmt, "tables": tables, "relationships": job.scanned.relationships}


def _options(
    kind: str, suggested: dict[str, Any], linked: bool
) -> tuple[list[tuple[str, dict[str, Any]]], str]:
    """The methods a column of `kind` can take in the page, as (id, method), and the id of the suggested
    one. A column that links two files takes the suggested method (so both sides match) or is kept."""
    from safetwin.masking.scan import _m
    from safetwin.spec.policy import FAKE_KINDS

    options: list[tuple[str, dict[str, Any]]] = [("keep", _m("keep"))]
    if linked:
        if suggested["method"] != "keep":
            options.insert(0, ("suggested", suggested))
    else:
        if kind != "other":
            options.append(("code", _m("pseudonymize")))
        if kind == "text":
            options += [(f"fake_{k}", _m("fake", kind=k)) for k in FAKE_KINDS]
            options += [
                ("last4", _m("redact", keep_last=4)),
                ("first3", _m("generalize", keep_chars=3)),
                ("hide", _m("redact", **{"with": "REDACTED"})),
            ]
        if kind in ("date", "datetime"):
            options += [("year", _m("generalize", to="year")), ("month", _m("generalize", to="month"))]
        options += [("null", _m("null")), ("drop", _m("drop"))]
        if not any(m == suggested for _, m in options):
            options.insert(0, ("suggested", suggested))
    default = next(i for i, m in options if m == suggested or (i == "keep" and linked))
    return options, default


def _rev_options(
    kind: str, suggested: dict[str, Any], linked: bool
) -> tuple[list[tuple[str, dict[str, Any]]], str]:
    """The methods a column of a reversible file can take, as (id, method), and the default: kept if the scan
    keeps it, else encrypted as `scan.make_reversible(..., algorithm="auto")` does (ff1 for a text column that
    looks like a phone or card number, aes-siv otherwise). A column that links two files is encrypted with
    aes-siv (equal values, equal outputs) or kept."""
    from safetwin.masking.scan import _m, number_shaped

    options: list[tuple[str, dict[str, Any]]] = [("keep", _m("keep"))]
    if kind != "other" or linked:
        options.insert(0, ("siv", _m("encrypt")))
    if not linked:
        if kind == "text":
            options += [
                ("ff1", _m("encrypt", algorithm="ff1")),
                ("ff1an", _m("encrypt", algorithm="ff1", alphabet="alphanumeric")),
            ]
        if kind != "other":
            options.append(("gcm", _m("encrypt", algorithm="aes-gcm")))
        options += [("null", _m("null")), ("drop", _m("drop"))]
    if suggested["method"] == "keep":
        return options, "keep"
    shaped = number_shaped(suggested) and kind == "text" and not linked
    return options, "ff1" if shaped else "siv" if kind != "other" or linked else "keep"


def _label(method: dict[str, Any]) -> str:
    """A method in plain words, as the page shows it: `fake email`, `rounded to the year`, `removed`."""
    m = method["method"]
    if m == "pseudonymize":
        return "replaced by a code"
    if m == "fake":
        return f"fake {str(method['kind']).replace('_', ' ')}"
    if m == "date_shift":
        return "date moved by a few days"
    if m == "drop":
        return "removed"
    if m == "null":
        return "emptied"
    if m == "keep":
        return "kept as it is"
    if m == "encrypt":
        algorithm = method.get("algorithm", "aes-siv")
        if algorithm == "ff1":
            kept = "letters and digits" if method.get("alphabet") == "alphanumeric" else "digits"
            return f"encrypted, keeps the format ({kept})"
        if algorithm == "aes-gcm":
            return "encrypted, random (hides repeats)"
        return "encrypted, standard"
    if m == "redact":
        if method.get("keep_last") is not None:
            return f"hidden except the last {method['keep_last']}"
        if method.get("keep_first") is not None:
            return f"hidden except the first {method['keep_first']}"
        return "replaced by fixed text"
    if method.get("to"):
        return f"rounded to the {method['to']}"
    if method.get("keep_chars") is not None:
        return f"first {method['keep_chars']} characters kept"
    if method.get("ip"):
        return "network part only"
    if method.get("bucket") is not None:
        return f"rounded to steps of {method['bucket']}"
    return "put in ranges"


def _policy_text(job: Job, choices: dict[str, str], picked: dict[str, dict[str, str]], fmt: str) -> str:
    """The policy of the page's choices: per file reversible or one-way, per column a method id of
    `scan_job`'s options for that kind of file (the default one when not given)."""
    from safetwin.masking.scan import make_reversible, render

    if job.scanned is None:
        raise UiError("scan the files first")
    result = copy.deepcopy(job.scanned)
    unknown = set(choices) - set(result.tables)
    if unknown or set(result.tables) - set(choices):
        raise UiError("choose reversible or one-way for every file")
    if any(c not in ("reversible", "one-way") for c in choices.values()):
        raise UiError("each file is either reversible or one-way")
    for table in result.tables:
        reversible = choices[table] == "reversible"
        given = picked.get(table) or {}
        if not isinstance(given, dict):
            raise UiError(f"no table {table} in this job")
        suggestions = result.tables[table].suggestions
        if set(given) - set(suggestions):
            raise UiError(f"no column {sorted(set(given) - set(suggestions))[0]} in {table}")
        for column, s in suggestions.items():
            options = (job.rev_options if reversible else job.options)[table][column]
            if column in given:
                method = options.get(str(given[column]))
                if method is None:
                    raise UiError(f"{table}.{column} can't be masked that way")
            elif reversible:  # not given: the default of a reversible file, as the page shows it
                method = options[job.rev_defaults[table][column]]
            else:
                method = s.method
            if method != s.method:
                s.method, s.reasons = copy.deepcopy(method), ["you chose it"]
    for text in result.relationships:
        (ta, ca), (tb, cb) = (side.strip().split(".", 1) for side in text.split("->"))
        kept = [result.tables[t].suggestions[c].method["method"] == "keep" for t, c in ((ta, ca), (tb, cb))]
        if kept[0] != kept[1]:
            raise UiError(f"{ta}.{ca} and {tb}.{cb} link the files: mask both or keep both")
    make_reversible(result, [])  # no new encryption, only links: one-way where they join a one-way file
    return render(
        result,
        source="./data",  # relative to the policy, in the job's folder (whose random name looks like a token)
        name="upload",
        target="./masked",
        key=f"env://{KEY_ENV}",
        target_format=fmt,
    )


def _body(job: Job, body: dict[str, Any], fmt: str) -> str:
    choices = body.get("choices") or {}
    picked = body.get("picked") or {}
    if not isinstance(choices, dict) or not isinstance(picked, dict):
        raise UiError("send the choices as objects")
    return _policy_text(job, dict(choices), dict(picked), fmt)


def _environ(key: MasterKey) -> dict[str, str]:
    """The environment a run resolves the policy's key in: the page's key, and nothing else."""
    return {KEY_ENV: key.hex_for_key_file()}


def _cell(value: Any) -> str | None:
    if value is None:
        return None
    text = value.hex() if isinstance(value, bytes) else str(value)
    return text if len(text) <= PREVIEW_CHARS else text[: PREVIEW_CHARS - 1] + "…"


def preview_job(job: Job, body: dict[str, Any], key: MasterKey) -> dict[str, Any]:
    """The first rows of every file as the choices would mask them: the mask step on a sample, no checks,
    nothing written but the sample."""
    from safetwin.masking.compile import compile_policy
    from safetwin.masking.hmacs import Subkeys
    from safetwin.masking.run import MaskFailed, _scan_input, prepare
    from safetwin.masking.staging import StagingError, stage_excel
    from safetwin.masking.step import ENCRYPT_USE, mask_frame, subkey_use

    fmt = job.scanned.fmt if job.scanned else "parquet"
    policy_path = job.folder / "preview.yaml"
    policy_path.write_text(_body(job, body, "parquet"), encoding="utf-8")
    sample = job.folder / "sample"
    shutil.rmtree(sample, ignore_errors=True)
    sample.mkdir(mode=0o700)
    try:
        if fmt == "xlsx":
            stage_excel(job.data, sample, limit=PREVIEW_ROWS)
        prepared = prepare(policy_path, source=sample if fmt == "xlsx" else None, environ=_environ(key))
        policy = prepared.policy
        compiled = compile_policy(policy, prepared.tables)
        subkeys = Subkeys(key, compiled.subkey_uses)
        tables = []
        for table, steps in compiled.columns.items():
            frame = _scan_input(policy, prepared.tables[table]).head(PREVIEW_ROWS).collect()
            uses = {c: u for c, step in steps.items() if (u := subkey_use(c, step)) is not None}
            macs = {c: subkeys.sealer() if u == ENCRYPT_USE else subkeys.mac(*u) for c, u in uses.items()}
            out = mask_frame(frame, columns=steps, macs=macs)
            tables.append(
                {
                    "name": table,
                    "columns": out.columns,
                    "rows": [[_cell(v) for v in row] for row in out.iter_rows()],
                }
            )
    except MaskFailed as err:
        errors = [p for p in err.problems if p.severity == "error"]
        raise UiError("; ".join(p.message for p in errors) or "the choices can't run") from None
    except StagingError as err:
        raise UiError(str(err)) from None
    except UiError:
        raise
    except Exception as err:  # Polars messages can quote a row
        raise UiError(f"the preview failed with {type(err).__name__} (its message can quote data)") from None
    finally:
        shutil.rmtree(sample, ignore_errors=True)
        policy_path.unlink(missing_ok=True)
    return {"rows": PREVIEW_ROWS, "tables": tables}


def mask_job(job: Job, body: dict[str, Any], key: MasterKey, history: Path | None = None) -> dict[str, Any]:
    from safetwin.dataplane.operators import ConfigError, Unsupported
    from safetwin.dataplane.run import PipelineInvalid
    from safetwin.dataplane.spill import SpillError
    from safetwin.dataplane.watchdog import MemoryLimitReached
    from safetwin.masking.run import MaskFailed
    from safetwin.masking.run import mask as run_mask
    from safetwin.spec.validate import redacted

    fmt = body.get("format") or (job.scanned.fmt if job.scanned else "parquet")
    if fmt not in FORMATS:
        raise UiError("the output is csv, parquet or xlsx")
    text = _body(job, body, fmt)
    policy = job.folder / "masking.yaml"
    policy.write_text(text, encoding="utf-8")
    shutil.rmtree(job.folder / "masked", ignore_errors=True)
    (job.folder / "masked.zip").unlink(missing_ok=True)
    total = sum(t.rows for t in job.scanned.tables.values()) if job.scanned else 0
    read: dict[int, int] = {}
    job.progress = {"phase": "starting", "rows": 0, "total": total}

    def on_event(event: Any) -> None:
        read[event.stage] = next(iter(event.rows_per_node.values()), 0)
        rows = min(sum(read.values()), total)
        job.progress = {"phase": "checking" if rows >= total else "masking", "rows": rows, "total": total}

    try:
        outcome = run_mask(policy, on_event=on_event, environ=_environ(key))
    except MaskFailed as err:
        errors = [p for p in err.problems if p.severity == "error"]
        raise UiError("; ".join(p.message for p in errors) or "the policy can't run") from None
    except PipelineInvalid as err:
        raise UiError("; ".join(redacted(p.message) for p in err.problems if p.severity == "error")) from None
    except (ConfigError, Unsupported, SpillError, MemoryLimitReached) as err:  # these name things, no data
        raise UiError(str(err)) from None
    except Exception as err:  # Polars and PyArrow messages can quote a row: say what kind of error, no more
        raise UiError(f"masking failed with {type(err).__name__} (its message can quote data)") from None
    finally:
        job.progress = {"phase": "done", "rows": total, "total": total}
    report = outcome.report
    if outcome.ok:
        _zip_masked(job, fmt)
    if history is not None:
        files = sorted({t.file for t in job.scanned.tables.values()}) if job.scanned else []
        save_history(history, job.folder.name, job.folder / "masked", files, body.get("choices") or {}, fmt)
    return {
        "ok": outcome.ok,
        "error": outcome.error,
        "warnings": report["warnings"],
        "tables": {
            t: {"rows_in": v["rows_in"], "rows_out": v["rows_out"]} for t, v in report["tables"].items()
        },
        "classes": {
            t: {c: info["class"] for c, info in v["columns"].items()} for t, v in report["tables"].items()
        },
        "orphans": sum(r["orphans"] for r in report["relationships"]),
        "findings": len(report["residual_scan"]["findings"]),
    }


def _zip_masked(job: Job, fmt: str) -> None:
    """masked.zip: one file per table (`customers.csv`), the report and the policy."""
    out = job.folder / "masked"
    with zipfile.ZipFile(job.folder / "masked.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for book in sorted(out.glob("*.xlsx")):  # an Excel twin: a workbook per table
            archive.write(book, book.name)
        for table in sorted(p for p in out.iterdir() if p.is_dir()):
            parts = sorted(table.glob(f"*.{fmt}"))
            for part in parts:
                archive.write(part, f"{table.name}.{fmt}" if len(parts) == 1 else f"{table.name}/{part.name}")
        for extra in ("report.html", "report.json"):
            if (out / extra).exists():
                archive.write(out / extra, extra)
        archive.write(job.folder / "masking.yaml", "masking.yaml")


# --- saving to a folder (a Google Drive, Dropbox, OneDrive or iCloud folder) -----------------------------


def sync_folders(home: Path) -> list[dict[str, str]]:
    """The folders that a cloud drive's desktop app keeps in sync, found below `home`: macOS's
    `Library/CloudStorage` (Google Drive, Dropbox, OneDrive, Box), iCloud Drive, and the older places in the
    home folder. Only names and paths; nothing is read from them."""
    found: list[dict[str, str]] = []
    reals: list[str] = []

    def add(name: str, path: Path) -> None:
        """Once per drive: a shortcut to a drive already listed (`~/Google Drive`, say) is left out."""
        real = os.path.realpath(path)
        if path.is_dir() and not any(r == real or r.startswith(real + os.sep) for r in reals):
            found.append({"name": name, "path": str(path)})
            reals.append(real)

    names = {"GoogleDrive": "Google Drive", "Dropbox": "Dropbox", "OneDrive": "OneDrive", "Box": "Box"}
    cloud = home / "Library" / "CloudStorage"
    if cloud.is_dir():
        for entry in sorted(cloud.iterdir()):
            kind, _, account = entry.name.partition("-")
            if kind in names:
                name = f"{names[kind]} ({account})" if account else names[kind]
                add(name, entry / "My Drive" if (entry / "My Drive").is_dir() else entry)
    add("iCloud Drive", home / "Library" / "Mobile Documents" / "com~apple~CloudDocs")
    for name, folder in (
        ("Google Drive", "Google Drive"),
        ("Google Drive", "GoogleDrive"),
        ("Dropbox", "Dropbox"),
        ("OneDrive", "OneDrive"),
    ):
        add(name, home / folder)
    return found


def save_copy(job: Job, folder_text: str, workspace_root: Path) -> Path:
    """Copy the job's masked.zip into a folder of this computer (a synced cloud folder, say), under a new
    name: written as a hidden file first and renamed when complete, never over an existing file."""
    archive = job.folder / "masked.zip"
    if not archive.exists():
        raise UiError("mask the files first: there is nothing to save yet")
    folder = Path(folder_text.strip()).expanduser()
    if not folder.is_absolute():
        raise UiError("give the full path of a folder, such as ~/Library/CloudStorage/... or /Users/you/...")
    if not folder.is_dir():
        raise UiError(f"{folder} is not a folder on this computer")
    if folder.resolve().is_relative_to(workspace_root.resolve()):
        raise UiError("choose a folder of your own, not one of the page's")
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    final, n = folder / f"safetwin-masked-{stamp}.zip", 1
    while final.exists():
        final, n = folder / f"safetwin-masked-{stamp}-{n}.zip", n + 1
    temporary = folder / f".{final.name}.part"
    try:
        shutil.copyfile(archive, temporary)
        os.replace(temporary, final)
    except OSError as err:
        temporary.unlink(missing_ok=True)
        reason = os.strerror(err.errno) if err.errno else type(err).__name__
        raise UiError(f"cannot write to {folder}: {reason}") from None
    return final


# --- the history: reports only ---------------------------------------------------------------------------


def save_history(
    root: Path, job_id: str, out: Path, files: list[str], choices: dict[str, str], fmt: str
) -> None:
    """Keep the run's report (no value in it) in `root/<when>-<job>/`, with the files' names and the
    choices; only the newest `HISTORY_KEEP` runs stay."""
    if not (out / "report.json").exists():
        return
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    entry = root / f"{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{job_id}"
    shutil.rmtree(entry, ignore_errors=True)
    entry.mkdir(mode=0o700)
    for name in ("report.json", "report.html"):
        if (out / name).exists():
            shutil.copyfile(out / name, entry / name)
    meta = {"files": files, "choices": {str(k): str(v) for k, v in choices.items()}, "format": fmt}
    (entry / "entry.json").write_text(json.dumps(meta), encoding="utf-8")
    for old in sorted(p for p in root.iterdir() if HISTORY_ID.fullmatch(p.name))[:-HISTORY_KEEP]:
        shutil.rmtree(old, ignore_errors=True)


def list_history(root: Path) -> list[dict[str, Any]]:
    """The runs of the history, newest first: when, files, choices, status and rows per table."""
    if not root.is_dir():
        return []
    runs = []
    for entry in sorted((p for p in root.iterdir() if HISTORY_ID.fullmatch(p.name)), reverse=True):
        try:
            report = json.loads((entry / "report.json").read_text(encoding="utf-8"))
            meta = json.loads((entry / "entry.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        runs.append(
            {
                "id": entry.name,
                "when": report.get("started_at"),
                "files": meta.get("files", []),
                "choices": meta.get("choices", {}),
                "format": meta.get("format"),
                "ok": report.get("status") == "ok",
                "tables": {
                    t: {"rows_in": v.get("rows_in"), "rows_out": v.get("rows_out")}
                    for t, v in report.get("tables", {}).items()
                },
            }
        )
    return runs


def history_entry(root: Path, entry_id: str) -> Path:
    if not HISTORY_ID.fullmatch(entry_id) or not (root / entry_id).is_dir():
        raise HTTPException(404, "no such run in the history")
    return root / entry_id


def unmask_job(job: Job, body: dict[str, Any], key: MasterKey) -> dict[str, Any]:
    from safetwin.masking.portable import Sealer
    from safetwin.masking.unmask import UnmaskError, unmask

    given = str(body.get("access_key") or "").strip()
    if given:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", given):
            raise UiError("an access key is 64 hexadecimal characters")
        sealer = Sealer(bytes.fromhex(given))
    else:
        sealer = Sealer(key.access_key())
    out = job.folder / "readable"
    shutil.rmtree(out, ignore_errors=True)
    (job.folder / "readable.zip").unlink(missing_ok=True)
    try:
        results = unmask([job.data], out, sealer)
    except UnmaskError as err:
        raise UiError(str(err)) from None
    except Exception as err:
        raise UiError(f"unmasking failed with {type(err).__name__} (its message can quote data)") from None
    with zipfile.ZipFile(job.folder / "readable.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for r in results:
            archive.write(r.output, r.output.name)
    return {
        "fingerprint": sealer.fingerprint,
        "tables": [
            {
                "name": r.table,
                "rows": r.rows,
                "decrypted": [
                    {"column": c, "algorithm": a} for c, a in zip(r.decrypted, r.ciphers, strict=True)
                ],
                "copied": list(r.copied),
            }
            for r in results
        ],
    }


# --- the app ------------------------------------------------------------------------------------------------


def create_app(token: str, port: int, key_path: Path, workspace: Workspace) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    computer = load_or_make_key(key_path)
    active: dict[str, Any] = {"key": computer, "source": "computer"}  # the key the page masks with, in memory
    history = key_path.parent / "ui-history"

    def key_info() -> dict[str, Any]:
        from safetwin.masking.portable import Sealer

        key: MasterKey = active["key"]
        return {
            "source": active["source"],
            "label": KEY_SOURCES[active["source"]],
            "fingerprint": key.fingerprint,
            "access_fingerprint": Sealer(key.access_key()).fingerprint,
        }

    hosts = {f"{HOST}:{port}", f"localhost:{port}"}

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        if request.headers.get("host") not in hosts:
            return JSONResponse({"error": "wrong host"}, status_code=421)
        path = request.url.path
        if path.startswith("/api/") and path != "/api/login":
            session = request.cookies.get(COOKIE, "")
            if not hmac.compare_digest(session.encode(), token.encode()):
                return JSONResponse({"error": "open the page from the address safetwin ui printed"}, 401)
            if request.method != "GET" and request.headers.get("x-safetwin") != "1":
                return JSONResponse({"error": "missing X-Safetwin header"}, status_code=403)
        try:
            response = await call_next(request)
        except Exception as err:  # its message could quote data: neither show nor log it
            response = JSONResponse({"error": f"something went wrong ({type(err).__name__})"}, 500)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers.setdefault("Content-Security-Policy", PAGE_CSP)
        return response

    @app.exception_handler(UiError)
    async def ui_error(_: Request, err: UiError) -> JSONResponse:
        return JSONResponse({"error": str(err)}, status_code=400)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/static/{name}")
    def static(name: str) -> FileResponse:
        if name not in ("app.js", "app.css"):
            raise HTTPException(404)
        return FileResponse(
            STATIC / name, media_type="text/javascript" if name.endswith(".js") else "text/css"
        )

    @app.post("/api/login")
    async def login(request: Request) -> Response:
        body = await request.json()
        given = str(body.get("token", "")) if isinstance(body, dict) else ""
        if not hmac.compare_digest(given.encode(), token.encode()):
            return JSONResponse({"error": "this link is old: run safetwin ui again"}, status_code=401)
        response = JSONResponse({"ok": True})
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict", path="/")
        return response

    @app.get("/api/state")
    def state() -> dict[str, Any]:
        return {"key_file": str(key_path), "key": key_info()}

    @app.post("/api/key")
    async def choose_key(request: Request) -> dict[str, Any]:
        """Change the key the page masks and unmasks with: this computer's key file, a new random key (its
        hex is in this one answer, to save), a key given as 64 hex characters, or a passphrase (scrypt). It
        stays in memory; a run gets it through its environment."""
        import asyncio

        body = await request.json()
        mode = body.get("mode") if isinstance(body, dict) else None
        value = str(body.get("value") or "") if isinstance(body, dict) else ""
        shown = None
        if mode == "computer":
            key = computer
        elif mode == "generate":
            key = new_key()
            shown = key.hex_for_key_file()
        elif mode == "hex":
            text = value.strip()
            if not re.fullmatch(r"[0-9a-fA-F]{64}", text):
                raise UiError("a key is 64 hexadecimal characters (what a safetwin key file holds)")
            key = MasterKey(bytes.fromhex(text))
        elif mode == "passphrase":
            try:
                key = await asyncio.to_thread(key_from_passphrase, value)
            except KeyRefError as err:
                raise UiError(str(err)) from None
        else:
            raise UiError("choose computer, generate, hex or passphrase")
        active.update(key=key, source=mode)
        info = key_info()
        if shown is not None:
            info["key"] = shown
        return info

    @app.get("/api/folders")
    def folders() -> dict[str, Any]:
        return {"folders": sync_folders(Path.home())}

    @app.post("/api/jobs/{job_id}/save")
    async def save(job_id: str, request: Request) -> dict[str, str]:
        job = workspace.get(job_id)
        body = await request.json()
        folder = body.get("folder") if isinstance(body, dict) else None
        if not isinstance(folder, str) or not folder.strip():
            raise UiError("choose a folder")
        return {"saved": str(await _in_thread_value(job, lambda: save_copy(job, folder, workspace.root)))}

    @app.get("/api/access-key")
    def access_key() -> Response:
        return Response(
            active["key"].access_key().hex() + "\n",
            media_type="text/plain",
            headers={"Content-Disposition": 'attachment; filename="safetwin-access-key.txt"'},
        )

    @app.post("/api/jobs")
    def new_job() -> dict[str, str]:
        return {"id": workspace.new()}

    @app.delete("/api/jobs/{job_id}")
    def clear_job(job_id: str) -> dict[str, bool]:
        workspace.get(job_id)
        workspace.remove(job_id)
        return {"ok": True}

    @app.put("/api/jobs/{job_id}/files/{name}")
    async def upload(job_id: str, name: str, request: Request) -> dict[str, Any]:
        job = workspace.get(job_id)
        if not FILE_NAME.fullmatch(name) or name.startswith("."):
            raise UiError(
                "a file name is letters, digits, spaces and . _ - ( ), ending in .csv, .parquet or .xlsx"
            )
        target = job.data / name
        size = 0
        with open(target, "wb") as handle:
            async for chunk in request.stream():
                size += len(chunk)
                handle.write(chunk)
        job.scanned = None
        return {"name": name, "bytes": size}

    @app.delete("/api/jobs/{job_id}/files/{name}")
    def remove_file(job_id: str, name: str) -> dict[str, bool]:
        job = workspace.get(job_id)
        if FILE_NAME.fullmatch(name):
            (job.data / name).unlink(missing_ok=True)
        job.scanned = None
        return {"ok": True}

    @app.post("/api/jobs/{job_id}/scan")
    def scan(job_id: str) -> dict[str, Any]:
        job = workspace.get(job_id)
        with job.lock:
            return scan_job(job)

    @app.post("/api/jobs/{job_id}/mask")
    async def mask(job_id: str, request: Request) -> dict[str, Any]:
        job = workspace.get(job_id)
        body = await request.json()
        if not isinstance(body, dict):
            raise UiError("send the choices as an object")
        return await _in_thread(job, lambda: mask_job(job, body, active["key"], history))

    @app.get("/api/jobs/{job_id}/progress")
    def progress(job_id: str) -> dict[str, Any]:
        return workspace.get(job_id).progress or {"phase": "idle"}

    @app.post("/api/jobs/{job_id}/preview")
    async def preview(job_id: str, request: Request) -> dict[str, Any]:
        job = workspace.get(job_id)
        body = await request.json()
        if not isinstance(body, dict):
            raise UiError("send the choices as an object")
        return await _in_thread(job, lambda: preview_job(job, body, active["key"]))

    @app.get("/api/history")
    def runs() -> dict[str, Any]:
        return {"runs": list_history(history)}

    @app.get("/api/history/{entry_id}/report")
    def old_report(entry_id: str) -> Response:
        path = history_entry(history, entry_id) / "report.html"
        if not path.exists():
            raise HTTPException(404, "no report for this run")
        return Response(
            path.read_bytes(), media_type="text/html", headers={"Content-Security-Policy": REPORT_CSP}
        )

    @app.delete("/api/history/{entry_id}")
    def forget(entry_id: str) -> dict[str, bool]:
        shutil.rmtree(history_entry(history, entry_id), ignore_errors=True)
        return {"ok": True}

    @app.post("/api/jobs/{job_id}/unmask")
    async def unmask(job_id: str, request: Request) -> dict[str, Any]:
        job = workspace.get(job_id)
        body = await request.json()
        if not isinstance(body, dict):
            raise UiError("send the key as an object")
        return await _in_thread(job, lambda: unmask_job(job, body, active["key"]))

    @app.get("/api/jobs/{job_id}/report")
    def report(job_id: str) -> Response:
        path = workspace.get(job_id).folder / "masked" / "report.html"
        if not path.exists():
            raise HTTPException(404, "no report yet")
        return Response(
            path.read_bytes(), media_type="text/html", headers={"Content-Security-Policy": REPORT_CSP}
        )

    @app.get("/api/jobs/{job_id}/download/{what}")
    def download(job_id: str, what: str) -> FileResponse:
        if what not in ("masked.zip", "readable.zip"):
            raise HTTPException(404)
        path = workspace.get(job_id).folder / what
        if not path.exists():
            raise HTTPException(404, "nothing to download yet")
        return FileResponse(path, media_type="application/zip", filename=what)

    return app


async def _in_thread_value(job: Job, work: Callable[[], Path]) -> Path:
    """Like `_in_thread`, for work that gives a path."""
    import asyncio

    def locked() -> Path:
        with job.lock:
            return work()

    return await asyncio.to_thread(locked)


async def _in_thread(job: Job, work: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run `work` in a thread (masking takes a while), one job at a time."""
    import asyncio

    def locked() -> dict[str, Any]:
        with job.lock:
            return work()

    return await asyncio.to_thread(locked)


def serve(*, open_browser: bool = True, key_path: Path | None = None) -> None:
    """Run the page until Ctrl-C. Prints the address to open."""
    import uvicorn

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((HOST, 0))
    listener.listen(64)
    port = int(listener.getsockname()[1])
    token = secrets.token_urlsafe(32)
    workspace = Workspace()
    path = key_path or ui_key_path()
    try:
        app = create_app(token, port, path, workspace)
    except KeyRefError:
        workspace.close()
        listener.close()
        raise
    address = f"http://{HOST}:{port}/#token={token}"
    print(f"safetwin ui: open {address}", flush=True)
    print("press Ctrl-C to stop (the files you added are removed then)", flush=True)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(address)).start()
    config = uvicorn.Config(
        app, log_config=None, access_log=False, server_header=False, lifespan="off", proxy_headers=False
    )
    try:
        uvicorn.Server(config).run(sockets=[listener])
    finally:
        workspace.close()
        listener.close()


__all__ = ["UiError", "Workspace", "create_app", "serve"]
