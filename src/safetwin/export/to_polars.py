"""`safetwin export --to polars`: a policy as one standalone Polars script (docs/guide.md).

The script is, in order:
1. a header: what made it, the policy's SHA-256, the derivation version, how to run it;
2. its imports (the standard library and Polars);
3. the word lists (`masking/wordlists.py`), the portable core (`masking/portable.py`) and the runner
   (`export/runner.py`), copied word for word: the engine runs the same code, so the two compute the same
   bytes;
4. one function per table, one line per column with its method and report class, written from the
   compiled policy (`masking/compile.py`), as the engine runs it;
5. the job (folders, formats, tables, relationships, subset) and a `main`.

The export reads the source's schemas (never a row), because the policy's unknown columns and the types of
some methods depend on them; the script checks at run time that the source still has those columns and
types. Every name from the policy or the source is written as a string literal (`json.dumps`), comments
included, so no name can break out of it. The script never holds the key, only its reference.
"""

import ast
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import polars as pl

from safetwin.masking import portable, wordlists
from safetwin.masking.check import table_glob
from safetwin.masking.compile import CompiledPolicy, compile_policy
from safetwin.masking.methods import pseudonym_format
from safetwin.masking.run import Prepared, engine_version, folder_of, uniqueness_candidates
from safetwin.masking.step import ColumnStep, subkey_use
from safetwin.spec.policy import (
    DateShift,
    Drop,
    Encrypt,
    Fake,
    Generalize,
    Keep,
    Null,
    Pseudonymize,
    Redact,
    column_class,
    relationships,
    staged_source,
    staged_target,
    subset_key,
)

from . import runner

MARKER = "# --- exported below this line"
TARGETS = ("polars",)
LINE_LENGTH = 110
IMPORTS = """import argparse
import base64
import glob
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import stat
import struct
import sys
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import polars as pl"""


class ExportError(Exception):
    """The policy can't be exported. The message names tables, columns and methods, never a value."""


def _q(text: str) -> str:
    """A Python string literal of `text` (also safe in a comment: no newline survives)."""
    return json.dumps(text)


def _below_marker(path: str) -> str:
    text = Path(path).read_text(encoding="utf-8")
    start = text.index(MARKER)
    return text[text.index("\n", start) + 1 :].strip("\n")


def _wordlists() -> str:
    text = Path(wordlists.__file__).read_text(encoding="utf-8")
    docstring = ast.parse(text).body[0]
    assert isinstance(docstring, ast.Expr)  # the module docstring, which the script's header replaces
    return "\n".join(text.splitlines()[docstring.end_lineno or 0 :]).strip("\n")


def _dtype_code(dtype: pl.DataType) -> str:
    """Polars code for a type that `bucket`, `bins` or `date_shift` keep."""
    if isinstance(dtype, pl.Datetime):
        zone = _q(dtype.time_zone) if dtype.time_zone is not None else "None"
        return f"pl.Datetime({_q(dtype.time_unit)}, {zone})"
    if dtype == pl.Date or (dtype.is_numeric() and not isinstance(dtype, pl.Decimal)):
        return f"pl.{dtype}()"
    raise ExportError(f"no Polars code for the type {dtype}")


def _mac(column: str, step: ColumnStep) -> str:
    use = subkey_use(column, step)
    assert use is not None  # only keyed methods ask
    return f"keys.mac({_q(use[0])}, {_q(use[1])})"


def _expression(column: str, step: ColumnStep, dtype: pl.DataType) -> str | None:
    """The Polars expression of one column (None: dropped), as the engine's `step.mask_column` does it."""
    name, spec = _q(column), step.spec
    match spec:
        case Keep():
            return f"pl.col({name})"
        case Null():
            return f"nulled({name})"
        case Drop():
            return None
        case Encrypt():
            args = [name, "keys.sealer()"]
            if spec.algorithm != "aes-siv":
                args.append(f"algorithm={_q(spec.algorithm)}")
            if spec.algorithm == "ff1":
                args.append(f"alphabet={_q(spec.alphabet or 'digits')}")
                if spec.domain is not None:
                    args.append(f"domain={_q(spec.domain)}")
            return f"encrypt({', '.join(args)})"
        case Pseudonymize():
            fmt = pseudonym_format(spec.format, dtype)
            args = [name, _mac(column, step), _q(fmt)]
            if spec.prefix:
                args.append(f"prefix={_q(spec.prefix)}")
            if fmt == "uuid" and dtype == pl.Binary:
                args.append("binary=True")
            return f"pseudonymize({', '.join(args)})"
        case Fake():
            mac = _mac(column, step) if spec.consistent else "None"
            return f"fake({name}, {_q(spec.kind)}, {mac})"
        case Generalize(to=to) if to is not None:
            return f"truncate({name}, {_q(to)})"
        case Generalize(bucket=width) if width is not None:
            return f"bucket({name}, {width!r}, {_dtype_code(dtype)})"
        case Generalize(bins=edges) if edges is not None:
            return f"bins({name}, {edges!r}, {_dtype_code(dtype)})"
        case Generalize(keep_chars=count) if count is not None:
            return f"keep_chars({name}, {count})"
        case Generalize():
            return f"ip_network_of({name})"
        case DateShift():
            mac = _mac(column, step)
            return f"date_shift({name}, {_q(spec.entity)}, {mac}, {spec.max_days}, {_dtype_code(dtype)})"
        case Redact():
            settings = [
                f"{key}={value!r}" if isinstance(value, int) else f"{key}={_q(value)}"
                for key, value in (
                    ("keep_last", spec.keep_last),
                    ("keep_first", spec.keep_first),
                    ("char", spec.char if "char" in spec.model_fields_set else None),
                    ("with_", spec.with_),
                )
                if value is not None
            ]
            return f"redact({', '.join([name, *settings])})"
    raise ExportError(f"column {_q(column)}: the method {spec.method} can't be exported to Polars")


def _table_function(table: str, steps: dict[str, ColumnStep], schema: pl.Schema) -> str:
    kept = sum(1 for step in steps.values() if not isinstance(step.spec, Drop))
    lines = [
        f"def mask_{table}(frame: pl.LazyFrame, keys: Keys) -> pl.LazyFrame:",
        f'    """{table}: {len(steps)} column(s) in, {kept} out, in the source\'s order."""',
        "    return frame.select(",
    ]
    for column, step in steps.items():
        expr = _expression(column, step, schema[column])
        label = column_class(step.spec).replace("_", " ")
        if expr is None:
            lines.append(f"        # {_q(column)}: dropped ({label})")
        else:
            lines.append(f"        {expr},  # {label}")
    lines.append("    )")
    return "\n".join(lines)


def _folder_for(path: Path, script: Path | None) -> str:
    """A folder as the script names it: relative to the script's folder, or absolute without a script file."""
    real = os.path.realpath(path)
    if script is None:
        return real
    relative = os.path.relpath(real, os.path.realpath(script.parent))
    return relative if relative.startswith(".") else f"./{relative}"


def _job(prepared: Prepared, policy_path: Path, script: Path | None, compiled: CompiledPolicy) -> str:
    policy = prepared.policy
    compiled_unique = uniqueness_candidates(policy, compiled)
    target = folder_of(policy_path.parent, policy.spec.target.folder)
    tables = []
    for table in policy.spec.tables:
        schema = prepared.tables[table].schema
        columns = ", ".join(f"{_q(c)}: {_q(str(d))}" for c, d in schema.items())
        unique = "".join(f"{_q(c)}, " for c in compiled_unique.get(table, []))
        tables.append(
            f"        Table(\n"
            f"            name={_q(table)},\n"
            f"            glob={_q(table_glob(policy, table))},\n"
            f"            columns={{{columns}}},\n"
            f"            mask=mask_{table},\n"
            f"            unique=({unique.strip()}),\n"
            f"        ),"
        )
    rels = "".join(
        f"({_q(r.from_table)}, {_q(r.from_column)}, {_q(r.to_table)}, {_q(r.to_column)}), "
        for r in relationships(policy)
    )
    subset = "None"
    if policy.spec.subset is not None:
        s = policy.spec.subset
        key = subset_key(policy)
        assert key is not None  # validate_policy makes sure
        subset = (
            f"Subset(root={_q(s.root)}, key={_q(key)}, fraction={float(s.fraction)!r}, "
            f"include_children={s.include_children})"
        )
    return "\n".join(
        [
            "JOB = Job(",
            f"    name={_q(policy.metadata.name)},",
            f"    key={_q(policy.spec.key)},",
            f"    source={_q(_folder_for(prepared.source, script))},",
            f"    source_format={_q(str(policy.spec.source.format))},",
            f"    delimiter={_q(policy.spec.source.delimiter)},",
            f"    target={_q(_folder_for(target, script))},",
            f"    target_format={_q(policy.spec.target.format)},",
            "    tables=(",
            *tables,
            "    ),",
            f"    relationships=({rels.strip()}),",
            f"    subset={subset},",
            ")",
        ]
    )


def _header(prepared: Prepared, policy_sha256: str, script: Path | None) -> str:
    policy = prepared.policy
    name = script.name if script is not None and re.fullmatch(r"[\w.-]+", script.name) else "this_file.py"
    subset = "selects the subset, " if policy.spec.subset is not None else ""
    paragraphs = [
        f"Write the safe twin of {policy.metadata.name}: its masking policy as plain Polars.",
        f"Exported by safetwin {engine_version()} (`safetwin export --to polars`), derivation safetwin/v1, "
        f"from the policy with SHA-256 {policy_sha256}. This file is generated: change the policy and export "
        "it again rather than editing it.",
        f"Run it with the key that {_q(policy.spec.key)} refers to (this file never holds the key):",
        f"    python {name} [--source DIR] [--target DIR] [--replace]",
        "It reads every table and checks that it still has the columns and types of the export. Then it "
        f"{subset}masks every column as the policy says, checks every relationship (0 orphans) and every "
        "column that must stay unique, and only then puts the files in place.",
        f"It needs Python 3.11 or later and Polars (exported with Polars {pl.__version__})"
        + (
            ", and the cryptography package for the columns it encrypts."
            if any(
                isinstance(spec, Encrypt)
                for columns in policy.spec.tables.values()
                for spec in columns.values()
            )
            else "."
        ),
    ]
    wrapped = [p if p.startswith("    ") else textwrap.fill(p, LINE_LENGTH - 4) for p in paragraphs]
    return '"""' + "\n\n".join(wrapped) + '\n"""'


def _section(title: str) -> str:
    return f"# --- {title} ".ljust(LINE_LENGTH, "-")


def _format(text: str) -> str:
    """`text` through `ruff format` when ruff is installed; as it is otherwise (it is valid either way)."""
    try:
        done = subprocess.run(
            [sys.executable, "-m", "ruff", "format", "--isolated", "--line-length", str(LINE_LENGTH), "-"],
            input=text,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return text
    return done.stdout if done.returncode == 0 and done.stdout else text


def export_polars(
    prepared: Prepared, policy_path: Path, policy_sha256: str, script: Path | None = None
) -> str:
    """The Polars script of a policy that passed its checks (`masking.run.prepare`). `script` is where it
    will be written, so the folders can be relative to it."""
    spec = prepared.policy.spec
    if staged_source(spec.source) or staged_target(spec.target):
        raise ExportError(
            "the Polars export reads and writes CSV or Parquet folders: a Postgres or Excel source or target "
            "can't be exported yet (use safetwin mask for it)"
        )
    compiled = compile_policy(prepared.policy, prepared.tables)
    functions = [
        _table_function(table, steps, prepared.tables[table].schema)
        for table, steps in compiled.columns.items()
    ]
    parts = [
        _header(prepared, policy_sha256, script),
        IMPORTS,
        _section("word lists (from safetwin/masking/wordlists.py)"),
        _wordlists(),
        _section("the portable core (from safetwin/masking/portable.py)"),
        _below_marker(portable.__file__),
        _section("the runner (from safetwin/export/runner.py)"),
        _below_marker(runner.__file__),
        _section(f"the tables of {prepared.policy.metadata.name}"),
        *functions,
        _job(prepared, policy_path, script, compiled),
        'if __name__ == "__main__":\n    sys.exit(main(JOB, Path(__file__).resolve().parent))',
    ]
    text = "\n\n\n".join(parts) + "\n"
    compile(text, script.name if script is not None else "<export>", "exec")  # a bug here, never the data's
    return _format(text)
