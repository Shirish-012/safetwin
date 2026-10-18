"""`safetwin scan`: profile a source folder and draft a masking policy (docs/guide.md).

    list the tables (one file per table) → sample each one → profile every column (type, nulls, distinct
    count, lengths) → count detector matches → guess keys and relationships → suggest a method per column
    → masking.yaml, with the reasons as comments

The sample is up to 10,000 rows or 1% of the table, whichever is larger, taken evenly through the file. What
comes out holds table and column names, types, counts and shares, **never a value**: the profile is computed
by Polars and only numbers leave it. The draft is checked with `validate_policy` before it is returned, and
the methods are chosen to fit their column's type, so it passes `safetwin check` as it is. Detection only
suggests: the person reviewing the draft decides.

The order of the rules, first match wins:
1. An empty column: keep.
2. A column name or the values say what it holds (email, phone, card, IBAN, IP address, UUID, birth date,
   name, address, postcode, national id, location, user agent): the method for that kind.
3. A key: an `id`-like name, unique and non-null in the sample (pseudonymize), or `<thing>_id` where a table
   `<thing>` or `<thing>s` has an `id` column (a relationship; both sides pseudonymized in the domain
   `<thing>`).
4. A date or datetime in a table with an entity (its first relationship column, else its key): date_shift.
5. Free text (long values with spaces), or any detector match in what would be kept: drop.
6. Anything else: keep, with a note when few distinct values make it a possible quasi-identifier.
"""

import json
import math
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import polars as pl

from safetwin.detect.exprs import count_matches
from safetwin.detect.names import name_signals, words
from safetwin.spec.policy import load_policy_text, validate_policy

from .check import kind_of

SAMPLE_MIN_ROWS = 10_000
SAMPLE_SHARE = 0.01
DETECT_SHARE = 0.5  # the share of non-null sample values a validator must accept to say what a column holds
FREE_TEXT_MIN_LENGTH = 30
QI_MAX_DISTINCT_SHARE = 0.20
_KEY_WORDS = ("id", "key", "uuid", "guid")
_BARE = ("keep", "null", "drop")
_DETECTOR_NOUNS = {
    "email": "valid emails",
    "phone": "phone numbers",
    "card": "card numbers that pass Luhn",
    "iban": "valid IBANs",
    "ipv4": "IPv4 addresses",
    "ipv6": "IPv6 addresses",
    "uuid": "UUIDs",
}
_TABLE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_PLAIN_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_YAML_WORDS = {"true", "false", "null", "yes", "no", "on", "off", "y", "n"}


class ScanError(Exception):
    """The source can't be scanned. The message is safe to show (names and paths, no values)."""


@dataclass
class Profile:
    """What the sample says about one column: numbers only."""

    dtype: pl.DataType
    rows: int
    nulls: int
    distinct: int
    min_length: int | None = None
    max_length: int | None = None
    spaced_share: float = 0.0
    dates: int = 0  # text values that start with an ISO date
    matches: dict[str, int] = field(default_factory=dict)

    @property
    def non_null(self) -> int:
        return self.rows - self.nulls

    def share(self, detector: str) -> float:
        return self.matches.get(detector, 0) / self.non_null if self.non_null else 0.0

    @property
    def unique(self) -> bool:
        return self.nulls == 0 and self.rows > 0 and self.distinct == self.rows

    @property
    def free_text(self) -> bool:
        """Long values, most with a space: notes, comments, messages."""
        return (self.max_length or 0) >= FREE_TEXT_MIN_LENGTH and self.spaced_share >= DETECT_SHARE

    def describe(self) -> str:
        dtype = self.dtype
        shown = f"Datetime({dtype.time_unit})" if isinstance(dtype, pl.Datetime) else str(dtype)
        parts = [shown, f"{self.nulls / self.rows:.0%} null" if self.rows else "no rows"]
        parts.append(f"{self.distinct:,} distinct")
        if self.min_length is not None and self.max_length is not None:
            parts.append(f"length {self.min_length} to {self.max_length}")
        return ", ".join(parts)


@dataclass
class Suggestion:
    method: dict[str, Any]
    reasons: list[str]


@dataclass
class ScannedTable:
    name: str
    file: str  # the file name in the source folder
    rows: int
    sampled: int
    columns: dict[str, Profile]
    suggestions: dict[str, Suggestion] = field(default_factory=dict)


@dataclass
class ScanResult:
    tables: dict[str, ScannedTable]
    relationships: list[str]
    fmt: str  # csv, parquet, xlsx, or postgres
    notes: list[str]


# --- tables and samples ------------------------------------------------------------------------------------


def _formats(folder: Path, fmt: str | None) -> str:
    present = {
        ext
        for ext in ("parquet", "csv", "xlsx")
        if any(n.endswith(f".{ext}") and not n.startswith((".", "~$")) for n in os.listdir(folder))
    }
    if fmt is not None:
        if fmt not in present:
            raise ScanError(f"{folder} has no .{fmt} file")
        return fmt
    if not present:
        raise ScanError(f"{folder} has no .parquet, .csv or .xlsx file")
    return next(ext for ext in ("parquet", "csv", "xlsx") if ext in present)


def table_name(stem: str) -> str:
    """A table name the policy accepts, from a file stem: lower case, `_` for anything else."""
    name = re.sub(r"[^a-z0-9_]+", "_", stem.lower()).strip("_")
    if not name or not name[0].isalpha():
        name = f"t_{name}"
    return name[:63]


def _lazy(path: Path, fmt: str, delimiter: str) -> pl.LazyFrame:
    if fmt == "parquet":
        return pl.scan_parquet(path, glob=False, hive_partitioning=False)
    return pl.scan_csv(path, separator=delimiter, infer_schema=False, glob=False)


def _sample(lf: pl.LazyFrame) -> tuple[int, pl.DataFrame]:
    rows = int(lf.select(pl.len()).collect(engine="streaming").item())
    want = max(SAMPLE_MIN_ROWS, math.ceil(rows * SAMPLE_SHARE))
    if rows <= want:
        return rows, lf.collect(engine="streaming")
    return rows, lf.gather_every(rows // want).head(want).collect(engine="streaming")


def _profile(sample: pl.DataFrame) -> dict[str, Profile]:
    exprs: list[pl.Expr] = []
    text = [c for c, t in sample.schema.items() if kind_of(t) == "text"]
    for i, c in enumerate(sample.columns):
        exprs += [pl.col(c).null_count().alias(f"n{i}"), pl.col(c).n_unique().alias(f"u{i}")]
        if c in text:
            s = pl.col(c).cast(pl.String)
            exprs += [
                s.str.len_chars().min().alias(f"lo{i}"),
                s.str.len_chars().max().alias(f"hi{i}"),
                s.str.contains(" ").mean().alias(f"sp{i}"),
                s.str.contains(r"^\d{4}-\d{2}-\d{2}").sum().alias(f"d{i}"),
            ]
    facts = sample.select(exprs).row(0, named=True) if exprs else {}
    profiles: dict[str, Profile] = {}
    for i, c in enumerate(sample.columns):
        nulls = int(facts[f"n{i}"])
        distinct = int(facts[f"u{i}"]) - (1 if nulls else 0)  # n_unique counts null as a value
        p = Profile(sample.schema[c], sample.height, nulls, distinct)
        if c in text:
            p.min_length, p.max_length = facts[f"lo{i}"], facts[f"hi{i}"]
            p.spaced_share = float(facts[f"sp{i}"] or 0.0)
            p.dates = int(facts[f"d{i}"] or 0)
        profiles[c] = p
    for (column, detector), count in count_matches(sample).items():
        profiles[column].matches[detector] = count
    return profiles


# --- suggestions -------------------------------------------------------------------------------------------


def _m(method: str, **settings: Any) -> dict[str, Any]:
    return {"method": method, **settings}


def _pii(column: str, p: Profile) -> Suggestion | None:
    """Rule 2: what the name or the values say the column holds."""
    kind = kind_of(p.dtype)
    signals = name_signals(column)
    ws = words(column)
    reasons = [f'name matches "{s}"' for s in signals]
    found = {d: p.share(d) for d in _DETECTOR_NOUNS if p.share(d) >= DETECT_SHARE}
    if p.free_text and not signals:
        return None  # values found inside free text don't make it an email column: rule 5 drops it
    reasons += [f"{share:.0%} of the sample are {_DETECTOR_NOUNS[d]}" for d, share in found.items()]

    def text_or_null(method: dict[str, Any]) -> Suggestion:
        if kind == "text":
            return Suggestion(method, reasons)
        return Suggestion(_m("null"), [*reasons, f"{method['method']} needs a text column, so null"])

    if "email" in found or "email" in signals:
        return text_or_null(_m("fake", kind="email"))
    if "card" in found or "card" in signals:
        return text_or_null(_m("redact", keep_last=4))
    if "iban" in found or "iban" in signals:
        return text_or_null(_m("redact", keep_last=4))
    if "national_id" in signals:
        return Suggestion(_m("null"), reasons)
    if "phone" in found or "phone" in signals:
        return text_or_null(_m("fake", kind="phone"))
    if "ipv4" in found or "ipv6" in found or "ip" in signals:
        return text_or_null(_m("generalize", ip=True))
    if "uuid" in found and kind == "text":
        return Suggestion(_m("pseudonymize", format="uuid"), reasons)
    if "birth_date" in signals:
        if kind in ("date", "datetime"):
            return Suggestion(_m("generalize", to="year"), reasons)
        if kind == "text":
            year = "keeps the first 4 characters (a year)"
            return Suggestion(_m("generalize", keep_chars=4), [*reasons, year])
        return Suggestion(_m("null"), reasons)
    if "postcode" in signals:
        return text_or_null(_m("generalize", keep_chars=3))
    if "address" in signals:
        return text_or_null(_m("fake", kind="street"))
    if "user_agent" in signals:
        return Suggestion(_m("null"), reasons)
    if "geo" in signals:
        if kind == "float":
            return Suggestion(_m("generalize", bucket=0.1), [*reasons, "rounded down to 0.1 degree"])
        return Suggestion(_m("null"), reasons)
    if "name" in signals:
        if "company" in ws:
            return text_or_null(_m("fake", kind="company"))
        if set(ws) & {"first", "given", "forename"}:
            return text_or_null(_m("fake", kind="first_name"))
        if set(ws) & {"last", "surname", "family"}:
            return text_or_null(_m("fake", kind="last_name"))
        if set(ws) <= {"name", "full", "customer", "user", "person", "contact", "display", "client"}:
            return text_or_null(_m("fake", kind="name"))
    return None


Reference = tuple[str, str, str, str]


def _known_references(
    tables: dict[str, ScannedTable], known: Sequence[Reference]
) -> dict[tuple[str, str], tuple[str, str, str]]:
    """The references of `known` foreign keys between scanned columns, each target column its own domain."""
    out: dict[tuple[str, str], tuple[str, str, str]] = {}
    for table, column, target, target_column in known:
        if (
            table in tables
            and target in tables
            and column in tables[table].columns
            and target_column in tables[target].columns
            and table != target
        ):
            out[(table, column)] = (target, target_column, f"{target}.{target_column}")
    return out


def _references(tables: dict[str, ScannedTable]) -> dict[tuple[str, str], tuple[str, str, str]]:
    """`(table, column)` of each `<thing>_id` column → (target table, target column, domain)."""
    out: dict[tuple[str, str], tuple[str, str, str]] = {}
    for t in tables.values():
        for column in t.columns:
            ws = words(column)
            if len(ws) < 2 or ws[-1] != "id":
                continue
            thing = "_".join(ws[:-1])
            plural = f"{thing[:-1]}ies" if thing.endswith("y") else ""
            for target in (thing, f"{thing}s", f"{thing}es", plural):
                if target in tables and target != t.name and "id" in tables[target].columns:
                    domain = thing if re.fullmatch(r"[a-z][a-z0-9_]*", thing) else f"{target}.id"
                    out[(t.name, column)] = (target, "id", domain)
                    break
    return out


def _is_key(column: str, p: Profile) -> bool:
    ws = words(column)
    return bool(ws) and ws[-1] in _KEY_WORDS and kind_of(p.dtype) in ("integer", "text")


def suggest(tables: dict[str, ScannedTable], known: Sequence[Reference] | None = None) -> list[str]:
    """Fill in every table's suggestions; return the relationships found: `known` ones (a database's foreign
    keys, `(table, column, target table, target column)`) instead of guesses from the column names."""
    refs = _references(tables) if known is None else _known_references(tables, known)
    referenced = {(target, col): domain for (target, col, domain) in refs.values()}
    relationships = [f"{t}.{c} -> {target}.{tc}" for (t, c), (target, tc, _) in refs.items()]
    keys: dict[str, str] = {}  # table → the column whose value names the entity a row belongs to
    for t in tables.values():
        for column, p in t.columns.items():
            if p.non_null == 0:
                t.suggestions[column] = Suggestion(_m("keep"), ["empty in the sample"])
            elif (s := _pii(column, p)) is not None:
                t.suggestions[column] = s
            elif (t.name, column) in refs:
                target, tc, domain = refs[(t.name, column)]
                t.suggestions[column] = Suggestion(
                    _m("pseudonymize", domain=domain), [f"points at {target}.{tc} (a relationship)"]
                )
                keys.setdefault(t.name, column)
            elif (t.name, column) in referenced:
                t.suggestions[column] = Suggestion(
                    _m("pseudonymize", domain=referenced[(t.name, column)]),
                    ["a key other tables point at" + (", unique in the sample" if p.unique else "")],
                )
            elif _is_key(column, p) and (p.unique or len(words(column)) > 1):
                why = "unique and non-null in the sample" if p.unique else "an id of another table?"
                t.suggestions[column] = Suggestion(_m("pseudonymize"), [f"looks like a key: {why}"])
        for column, s in t.suggestions.items():  # no relationship column: the table's own key
            if s.method["method"] == "pseudonymize":
                keys.setdefault(t.name, column)
    for t in tables.values():
        for column, p in t.columns.items():
            if column in t.suggestions:
                continue
            kind = kind_of(p.dtype)
            hits = {d: n for d, n in p.matches.items() if n and d in _DETECTOR_NOUNS}
            entity = keys.get(t.name)
            if kind in ("date", "datetime") and entity is not None:
                t.suggestions[column] = Suggestion(
                    _m("date_shift", entity=entity), [f"a date: shifted per {entity}, so intervals stay"]
                )
            elif hits:
                found = ", ".join(f"{n:,} {_DETECTOR_NOUNS[d]}" for d, n in hits.items())
                t.suggestions[column] = Suggestion(_m("drop"), [f"the sample has {found} in it"])
            elif kind == "text" and p.free_text:
                t.suggestions[column] = Suggestion(_m("drop"), ["free text (long values with spaces)"])
            elif kind == "text" and p.distinct > 1 and p.distinct <= QI_MAX_DISTINCT_SHARE * p.non_null:
                t.suggestions[column] = Suggestion(
                    _m("keep"), ["few distinct values: a possible quasi-identifier, consider generalize"]
                )
            else:
                reason = "no personal data found"
                if kind in ("date", "datetime"):
                    reason += "; a date with no entity column to shift it by"
                elif kind == "text" and p.dates >= DETECT_SHARE * p.non_null:
                    reason += "; dates as text: date_shift needs a date column (a Parquet source)"
                t.suggestions[column] = Suggestion(_m("keep"), [reason])
    return relationships


# --- the scan and the draft --------------------------------------------------------------------------------


def scan(
    folder: Path,
    *,
    fmt: str | None = None,
    delimiter: str = ",",
    known: Sequence[Reference] | None = None,
    rows: Mapping[str, int] | None = None,
) -> ScanResult:
    """Scan every table of the folder. Raises `ScanError` when it has none or a file can't be read. An
    Excel folder is staged to Parquet first (`staging.py`). `known` relationships replace the guessed ones;
    `rows` gives the true row counts of tables that were copied in part (a Postgres sample)."""
    if not folder.is_dir():
        raise ScanError(f"{folder} is not a folder")
    fmt = _formats(folder, fmt)
    if fmt == "xlsx":
        from .staging import StagingError, stage_excel, staging_folder

        with staging_folder() as staged:
            try:
                stage_excel(folder, staged)
            except StagingError as err:
                raise ScanError(str(err)) from None
            result = scan(staged, fmt="parquet")
        result.fmt = "xlsx"
        for t in result.tables.values():
            t.file = f"{t.name}.xlsx"
        return result
    notes = []
    if fmt == "parquet" and any(n.endswith(".csv") for n in os.listdir(folder)):
        notes.append("the folder has Parquet and CSV files: Parquet was scanned (--format csv for the other)")
    tables: dict[str, ScannedTable] = {}
    for file in sorted(os.listdir(folder)):
        if not file.endswith(f".{fmt}") or file.startswith("."):
            continue
        name = table_name(file.removesuffix(f".{fmt}"))
        if name in tables:
            raise ScanError(f"'{file}' and '{tables[name].file}' would both be table '{name}': rename one")
        try:
            count, sample = _sample(_lazy(folder / file, fmt, delimiter))
            profiles = _profile(sample)
        except (pl.exceptions.PolarsError, OSError) as err:
            raise ScanError(f"'{file}' can't be read ({type(err).__name__})") from None
        total = rows[name] if rows is not None and name in rows else count
        tables[name] = ScannedTable(name, file, total, sample.height, profiles)
    relationships = suggest(tables, known)
    return ScanResult(tables, relationships, fmt, notes)


def scan_postgres(url: str, schema: str) -> ScanResult:
    """Scan the tables of a Postgres schema: a sample of each (its first `SAMPLE_MIN_ROWS` rows, or 1% when
    that is more) is copied to a private staging folder and scanned; the database's foreign keys are the
    relationships. Raises `ScanError`."""
    from .staging import StagingError, connect, count_rows, read_facts, stage_postgres, staging_folder

    try:
        connection = connect(url, read_only=True)
    except StagingError as err:
        raise ScanError(str(err)) from None
    try:
        facts = read_facts(connection, schema)
        usable = [t for t in facts.tables if re.fullmatch(r"[a-z][a-z0-9_]{0,62}", t)]
        notes = [
            f"the table {t!r} was skipped: a policy names tables in lower case letters, digits and _"
            for t in facts.tables
            if t not in usable
        ]
        if facts.skipped_foreign_keys:
            notes.append(f"{facts.skipped_foreign_keys} foreign key(s) of several columns were left out")
        if not usable:
            raise ScanError(f"the schema {schema} has no table to scan")
        counts = {t: count_rows(connection, schema, t) for t in usable}
        with staging_folder() as staged:
            for table in usable:
                limit = max(SAMPLE_MIN_ROWS, math.ceil(counts[table] * SAMPLE_SHARE))
                stage_postgres(connection, schema, [table], staged, limit=limit)
            result = scan(staged, fmt="parquet", known=facts.foreign_keys, rows=counts)
    except StagingError as err:
        raise ScanError(str(err)) from None
    finally:
        connection.close()
    result.fmt = "postgres"
    result.notes = notes + result.notes
    return result


REVERSIBLE_ALGORITHMS = ("aes-siv", "aes-gcm", "auto")


def number_shaped(method: dict[str, Any]) -> bool:
    """Whether a suggestion is for a phone or card number (fake phone, redact keeping the last digits): the
    columns that `auto` encrypts with ff1, keeping their format."""
    return (method["method"] == "fake" and method.get("kind") == "phone") or (
        method["method"] == "redact" and method.get("keep_last") is not None
    )


def make_reversible(
    result: ScanResult, tables: Iterable[str] | None = None, algorithm: str = "aes-siv"
) -> None:
    """Turn the suggestions of `tables` (every table when None) reversible: each column they mask is
    encrypted instead, so the access key reads it back; kept columns stay kept. `algorithm` is `aes-siv`
    (every column), `aes-gcm` (every column but those that link tables, which need equal outputs) or `auto`
    (ff1 for text columns that look like phone or card numbers, so they keep their format; aes-siv for the
    rest). A relationship between a reversible table and a one-way table stays one-way on both sides
    (pseudonymized), so that it still joins and the one-way table holds nothing reversible."""
    if algorithm not in REVERSIBLE_ALGORITHMS:
        raise ValueError(f"algorithm is one of {', '.join(REVERSIBLE_ALGORITHMS)}")
    chosen = set(result.tables) if tables is None else set(tables)
    linked = {tuple(side.strip().split(".", 1)) for text in result.relationships for side in text.split("->")}
    for name in chosen:
        table = result.tables[name]
        for column, s in table.suggestions.items():
            if s.method["method"] == "keep":
                continue
            textual = result.fmt == "csv" or kind_of(table.columns[column].dtype) == "text"
            settings: dict[str, Any] = {}
            if (name, column) not in linked:
                if algorithm == "aes-gcm":
                    settings = {"algorithm": "aes-gcm"}
                elif algorithm == "auto" and textual and number_shaped(s.method):
                    settings = {"algorithm": "ff1"}
            s.reasons = [f"reversible (instead of {s.method['method']})", *s.reasons]
            s.method = _m("encrypt", **settings)
    changed = True
    while changed:  # until every relationship has the same method on both sides
        changed = False
        for text in result.relationships:
            (ta, ca), (tb, cb) = (side.strip().split(".", 1) for side in text.split("->"))
            sa, sb = result.tables[ta].suggestions[ca], result.tables[tb].suggestions[cb]
            for mine, theirs, other in ((sa, sb, f"{tb}.{cb}"), (sb, sa, f"{ta}.{ca}")):
                if mine.method["method"] == "encrypt" and theirs.method["method"] != "encrypt":
                    mine.method = dict(theirs.method)
                    mine.reasons = [f"one-way: it joins {other}, which is one-way"]
                    changed = True


def _yaml_key(name: str) -> str:
    return name if _PLAIN_KEY.match(name) and name.lower() not in _YAML_WORDS else json.dumps(name)


def _flow(method: dict[str, Any]) -> str:
    if len(method) == 1 and method["method"] in _BARE:
        return str(method["method"])
    settings = (f"{k}: {json.dumps(v) if isinstance(v, bool) else v}" for k, v in method.items())
    return "{ " + ", ".join(settings) + " }"


def policy_name(folder: Path) -> str:
    name = re.sub(r"[^a-z0-9]+", "-", folder.resolve().name.lower()).strip("-")
    return f"{name}-masking" if name else "masking-policy"


def render(
    result: ScanResult,
    *,
    source: str,
    name: str,
    target: str = "./safe",
    key: str = "env://SAFETWIN_KEY",
    delimiter: str = ",",
    target_format: str = "parquet",
    postgres: str | None = None,
    pg_schema: str = "public",
) -> str:
    """The draft policy as YAML text, with the reasons and profiles as comments. Checked before it is
    returned: it raises `AssertionError` if it isn't a valid policy (a bug, never the data's fault)."""
    mapped = result.fmt in ("csv", "parquet") and any(
        t.name != t.file.removesuffix(f".{result.fmt}") for t in result.tables.values()
    )
    lines = [
        "# Drafted by safetwin scan. Detection only suggests: review every column before you mask.",
        "# The comments give the reasons and the sample's profile (never a value).",
        "apiVersion: safetwin/v1",
        "kind: MaskingPolicy",
        "metadata:",
        f"  name: {name}",
        "spec:",
    ]
    extra = f", delimiter: {json.dumps(delimiter)}" if result.fmt == "csv" and delimiter != "," else ""
    if result.fmt == "postgres":
        assert postgres is not None, "a postgres scan needs the reference of its URL"
        lines.append(f"  source: {{ postgres: {postgres}, schema: {pg_schema} }}")
    elif mapped:
        lines.append(f"  source:\n    folder: {json.dumps(source)}\n    format: {result.fmt}")
        if extra:
            lines.append(f"    delimiter: {json.dumps(delimiter)}")
        lines.append("    tables:")
        lines += [f"      {t.name}: {json.dumps(t.file)}" for t in result.tables.values()]
    else:
        lines.append(f"  source: {{ folder: {json.dumps(source)}, format: {result.fmt}{extra} }}")
    lines += [
        f"  target: {{ folder: {json.dumps(target)}, format: {target_format} }}",
        f"  key: {key}",
        "  unknown_columns: fail",
        "  tables:",
    ]
    for t in result.tables.values():
        sampled = "all rows" if t.sampled == t.rows else f"a sample of {t.sampled:,}"
        lines.append(f"    {t.name}:  # {t.rows:,} rows, {sampled}")
        width = max(len(_yaml_key(c)) for c in t.columns) + 1
        for column, s in t.suggestions.items():
            label = f"{_yaml_key(column)}:".ljust(width)
            comment = "; ".join(s.reasons) + f" ({t.columns[column].describe()})"
            lines.append(f"      {label} {_flow(s.method)}  # {comment}")
    if result.relationships:
        lines.append("  relationships:")
        lines += [f"    - {r}" for r in result.relationships]
    text = "\n".join(lines) + "\n"
    problems = [p for p in validate_policy(load_policy_text(text)) if p.code != "key_reference"]
    assert not [p for p in problems if p.severity == "error"], problems
    return text
