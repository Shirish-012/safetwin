"""The masking policy (`kind: MaskingPolicy`, docs/guide.md): models, loading and the checks that need no
data.

A policy names a source and a target folder, a key *reference* (never a key), and a method for every column
of every table. It compiles to the internal pipeline format (`safetwin.masking.compile`). The checks that need
the source's columns and types (every column named, methods that fit the types) are in
`safetwin.masking.check`, because they need the data libraries and this module must not: the engine's
control plane imports `safetwin.spec`.

Messages never repeat a value of the file: they name tables, columns, methods and settings (docs/security.md).
"""

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Self, get_args

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StringConstraints,
    model_validator,
)

from safetwin.keys import is_reference

from .io import load_model
from .models import PipelineName
from .validate import Problem, find_secrets, redacted

TableName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,62}$")]
ColumnName = Annotated[str, StringConstraints(min_length=1, max_length=256)]
DomainName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")]
Number = StrictInt | StrictFloat
FakeKind = Literal["name", "first_name", "last_name", "email", "phone", "street", "city", "company", "text"]
FAKE_KINDS: tuple[str, ...] = get_args(FakeKind)
BARE_METHODS = ("keep", "null", "drop")
RELATIONSHIP = re.compile(r"^\s*([a-z][a-z0-9_]*)\.(\S+)\s*->\s*([a-z][a-z0-9_]*)\.(\S+)\s*$")

# The class of a column in the report (docs/guide.md).
ColumnClass = Literal["kept", "encrypted", "pseudonymized", "generalized", "removed", "partially_redacted"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Keep(_Model):
    """Copy the column as it is."""

    method: Literal["keep"]


class Null(_Model):
    """Replace every value by null (the column and its type stay)."""

    method: Literal["null"]


class Drop(_Model):
    """Leave the column out of the output."""

    method: Literal["drop"]


class Pseudonymize(_Model):
    """A keyed, deterministic replacement: equal inputs give equal outputs within a domain."""

    method: Literal["pseudonymize"]
    domain: DomainName | None = None  # default: <table>.<column>
    format: Literal["auto", "hex", "int", "uuid"] = "auto"
    prefix: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_:.-]{0,32}$")] = ""

    @model_validator(mode="after")
    def _prefix_is_for_text(self) -> Self:
        if self.prefix and self.format in ("int", "uuid"):
            raise ValueError(f"prefix is for text pseudonyms: format {self.format} can't have one")
        return self


class Encrypt(_Model):
    """Reversible: whoever holds the key's access key (or the key) reads the values back with `safetwin
    unmask`. `algorithm`:

    - `aes-siv` (the default): equal inputs give equal outputs, in every column, so relationships hold;
    - `aes-gcm`: a random nonce per value, so equal inputs give different outputs (no relationship, nothing
      shows which values are equal); any AES-GCM library decrypts it;
    - `ff1`: format-preserving (NIST SP 800-38G) on a text column: the characters of `alphabet` (`digits`,
      the default, or `alphanumeric`) are encrypted, every other one stays, and the length stays. `domain`
      is its tweak: columns that join need the same one. A value with too few such characters (6 digits, 4
      letters or digits) is emptied.
    """

    method: Literal["encrypt"]
    algorithm: Literal["aes-siv", "aes-gcm", "ff1"] = "aes-siv"
    alphabet: Literal["digits", "alphanumeric"] | None = None
    domain: DomainName | None = None

    @model_validator(mode="after")
    def _ff1_settings(self) -> Self:
        if self.algorithm != "ff1" and (self.alphabet is not None or self.domain is not None):
            raise ValueError("alphabet and domain are settings of algorithm ff1")
        return self


class Fake(_Model):
    """Realistic text of a kind, consistent per input (keyed) or random per row."""

    method: Literal["fake"]
    kind: FakeKind
    locale: Literal["en"] = "en"
    consistent: StrictBool = True


class Generalize(_Model):
    """A coarser value of the same type: exactly one of `to`, `bucket`, `bins`, `keep_chars` and `ip`."""

    method: Literal["generalize"]
    to: Literal["year", "month", "week", "day"] | None = None
    bucket: Annotated[Number, Field(gt=0)] | None = None
    bins: Annotated[list[Number], Field(min_length=1, max_length=1000)] | None = None
    keep_chars: Annotated[StrictInt, Field(ge=1, le=1000)] | None = None
    ip: Literal[True] | None = None

    @model_validator(mode="after")
    def _one_setting(self) -> Self:
        given = [
            name for name in ("to", "bucket", "bins", "keep_chars", "ip") if getattr(self, name) is not None
        ]
        if len(given) != 1:
            raise ValueError("give exactly one of to, bucket, bins, keep_chars and ip")
        if self.bins is not None and any(b >= a for a, b in zip(self.bins[1:], self.bins, strict=False)):
            raise ValueError("bins must be in increasing order, without repeats")
        return self


class DateShift(_Model):
    """Move every date of an entity by the same keyed offset (never 0 days)."""

    method: Literal["date_shift"]
    entity: ColumnName
    max_days: Annotated[StrictInt, Field(ge=1, le=36500)] = 30


class Redact(_Model):
    """Hide characters: keep the last or first N (the rest become `char`), or replace the whole value."""

    model_config = ConfigDict(populate_by_name=True)

    method: Literal["redact"]
    keep_last: Annotated[StrictInt, Field(ge=0, le=1000)] | None = None
    keep_first: Annotated[StrictInt, Field(ge=0, le=1000)] | None = None
    char: Annotated[str, StringConstraints(min_length=1, max_length=1)] = "*"
    with_: Annotated[str, StringConstraints(max_length=200)] | None = Field(default=None, alias="with")

    @model_validator(mode="after")
    def _one_setting(self) -> Self:
        given = [n for n in ("keep_last", "keep_first", "with_") if getattr(self, n) is not None]
        if len(given) != 1:
            raise ValueError("give exactly one of keep_last, keep_first and with")
        if self.with_ is not None and "char" in self.model_fields_set:
            raise ValueError("char is for keep_last and keep_first: with replaces the whole value")
        return self


Method = Annotated[
    Keep | Null | Drop | Encrypt | Pseudonymize | Fake | Generalize | DateShift | Redact,
    Field(discriminator="method"),
]


def _bare_method(value: Any) -> Any:
    """`keep`, `drop`, `null` (a string, or YAML's null) stand for `{method: ...}`."""
    if value is None:
        return {"method": "null"}
    if isinstance(value, str):
        if value in BARE_METHODS:
            return {"method": value}
        raise ValueError("a method given by name alone can only be keep, null or drop: write {method: ...}")
    return value


ColumnSpec = Annotated[
    Method,
    BeforeValidator(_bare_method, json_schema_input_type=Method | Literal["keep", "null", "drop"] | None),
]


SchemaName = Annotated[str, StringConstraints(pattern=r"^[a-z_][a-z0-9_]{0,62}$")]
FileFormat = Literal["csv", "parquet", "xlsx"]


class Source(_Model):
    """Where the production data is: a folder of CSV, Parquet or Excel files (one table per file stem by
    default; one per sheet for a workbook with several), or a Postgres schema (read-only)."""

    model_config = ConfigDict(populate_by_name=True)

    folder: Annotated[str, StringConstraints(min_length=1)] | None = None
    format: FileFormat | None = None
    tables: dict[TableName, Annotated[str, StringConstraints(min_length=1)]] | None = None  # name -> glob
    delimiter: Annotated[str, StringConstraints(pattern=r"^[\t -~]$")] = ","  # CSV only
    postgres: Annotated[str, StringConstraints(min_length=1)] | None = None  # env://NAME or file://PATH
    pg_schema: SchemaName = Field(default="public", alias="schema")  # Postgres only

    @model_validator(mode="after")
    def _one_kind(self) -> Self:
        if (self.folder is None) == (self.postgres is None):
            raise ValueError("give either folder (with format) or postgres")
        if self.folder is not None and self.format is None:
            raise ValueError("a folder source needs a format: csv, parquet or xlsx")
        if self.postgres is not None and (self.format is not None or self.tables is not None):
            raise ValueError("a postgres source takes schema, not format or tables (its tables: spec.tables)")
        if self.format == "xlsx" and self.tables is not None:
            raise ValueError("an xlsx source names its tables after its files and sheets: leave out tables")
        return self


class Target(_Model):
    """Where the safe twin goes. `safetwin mask --out` overrides the folder. With `postgres`, the twin goes
    into that database's `schema` (never the source's), and the folder gets the report."""

    model_config = ConfigDict(populate_by_name=True)

    folder: Annotated[str, StringConstraints(min_length=1)]
    format: FileFormat = "parquet"
    compression: Literal["zstd"] = "zstd"
    postgres: Annotated[str, StringConstraints(min_length=1)] | None = None
    pg_schema: SchemaName | None = Field(default=None, alias="schema")

    @model_validator(mode="after")
    def _schema_for_postgres(self) -> Self:
        if (self.postgres is None) != (self.pg_schema is None):
            raise ValueError("a postgres target needs both postgres and schema")
        if self.postgres is not None and "format" in self.model_fields_set:
            raise ValueError("a postgres target writes tables, not files: leave out format")
        return self


def staged_source(source: Source) -> bool:
    """Whether the source is copied to Parquet before a run (Postgres, Excel): the engine reads files of
    one plain format."""
    return source.postgres is not None or source.format == "xlsx"


def staged_target(target: Target) -> bool:
    """Whether the twin is written as Parquet first, then delivered (Postgres, Excel)."""
    return target.postgres is not None or target.format == "xlsx"


def engine_format(source: Source) -> Literal["csv", "parquet"]:
    """The file format the engine reads: Parquet for a staged source."""
    return "parquet" if staged_source(source) or source.format == "parquet" else "csv"


class Subset(_Model):
    """A smaller twin (docs/guide.md): `fraction` of the rows of `root`, chosen by a keyed hash of its
    `key` column (stable across runs), plus every row that keeps the relationships valid."""

    root: TableName
    fraction: Annotated[StrictFloat | StrictInt, Field(gt=0, le=1)]
    key: ColumnName | None = None  # default: the root's column that relationships point at
    include_children: StrictBool = True


class PolicyMetadata(_Model):
    name: PipelineName
    description: str | None = None


class PolicySpec(_Model):
    source: Source
    target: Target
    key: Annotated[str, StringConstraints(min_length=1)]
    unknown_columns: Literal["fail", "null", "drop"] = "fail"
    tables: Annotated[
        dict[TableName, Annotated[dict[ColumnName, ColumnSpec], Field(min_length=1)]], Field(min_length=1)
    ]
    relationships: list[Annotated[str, StringConstraints(pattern=RELATIONSHIP.pattern)]] = Field(
        default_factory=list
    )
    subset: Subset | None = None


class MaskingPolicy(_Model):
    """A policy file."""

    apiVersion: Literal["safetwin/v1"]
    kind: Literal["MaskingPolicy"]
    metadata: PolicyMetadata
    spec: PolicySpec


def load_policy_file(path: Path) -> MaskingPolicy:
    """Load a policy. Raises `SpecError` if it isn't a valid policy and `OSError` if it can't be read."""
    return load_model(path.read_bytes(), MaskingPolicy)


def load_policy_text(text: str) -> MaskingPolicy:
    return load_model(text, MaskingPolicy)


# --- facts about a policy ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Relationship:
    from_table: str
    from_column: str
    to_table: str
    to_column: str

    @property
    def text(self) -> str:
        return f"{self.from_table}.{self.from_column} -> {self.to_table}.{self.to_column}"


def relationships(policy: MaskingPolicy) -> list[Relationship]:
    out = []
    for text in policy.spec.relationships:
        match = RELATIONSHIP.fullmatch(text)
        if match is not None:  # the model's pattern guarantees it
            out.append(Relationship(*match.groups()))
    return out


def default_domain(table: str, column: str) -> str:
    return f"{table}.{column}"


def pseudonym_domain(policy: MaskingPolicy, table: str, column: str) -> str | None:
    """The pseudonymize domain of a column, or None when the column is not pseudonymized."""
    spec = policy.spec.tables.get(table, {}).get(column)
    if isinstance(spec, Pseudonymize):
        return spec.domain or default_domain(table, column)
    return None


class EntityDomainError(ValueError):
    """A kept entity column points (through relationships) at more than one column."""


def entity_domain(policy: MaskingPolicy, table: str, entity: str) -> str:
    """The domain a date shift draws its offset from, so all dates of one customer move together across
    tables:

    - the entity column's pseudonymize domain, if it has one;
    - else, following the relationships from the entity column (`orders.customer_id -> customers.id`) to the
      column at the end of the chain, `<table>.<column>` of that column (`customers.id`);
    - else `<table>.<entity column>`.

    Raises `EntityDomainError` when a column of the chain points at two different columns.
    """
    if (domain := pseudonym_domain(policy, table, entity)) is not None:
        return domain
    rels = relationships(policy)
    current, seen = (table, entity), {(table, entity)}
    while True:
        targets = {(r.to_table, r.to_column) for r in rels if (r.from_table, r.from_column) == current}
        if len(targets) > 1:
            raise EntityDomainError(
                f"the date_shift entity {table}.{redacted(entity)} leads through spec.relationships to "
                f"{len(targets)} different columns, so its dates can't share one shift: keep one "
                "relationship per column"
            )
        if not targets or (nxt := targets.pop()) in seen:
            return pseudonym_domain(policy, *current) or default_domain(*current)
        current = nxt
        seen.add(current)


def column_class(spec: Method) -> ColumnClass:
    """The report class of a column (docs/guide.md sections 2 and 3)."""
    match spec:
        case Keep():
            return "kept"
        case Encrypt():
            return "encrypted"
        case Pseudonymize() | DateShift():
            return "pseudonymized"
        case Fake():
            return "pseudonymized" if spec.consistent else "removed"
        case Generalize():
            return "generalized"
        case Redact():
            return "removed" if spec.with_ is not None else "partially_redacted"
        case _:
            return "removed"


def method_params(spec: Method) -> dict[str, Any]:
    """The settings of a method, for the report: what the policy set, without `method`."""
    return spec.model_dump(by_alias=True, exclude_unset=True, exclude={"method"})


# --- checks that need no data ----------------------------------------------------------------------------


def _error(code: str, message: str) -> Problem:
    return Problem("error", code, message)


def validate_policy(policy: MaskingPolicy) -> list[Problem]:
    """Every problem of the policy that can be found without the data."""
    return [
        *_check_key(policy),
        *_check_relationships(policy),
        *_check_entities(policy),
        *_check_subset(policy),
        *_check_secrets(policy),
    ]


def _check_key(policy: MaskingPolicy) -> Iterator[Problem]:
    key = policy.spec.key
    if key.startswith("keychain://"):
        yield _error(
            "unsupported_key", "spec.key: keychain:// keys are not supported yet: use env:// or file://"
        )
    elif not is_reference(key) or not key.startswith(("env://", "file://")):
        yield _error(
            "key_reference",
            "spec.key must be a reference to the key (env://NAME or file://PATH), never the key itself",
        )
    for where, ref in (
        ("spec.source", policy.spec.source.postgres),
        ("spec.target", policy.spec.target.postgres),
    ):
        if ref is not None and (not is_reference(ref) or not ref.startswith(("env://", "file://"))):
            yield _error(
                "url_reference",
                f"{where}.postgres must be a reference to the database URL (env://NAME or file://PATH), "
                "never the URL itself: it can hold a password",
            )


def _side_ok(policy: MaskingPolicy, table: str, column: str, where: str) -> Iterator[Problem]:
    if table not in policy.spec.tables:
        yield _error(
            "unknown_table", f"spec.relationships: {where} names table '{table}', which spec.tables lacks"
        )
    elif column not in policy.spec.tables[table]:
        yield _error(
            "unknown_column",
            f"spec.relationships: {where} names column '{redacted(column)}' of '{table}', which spec.tables "
            f"doesn't name",
        )


def _check_relationships(policy: MaskingPolicy) -> Iterator[Problem]:
    for rel in relationships(policy):
        problems = [
            *_side_ok(policy, rel.from_table, rel.from_column, f"'{redacted(rel.text)}'"),
            *_side_ok(policy, rel.to_table, rel.to_column, f"'{redacted(rel.text)}'"),
        ]
        yield from problems
        if problems:
            continue
        a = policy.spec.tables[rel.from_table][rel.from_column]
        b = policy.spec.tables[rel.to_table][rel.to_column]
        if isinstance(a, Keep) and isinstance(b, Keep):
            continue
        if isinstance(a, Encrypt) and isinstance(b, Encrypt):
            if "aes-gcm" in (a.algorithm, b.algorithm):
                yield _error(
                    "relationship_domain",
                    f"spec.relationships: '{redacted(rel.text)}' joins a column encrypted with aes-gcm, "
                    "whose equal values give different outputs: use aes-siv (or ff1) on both sides",
                )
            elif (a.algorithm, a.alphabet or "digits", a.domain) != (
                b.algorithm,
                b.alphabet or "digits",
                b.domain,
            ):
                yield _error(
                    "relationship_domain",
                    f"spec.relationships: '{redacted(rel.text)}' joins columns encrypted differently: give "
                    "both sides the same algorithm (and for ff1 the same alphabet and domain)",
                )
            continue  # equal values, equal ciphertexts: the relationship holds
        da = pseudonym_domain(policy, rel.from_table, rel.from_column)
        db = pseudonym_domain(policy, rel.to_table, rel.to_column)
        if da is None or db is None or da != db:
            yield _error(
                "relationship_domain",
                f"spec.relationships: '{redacted(rel.text)}' joins columns that must both be pseudonymized "
                "with the same domain, both encrypted, or both kept",
            )
        elif isinstance(a, Pseudonymize) and isinstance(b, Pseudonymize) and a.format != b.format:
            yield _error(
                "relationship_domain",
                f"spec.relationships: '{redacted(rel.text)}' joins pseudonyms of different formats "
                f"({a.format} and {b.format}): give both sides the same format",
            )


def _check_entities(policy: MaskingPolicy) -> Iterator[Problem]:
    for table, columns in policy.spec.tables.items():
        for column, spec in columns.items():
            if isinstance(spec, DateShift) and spec.entity not in columns:
                yield _error(
                    "unknown_column",
                    f"spec.tables.{table}.{redacted(column)}: date_shift entity "
                    f"'{redacted(spec.entity)}' is not a column of '{table}' in the policy",
                )
            elif isinstance(spec, DateShift):
                try:
                    entity_domain(policy, table, spec.entity)
                except EntityDomainError as err:
                    yield _error("entity_domain", f"spec.tables.{table}.{redacted(column)}: {err}")


def subset_key(policy: MaskingPolicy) -> str | None:
    """The column of the subset's root whose value decides if a row is picked: `subset.key`, else the one
    column of the root that relationships point at (None when there is no such single column)."""
    subset = policy.spec.subset
    if subset is None:
        return None
    if subset.key is not None:
        return subset.key
    targets = {r.to_column for r in relationships(policy) if r.to_table == subset.root}
    return targets.pop() if len(targets) == 1 else None


def _check_subset(policy: MaskingPolicy) -> Iterator[Problem]:
    subset = policy.spec.subset
    if subset is None:
        return
    if subset.root not in policy.spec.tables:
        yield _error("unknown_table", f"spec.subset.root: '{subset.root}' is not a table of spec.tables")
        return
    key = subset_key(policy)
    if key is None:
        yield _error(
            "subset_key",
            f"spec.subset: give key, the column of '{subset.root}' whose value picks a row (no single column "
            "of it is the target of a relationship)",
        )
    elif key not in policy.spec.tables[subset.root]:
        yield _error(
            "unknown_column",
            f"spec.subset.key: '{redacted(key)}' is not a column of '{subset.root}' in the policy",
        )


def _check_secrets(policy: MaskingPolicy) -> Iterator[Problem]:
    data = {
        "metadata": policy.metadata.model_dump(exclude_unset=True),
        "spec": policy.spec.model_dump(exclude_unset=True, by_alias=True),
    }
    for scope, value in data.items():
        for where, kind in find_secrets(value, scope):
            yield _error(
                "inline_secret",
                f"{where} looks like a secret ({kind}). Don't put keys or tokens in the policy: refer to "
                "them with env://NAME or file://PATH",
            )
