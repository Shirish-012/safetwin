"""The `transform.mask` operator: every column of one table through its method, in one Polars step.

Its config (written by the policy compiler, `compile.py`) holds the method of every column and the domain
of each keyed method, never key material, and with `subset: true` it first keeps only the rows of a subset
(the filter comes from the run context, because it holds data values):

    {table: customers, columns: {id: {spec: {method: pseudonymize, domain: customer}, domain: customer}, ...}}

The subkeys come from the run context (`RunContext.subkeys`, memory only). The step is one `map_batches` in
the stage's streaming query (the fused path): each batch is masked column by column, and the keyed methods
hash each distinct value of the batch once. Row order is unchanged, and so is the row count without a
subset.
"""

from collections.abc import Mapping
from functools import partial
from typing import Annotated, Any

import polars as pl
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from safetwin.spec.models import Node
from safetwin.spec.policy import (
    ColumnSpec,
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
)

from ..dataplane.operators import ConfigError, Transform, no_such_columns
from . import methods
from .hmacs import Mac, is_text
from .portable import Sealer

# The subkey use of `encrypt`: one access key per masking key, for every column (`Subkeys.sealer`).
ENCRYPT_USE = ("encrypt", "access")


class ColumnStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    spec: ColumnSpec
    domain: str | None = None  # the subkey domain of a keyed method (date_shift: the entity's domain)


class MaskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    table: str
    columns: Annotated[dict[str, ColumnStep], Field(min_length=1)]
    subset: bool = False  # keep only the rows of the subset (the filter comes from the run context)


def parse_mask_config(node: Node) -> MaskConfig:
    try:
        return MaskConfig.model_validate(node.config)
    except ValidationError as err:
        problems = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'config'}: {e['msg'].removeprefix('Value error, ')}"
            for e in err.errors(include_url=False, include_input=False, include_context=False)
        )
        raise ConfigError(f"{node.id} ({node.operator}): {problems}") from None


def subkey_use(column: str, step: ColumnStep) -> tuple[str, str] | None:
    """The (method, domain) subkey a column needs, or None for an unkeyed method."""
    spec = step.spec
    if isinstance(spec, Encrypt):
        return ENCRYPT_USE
    if (
        isinstance(spec, Pseudonymize)
        or (isinstance(spec, Fake) and spec.consistent)
        or isinstance(spec, DateShift)
    ):
        if step.domain is None:
            raise ValueError(f"column '{column}' needs a domain for {spec.method}")
        return spec.method, step.domain
    return None


def classification(node: Node) -> dict[str, str]:
    """The report class of each column the step outputs (dropped columns are left out)."""
    config = parse_mask_config(node)
    return {name: column_class(c.spec) for name, c in config.columns.items() if not isinstance(c.spec, Drop)}


def build_mask_step(node: Node, ctx: Any) -> Transform:
    config = parse_mask_config(node)
    macs: dict[str, Mac | Sealer] = {}
    for name, step in config.columns.items():
        try:
            use = subkey_use(name, step)
        except ValueError as err:
            raise ConfigError(f"{node.id} ({node.operator}): {err}") from None
        if use is None:
            continue
        subkeys = getattr(ctx, "subkeys", None)
        if subkeys is None:
            raise ConfigError(
                f"{node.id} ({node.operator}): needs the masking key, which only `safetwin mask` provides"
            )
        try:
            macs[name] = subkeys.sealer() if use == ENCRYPT_USE else subkeys.mac(*use)
        except LookupError as err:
            raise ConfigError(f"{node.id} ({node.operator}): {err}") from None
    stats = methods.MaskStats() if ctx is None else ctx.mask_stats.setdefault(node.id, methods.MaskStats())
    row_filter = None
    if config.subset:
        row_filter = getattr(ctx, "subset_filters", {}).get(config.table)
        if row_filter is None:
            raise ConfigError(
                f"{node.id} ({node.operator}): needs the subset's selection, which only `safetwin mask` makes"
            )

    def apply(frame: pl.LazyFrame) -> pl.LazyFrame:
        schema = frame.collect_schema()
        missing = [name for name in config.columns if name not in schema]
        if missing:
            raise no_such_columns(node, missing, schema.names())
        unnamed = [name for name in schema.names() if name not in config.columns]
        if unnamed:
            raise ConfigError(
                f"{node.id} ({node.operator}): the policy names no method for {', '.join(map(repr, unnamed))}"
            )
        for step in config.columns.values():
            if isinstance(step.spec, DateShift) and step.spec.entity not in schema:
                raise no_such_columns(node, [step.spec.entity], schema.names())
        out_schema = {
            name: methods.output_dtype(config.columns[name].spec, dtype)
            for name, dtype in schema.items()
            if not isinstance(config.columns[name].spec, Drop)
        }
        if row_filter is not None:
            frame = frame.filter(row_filter)
        return frame.map_batches(
            partial(mask_frame, columns=config.columns, macs=macs, stats=stats),
            schema=out_schema,
            streamable=True,
            predicate_pushdown=False,
            projection_pushdown=False,
            slice_pushdown=False,
        )

    return apply


def mask_column(
    df: pl.DataFrame,
    name: str,
    step: ColumnStep,
    mac: Mac | Sealer | None,
    stats: methods.MaskStats | None,
) -> pl.Series:
    """One column of a batch through its method."""
    series = df.get_column(name)
    spec = step.spec
    if is_text(series.dtype) and series.dtype != pl.String and not isinstance(spec, Keep | Null):
        series = series.cast(pl.String)  # Categorical and Enum: every method works on their text
    match spec:
        case Keep():
            return series
        case Null():
            return methods.null(series)
        case Encrypt():
            assert isinstance(mac, Sealer)
            return methods.encrypt(series, spec, mac, stats)
        case Pseudonymize():
            assert isinstance(mac, Mac)
            return methods.pseudonymize(series, mac, spec.format, spec.prefix)
        case Fake():
            assert mac is None or isinstance(mac, Mac)
            return methods.fake(series, spec, mac)
        case Generalize():
            return methods.generalize(series, spec, stats)
        case DateShift():
            assert isinstance(mac, Mac)
            entity = df.get_column(spec.entity)
            if is_text(entity.dtype):
                entity = entity.cast(pl.String)
            return methods.date_shift(series, entity, mac, spec.max_days, stats)
        case Redact():
            return methods.redact(series, spec)
    raise ConfigError(f"no method for column '{name}'")


def mask_frame(
    df: pl.DataFrame,
    *,
    columns: Mapping[str, ColumnStep],
    macs: Mapping[str, Mac | Sealer],
    stats: methods.MaskStats | None = None,
) -> pl.DataFrame:
    """A batch masked: its columns in their order, without the dropped ones. Same rows, same order."""
    out = [
        mask_column(df, name, columns[name], macs.get(name), stats).alias(name)
        for name in df.columns
        if not isinstance(columns[name].spec, Drop)
    ]
    return pl.DataFrame(out, height=df.height) if not out else pl.DataFrame(out)
