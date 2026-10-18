"""Subset selection (docs/guide.md): which rows of each table a smaller twin keeps.

A pre-pass before the stages run, on the key columns only (the columns of the relationships and the root's
key), read from the input:

1. **Root rows:** a row of the root table is in when `HMAC(subkey("subset", <root>), canonical bytes of its
   key)`, read as a 64-bit number, is below `fraction` * 2^64. The same key picks the same rows on every run,
   and a row added later doesn't change which earlier rows are in.
2. **Parents, always:** for every relationship `child.c -> parent.k`, the parent rows whose `k` is a value of
   `c` in a selected child row. So every reference still points at a row.
3. **Children, with `include_children`:** the child rows whose `c` is a value of `k` in a parent row reached
   *downward* (a root row, or a child of one). Rows pulled in only as parents don't pull in their children,
   or one shared parent (a product, a country) would pull in the whole child table.

Steps 2 and 3 repeat until nothing changes (cycles and self-references end too). Every reason a row is in is
a value test on one of its columns, so a table's selection is the OR of `column ∈ values` tests: an
expression the `transform.mask` step filters by, from the run context. The value sets are data, so they stay
in memory, never in the pipeline text, a log or the report. A table with no relationship path to the root is
copied whole.
"""

from collections.abc import Callable
from dataclasses import dataclass, field

import polars as pl

from safetwin.keys import MasterKey
from safetwin.spec.policy import MaskingPolicy, relationships, subset_key

from .portable import Mac, picked, subset_columns, subset_filters

__all__ = ["SubsetPlan", "picked", "select"]


@dataclass
class SubsetPlan:
    """The filter of each table (None: copied whole), and what the report says about the selection."""

    filters: dict[str, pl.Expr | None]
    root: str
    key: str
    fraction: float
    include_children: bool
    root_rows: int = 0  # rows of the root picked by the hash
    whole: list[str] = field(default_factory=list)  # tables with no relationship path to the root

    def summary(self) -> dict[str, object]:
        return {
            "root": self.root,
            "key": self.key,
            "fraction": self.fraction,
            "include_children": self.include_children,
            "root_rows_picked": self.root_rows,
            "copied_whole": self.whole,
        }


def select(policy: MaskingPolicy, key: MasterKey, scan_input: Callable[[str], pl.LazyFrame]) -> SubsetPlan:
    """The selection of a policy with a subset (checked by `validate_policy` and against the source).
    `scan_input(table)` reads a table of the input. The algorithm is `portable.subset_filters`."""
    subset = policy.spec.subset
    root_key = subset_key(policy)
    assert subset is not None  # validate_policy makes sure of it, and of the key
    assert root_key is not None
    rels = [(r.from_table, r.from_column, r.to_table, r.to_column) for r in relationships(policy)]
    columns = subset_columns(subset.root, root_key, rels)
    frames = {t: scan_input(t).select(cs).collect(engine="streaming") for t, cs in columns.items()}
    mac = Mac(key.subkey("subset", subset.root))
    found, root_rows = subset_filters(
        frames, subset.root, root_key, float(subset.fraction), subset.include_children, rels, mac
    )
    filters: dict[str, pl.Expr | None] = {t: found.get(t) for t in policy.spec.tables}
    return SubsetPlan(
        filters,
        subset.root,
        root_key,
        float(subset.fraction),
        subset.include_children,
        root_rows=root_rows,
        whole=[t for t in policy.spec.tables if t not in columns],
    )
