"""The policy compiler (docs/internals.md): a checked policy and its source tables → a pipeline.

One chain per table: a source (`source.parquet` or `source.csv`) → one `transform.mask` step with the method
of every column (unknown columns expanded to `null` or `drop` as the policy says) → a sink (`sink.parquet`
or `sink.csv`) in `<target>/<table>/`. The pipeline holds methods, settings and domains, never key
material: the subkeys it needs are listed in `subkey_uses` and derived in memory when the run starts.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from safetwin.spec.models import Pipeline
from safetwin.spec.policy import (
    DateShift,
    Drop,
    Fake,
    MaskingPolicy,
    Method,
    Null,
    Pseudonymize,
    default_domain,
    engine_format,
    entity_domain,
    pseudonym_domain,
    staged_target,
)

from .check import SOURCE_SOCKET, TARGET_SOCKET, SourceTable
from .step import ColumnStep, subkey_use


@dataclass(frozen=True)
class CompiledPolicy:
    pipeline: Pipeline
    columns: dict[str, dict[str, ColumnStep]]  # table -> column -> step, every source column, in source order
    subkey_uses: frozenset[tuple[str, str]]


def _domain(policy: MaskingPolicy, table: str, column: str, spec: Method) -> str | None:
    if isinstance(spec, Pseudonymize):
        return pseudonym_domain(policy, table, column)
    if isinstance(spec, Fake) and spec.consistent:
        return default_domain(table, column)
    if isinstance(spec, DateShift):
        return entity_domain(policy, table, spec.entity)
    return None


def compile_policy(
    policy: MaskingPolicy,
    tables: Mapping[str, SourceTable],
    *,
    target_format: str | None = None,
    subset_tables: frozenset[str] = frozenset(),
) -> CompiledPolicy:
    """Compile a policy that passed `validate_policy` and `check_against_source`. The mask steps of
    `subset_tables` filter their rows by the subset's selection."""
    fmt = target_format or ("parquet" if staged_target(policy.spec.target) else policy.spec.target.format)
    nodes: list[dict[str, Any]] = []
    columns: dict[str, dict[str, ColumnStep]] = {}
    uses: set[tuple[str, str]] = set()
    for table in policy.spec.tables:
        source = tables[table]
        named = policy.spec.tables[table]
        steps: dict[str, ColumnStep] = {}
        for column in source.schema.names():
            spec = named.get(column)
            if spec is None:
                if policy.spec.unknown_columns == "fail":
                    raise ValueError(f"table '{table}' has a column the policy doesn't name")
                spec = Null(method="null") if policy.spec.unknown_columns == "null" else Drop(method="drop")
            step = ColumnStep(spec=spec, domain=_domain(policy, table, column, spec))
            if (use := subkey_use(column, step)) is not None:
                uses.add(use)
            steps[column] = step
        columns[table] = steps
        source_config: dict[str, Any] = {"path": source.glob}
        source_format = engine_format(policy.spec.source)
        if source_format == "csv":
            source_config["delimiter"] = policy.spec.source.delimiter
        nodes += [
            {
                "id": f"read_{table}",
                "operator": f"source.{source_format}",
                "socket": SOURCE_SOCKET,
                "config": source_config,
            },
            {
                "id": f"mask_{table}",
                "operator": "transform.mask",
                "inputs": [f"read_{table}"],
                "config": {
                    "table": table,
                    **({"subset": True} if table in subset_tables else {}),
                    "columns": {
                        name: {
                            "spec": step.spec.model_dump(by_alias=True, exclude_unset=True),
                            **({"domain": step.domain} if step.domain is not None else {}),
                        }
                        for name, step in steps.items()
                    },
                },
            },
            {
                "id": f"write_{table}",
                "operator": f"sink.{fmt}",
                "inputs": [f"mask_{table}"],
                "socket": TARGET_SOCKET,
                "config": {"path": f"{table}/"},
            },
        ]
    pipeline = Pipeline.model_validate(
        {
            "apiVersion": "safetwin/v1",
            "kind": "Pipeline",
            "metadata": {"name": policy.metadata.name, "description": "compiled from a masking policy"},
            "spec": {
                "sockets": {
                    SOURCE_SOCKET: "socket://safetwin-source",
                    TARGET_SOCKET: "socket://safetwin-target",
                },
                "nodes": nodes,
            },
        }
    )
    return CompiledPolicy(pipeline, columns, frozenset(uses))
