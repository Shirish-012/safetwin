"""Planning a batch pipeline: where it splits into stages, and how each stage runs.

A stage is a group of connected nodes that run together, with data flowing between them in memory. Stages are
split after the sinks, the points where data is committed to the user's storage (docs/internals.md): a node
that reads from a sink starts a new stage, which reads what the sink committed. Retrying a stage therefore
never needs data that was not stored.
"""

from dataclasses import dataclass
from typing import Literal

from safetwin.spec import BUILTIN, Catalog, Pipeline, redacted
from safetwin.spec.models import Node

from .operators import ConfigError, Unsupported, has_polars_builder, is_duckdb_operator

DataPath = Literal["fused", "batch", "hybrid"]


@dataclass(frozen=True)
class Stage:
    """A run of nodes that ends with a sink.

    `nodes` are in the order the data flows. The first one is a source, or, when `input_from` is set, the
    first node after the sink with that id, which reads what that sink committed.
    """

    index: int
    nodes: tuple[Node, ...]
    input_from: str | None = None


def split_stages(pipeline: Pipeline, catalog: Catalog = BUILTIN) -> list[Stage]:
    """The stages of a validated pipeline, in the order they run.

    Only linear chains are supported so far: each starts at a source, and every node reads from the one
    before it. Independent chains (one per table of a masking policy) run one after the other, in the order
    of their sources. A node with more than one input (fan-in) or one that more than one
    node reads (fan-out), or a port other than `out` raises `Unsupported` (a
    `NotImplementedError`) that says which. A chain that does not end with a sink raises `ConfigError`:
    it would write nothing.
    """
    nodes = {node.id: node for node in pipeline.spec.nodes}
    readers: dict[str, list[str]] = {}  # node id -> ids of the nodes that read it
    for node in pipeline.spec.nodes:
        if len(node.inputs) > 1:
            raise Unsupported(
                f"'{redacted(node.id)}' reads from {len(node.inputs)} nodes: fan-in is not supported yet, "
                "only linear chains run"
            )
        for ref in node.inputs:
            source, _, port = ref.partition(".")
            if port not in ("", "out"):
                raise Unsupported(f"'{redacted(ref)}': output ports other than 'out' are not supported yet")
            readers.setdefault(source, []).append(node.id)
    for source, names in readers.items():
        if len(names) > 1:
            raise Unsupported(
                f"'{redacted(source)}' feeds {len(names)} nodes: fan-out is not supported yet, "
                "only linear chains run"
            )
    starts = [node for node in pipeline.spec.nodes if not node.inputs]
    if not starts:
        raise Unsupported("the pipeline has no node without inputs: it needs a source")

    chains: list[list[Node]] = []
    for start in starts:  # independent chains (a masking policy has one per table) run one after the other
        chain = [start]
        while readers.get(chain[-1].id) and len(chain) <= len(nodes):
            chain.append(nodes[readers[chain[-1].id][0]])
        chains.append(chain)
    if sum(len(chain) for chain in chains) != len(nodes):
        raise Unsupported("the nodes do not form chains that each start at a source")

    stages: list[Stage] = []
    for chain in chains:
        pending: list[Node] = []
        input_from: str | None = None
        for node in chain:
            pending.append(node)
            spec = catalog.get(node.operator)
            if spec is None:
                raise ConfigError(
                    f"'{redacted(node.id)}' uses '{redacted(node.operator)}', which is not an operator"
                )
            if spec.category == "sink":
                stages.append(Stage(len(stages), tuple(pending), input_from))
                pending, input_from = [], node.id
        if pending:
            raise ConfigError(
                f"'{redacted(pending[-1].id)}' is the end of the pipeline, but nothing writes its data: "
                "end the pipeline with a sink"
            )
    return stages


def choose_path(stage: Stage, *, force_path: DataPath | None = None) -> DataPath:
    """`hybrid` when a node of the stage runs in DuckDB (`transform.sql`, `transform.sort`), else `fused`
    when every operator can run inside one Polars query, else `batch`.

    `force_path` overrides the choice (for tests and for `safetwin run-local --path`). A stage with a node for
    DuckDB can only run on the hybrid path.
    """
    if force_path is not None:
        return force_path
    if any(is_duckdb_operator(node.operator) for node in stage.nodes):
        return "hybrid"
    return "fused" if all(has_polars_builder(node.operator) for node in stage.nodes) else "batch"
