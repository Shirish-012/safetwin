"""Planning: where a pipeline splits into stages (docs/internals.md), and which path a stage takes."""

from typing import Any

import pytest

from safetwin.dataplane.operators import ConfigError, Unsupported
from safetwin.dataplane.planner import Stage, choose_path, split_stages
from safetwin.spec import BUILTIN, Catalog, OperatorSpec

# A step that no Polars query can run (none of the built-in operators is one; custom Python steps would be):
# its stage takes the batch path.
CUSTOM = Catalog(
    [*BUILTIN.values(), OperatorSpec("transform.custom", "transform", {"in": "records"}, {"out": "records"})]
)


def ids(stage: Stage) -> list[str]:
    return [node.id for node in stage.nodes]


# --- stages -------------------------------------------------------------------------------------------------


def test_a_chain_with_one_sink_is_one_stage_in_the_order_the_data_flows(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("drop", "transform.filter", "read", expr="id IS NOT NULL"),
        nodes.step("tidy", "transform.trim", "drop", columns=["name"]),
        nodes.write("write", "tidy"),
    )
    (stage,) = split_stages(p)
    assert (stage.index, ids(stage), stage.input_from) == (0, ["read", "drop", "tidy", "write"], None)


def test_the_order_of_the_nodes_in_the_file_does_not_matter(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.write("write", "tidy"),
        nodes.step("tidy", "transform.trim", "drop", columns=["name"]),
        nodes.step("drop", "transform.filter", "read", expr="id IS NOT NULL"),
        nodes.read(),
    )
    assert [ids(stage) for stage in split_stages(p)] == [["read", "drop", "tidy", "write"]]


def test_a_node_that_reads_a_sink_starts_a_new_stage_that_reads_what_the_sink_committed(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("drop", "transform.filter", "read", expr="id IS NOT NULL"),
        nodes.write("write_raw", "drop", path="raw/"),
        nodes.step("tidy", "transform.trim", "write_raw", columns=["name"]),
        nodes.write("write_clean", "tidy", path="clean/"),
    )
    first, second = split_stages(p)
    assert (first.index, ids(first), first.input_from) == (0, ["read", "drop", "write_raw"], None)
    assert (second.index, ids(second), second.input_from) == (1, ["tidy", "write_clean"], "write_raw")


def test_a_sink_can_read_a_sink(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("raw", "read", path="raw/"),
        nodes.write("copy", "raw", path="copy/"),
    )
    assert [(ids(stage), stage.input_from) for stage in split_stages(p)] == [
        (["read", "raw"], None),
        (["copy"], "raw"),
    ]


def test_three_stages(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("a", "read", path="a/"),
        nodes.step("s", "transform.select", "a", columns=["id"]),
        nodes.write("b", "s", path="b/"),
        nodes.write("c", "b", path="c/"),
    )
    assert [(ids(stage), stage.input_from) for stage in split_stages(p)] == [
        (["read", "a"], None),
        (["s", "b"], "a"),
        (["c"], "b"),
    ]


def test_a_pinned_operator_version_is_still_a_sink_or_a_source(nodes: Any) -> None:
    p = nodes.pipeline(
        {**nodes.read(), "operator": "source.csv@1"},
        {**nodes.write("write", "read"), "operator": "sink.parquet@1"},
    )
    assert [ids(stage) for stage in split_stages(p)] == [["read", "write"]]


# --- what is not supported yet ------------------------------------------------------------------------------


def test_fan_out_is_refused_and_says_where(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("one", "read", path="one/"),
        nodes.write("two", "read", path="two/"),
    )
    with pytest.raises(NotImplementedError, match="'read' feeds 2 nodes: fan-out is not supported yet"):
        split_stages(p)


def test_fan_in_is_refused_and_says_where(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read("first"),
        nodes.read("second"),
        {**nodes.write("write", "first"), "inputs": ["first", "second"]},
    )
    with pytest.raises(NotImplementedError, match="'write' reads from 2 nodes: fan-in is not supported yet"):
        split_stages(p)


def test_independent_chains_become_stages_in_the_order_of_their_sources(nodes: Any) -> None:
    # A masking policy compiles to one chain per table (M1a): they run one after the other.
    p = nodes.pipeline(
        nodes.read("first"),
        nodes.write("one", "first", path="one/"),
        nodes.read("second"),
        nodes.write("two", "second", path="two/"),
    )
    stages = split_stages(p)
    assert [[node.id for node in stage.nodes] for stage in stages] == [["first", "one"], ["second", "two"]]
    assert [stage.index for stage in stages] == [0, 1]
    assert all(stage.input_from is None for stage in stages)


def test_an_operator_that_is_not_in_the_catalog_is_a_config_error(nodes: Any) -> None:
    p = nodes.pipeline(nodes.read(), nodes.step("odd", "transform.nope", "read"), nodes.write("write", "odd"))
    with pytest.raises(ConfigError, match=r"'odd' uses 'transform\.nope', which is not an operator"):
        split_stages(p)


def test_an_output_port_other_than_out_is_refused(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("check", "transform.custom", "read"),
        nodes.write("write", "check.rest"),
    )
    with pytest.raises(NotImplementedError, match=r"'check\.rest': output ports other than 'out'"):
        split_stages(p)


def test_what_is_refused_is_a_not_implemented_error(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(), nodes.write("one", "read", path="one/"), nodes.write("two", "read", path="two/")
    )
    with pytest.raises(Unsupported):
        split_stages(p)
    assert issubclass(Unsupported, NotImplementedError)


def test_a_chain_that_does_not_end_with_a_sink_would_write_nothing(nodes: Any) -> None:
    p = nodes.pipeline(nodes.read(), nodes.step("drop", "transform.filter", "read", expr="id IS NOT NULL"))
    with pytest.raises(ConfigError, match="'drop' is the end of the pipeline, but nothing writes its data"):
        split_stages(p)
    after_a_sink = nodes.pipeline(
        nodes.read(),
        nodes.write("write", "read"),
        nodes.step("drop", "transform.filter", "write", expr="id IS NOT NULL"),
    )
    with pytest.raises(ConfigError, match="'drop' is the end of the pipeline"):
        split_stages(after_a_sink)


# --- fused or batch -----------------------------------------------------------------------------------------


def test_a_stage_whose_operators_all_run_in_polars_is_fused(nodes: Any) -> None:
    (stage,) = split_stages(nodes.messy())
    assert choose_path(stage) == "fused"


def test_a_stage_with_an_operator_that_has_no_polars_builder_takes_the_batch_path(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("unique", "transform.custom", "read"),
        nodes.write("write", "unique"),
    )
    (stage,) = split_stages(p, CUSTOM)
    assert choose_path(stage) == "batch"


@pytest.mark.parametrize(
    ("operator", "config"),
    [("transform.sort", {"by": ["id"]}), ("transform.sql", {"sql": "SELECT * FROM input"})],
)
def test_a_stage_with_a_step_that_duckdb_runs_is_hybrid(nodes: Any, operator: str, config: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("drop", "transform.filter", "read", expr="id IS NOT NULL"),
        nodes.step("heavy", operator, "drop", **config),
        nodes.step("tidy", "transform.trim", "heavy", columns=["name"]),
        nodes.write("write", "tidy"),
    )
    (stage,) = split_stages(p)
    assert choose_path(stage) == "hybrid"


def test_a_pinned_version_of_a_duckdb_operator_is_hybrid_too(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("heavy", "transform.sql@1", "read", sql="SELECT * FROM input"),
        nodes.write("write", "heavy"),
    )
    (stage,) = split_stages(p)
    assert choose_path(stage) == "hybrid"


def test_hybrid_wins_over_batch_when_a_stage_has_both_kinds_of_operator(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("unique", "transform.custom", "read"),
        nodes.step("sorted", "transform.sort", "unique", by=["id"]),
        nodes.write("write", "sorted"),
    )
    (stage,) = split_stages(p, CUSTOM)
    assert choose_path(stage) == "hybrid"  # the hybrid path then says what it can't run (transform.custom)


def test_each_stage_is_chosen_on_its_own(nodes: Any) -> None:
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("raw", "read", path="raw/"),
        nodes.step("unique", "transform.custom", "raw"),
        nodes.write("tidy", "unique", path="tidy/"),
        nodes.step("sorted", "transform.sort", "tidy", by=["id"]),
        nodes.write("write", "sorted"),
    )
    first, second, third = split_stages(p, CUSTOM)
    assert (choose_path(first), choose_path(second), choose_path(third)) == ("fused", "batch", "hybrid")


@pytest.mark.parametrize("forced", ["fused", "batch", "hybrid"])
def test_force_path_decides(nodes: Any, forced: str) -> None:
    sort = nodes.pipeline(
        nodes.read(),
        nodes.step("sorted", "transform.sort", "read", by=["id"]),
        nodes.write("write", "sorted"),
    )
    for p in (sort, nodes.messy()):
        (stage,) = split_stages(p)
        assert choose_path(stage, force_path=forced) == forced  # type: ignore[arg-type]
