import pytest

from safetwin.spec import BUILTIN, Catalog, OperatorSpec

# Exactly the operators the data plane runs: two sources, the transforms (masking included), the two DuckDB
# steps and two sinks.
RUNNABLE = [
    "source.csv",
    "source.parquet",
    "transform.mask",
    "sink.csv",
    "transform.select",
    "transform.filter",
    "transform.derive",
    "transform.trim",
    "transform.parse_dates",
    "transform.cast",
    "transform.sort",
    "transform.sql",
    "sink.parquet",
]


@pytest.mark.parametrize("operator", RUNNABLE)
def test_runnable_operators_exist(operator: str) -> None:
    assert operator in BUILTIN
    assert BUILTIN[operator].id == operator
    assert BUILTIN[operator].category == operator.split(".")[0]


def test_the_catalog_holds_only_what_the_data_plane_runs() -> None:
    assert sorted(BUILTIN) == sorted(RUNNABLE)


def test_every_catalog_operator_has_a_runner() -> None:
    from safetwin.dataplane.operators import has_polars_builder, is_duckdb_operator

    assert [op for op in BUILTIN if not (has_polars_builder(op) or is_duckdb_operator(op))] == []


def test_lookup_ignores_a_pinned_version() -> None:
    assert BUILTIN["transform.sql@1"] is BUILTIN["transform.sql"]
    assert BUILTIN.get("source.csv@12") is BUILTIN["source.csv"]
    assert "transform.sql@1" in BUILTIN
    assert BUILTIN.get("transform.nope@1") is None
    with pytest.raises(KeyError):
        BUILTIN["transform.nope"]


def test_iteration_lists_unversioned_ids() -> None:
    assert set(BUILTIN) == {op.id for op in BUILTIN.values()}
    assert len(BUILTIN) == len(list(BUILTIN))


def test_every_source_needs_a_socket_and_has_no_inputs() -> None:
    sources = [op for op in BUILTIN.values() if op.category == "source"]
    assert [op.id for op in sources] == ["source.csv", "source.parquet"]
    assert all(op.needs_socket and not op.inputs and op.outputs for op in sources)


def test_ports() -> None:
    assert BUILTIN["source.csv"].outputs == {"out": "records"}
    assert BUILTIN["transform.filter"].inputs == {"in": "records"}
    assert BUILTIN["transform.filter"].outputs == {"out": "records"}
    assert BUILTIN["sink.parquet"].inputs == {"in": "records"}
    assert BUILTIN["sink.parquet"].needs_socket
    assert not BUILTIN["transform.sql"].needs_socket


def test_a_sink_exposes_what_it_committed() -> None:
    # A step that reads a sink starts a new stage, which reads what the sink committed: that needs an output.
    assert BUILTIN["sink.parquet"].outputs == {"out": "records"}


def test_custom_catalog_can_add_operators() -> None:
    split = OperatorSpec("transform.split", "transform", inputs={"in": "records"})
    catalog = Catalog([*BUILTIN.values(), split])
    assert catalog["transform.split@2"] is split
    assert "transform.split" not in BUILTIN
