"""The hybrid path: stages with a step that DuckDB runs (`transform.sql`, `transform.sort`)."""

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import duckdb
import polars as pl
import pytest

from safetwin.dataplane import hybrid
from safetwin.dataplane.manifest import Manifest
from safetwin.dataplane.operators import ConfigError, Unsupported
from safetwin.dataplane.run import RunResult, run_pipeline_local
from safetwin.dataplane.runtime import ProgressEvent
from safetwin.dataplane.spill import (
    OutOfMemory,
    SpillError,
    SpillSettings,
    default_memory_limit,
    duckdb_threads,
)

MB = 1_000_000
PEOPLE = ["id", "name", "city", "amount"]


def go(pipeline: Any, sockets: Any, **kwargs: Any) -> RunResult:
    return run_pipeline_local(pipeline, sockets.folders, **kwargs)  # type: ignore[no-any-return]


def the_manifest(result: RunResult, stage: int = 0) -> Manifest:
    return Manifest.model_validate_json(result.stages[stage].manifest.read_text(encoding="utf-8"))


def write_people(sockets: Any, data: Any, rows: list[list[str]], name: str = "people.csv") -> None:
    data.write_csv(sockets.inbox / name, rows, header=PEOPLE)


def assert_rows(actual: list[tuple[Any, ...]], expected: list[tuple[Any, ...]]) -> None:
    """The rows are the expected ones, the floats in them to within the rounding of a sum."""
    assert len(actual) == len(expected)
    for got, want in zip(actual, expected, strict=True):
        assert got == pytest.approx(want)


def python_sort(rows: list[dict[str, Any]], keys: list[tuple[str, bool]], nulls: str) -> list[dict[str, Any]]:
    """`rows` sorted by `keys` (column and descending), with the nulls first or last for every column.

    One stable sort for each key, the least important first: what the SQL of an ORDER BY means.
    """
    ordered = list(rows)
    for column, descending in reversed(keys):
        present = sorted(
            (r for r in ordered if r[column] is not None), key=lambda r: r[column], reverse=descending
        )
        missing = [r for r in ordered if r[column] is None]
        ordered = missing + present if nulls == "first" else present + missing
    return ordered


# --- transform.sql ------------------------------------------------------------------------------------------


def test_sql_aggregates_and_filters_the_table_input(nodes: Any, data: Any, sockets: Any) -> None:
    rows = data.messy_rows(3000)
    data.write_csv(sockets.inbox / "a.csv", rows)
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("numbers", "transform.cast", "read", columns={"amount": "float"}),
        nodes.step(
            "totals",
            "transform.sql",
            "numbers",
            sql="SELECT city, count(*) AS n, sum(amount) AS total FROM input "
            "WHERE amount IS NOT NULL AND id IS NOT NULL GROUP BY city ORDER BY city NULLS LAST",
        ),
        nodes.write("write", "totals", path="totals/"),
    )
    result = go(p, sockets)
    (stage,) = result.stages
    expected: dict[str | None, list[float]] = {}
    for row in rows:
        if row[0] != "" and row[3] not in ("", "n/a"):
            expected.setdefault(row[2] or None, []).append(float(row[3]))
    cities = sorted(expected, key=lambda city: (city is None, city or ""))
    written = data.dataset(stage)
    assert stage.path == "hybrid"
    assert written["city"].to_list() == cities
    assert written["n"].to_list() == [len(expected[city]) for city in cities]
    assert written["total"].to_list() == pytest.approx([sum(expected[city]) for city in cities])
    assert written.schema == pl.Schema({"city": pl.String, "n": pl.Int64, "total": pl.Float64})
    assert None in cities  # the rows without a city make a group of their own
    assert stage.rows_per_node == {
        "read": 3000,
        "numbers": 3000,
        "totals": len(cities),
        "write": len(cities),
    }
    assert [(c.name, c.type) for c in the_manifest(result).columns] == [
        ("city", "string"),
        ("n", "int64"),
        ("total", "double"),
    ]
    assert the_manifest(result).lineage.operators == ["transform.cast", "transform.sql"]


def test_sql_filters_rows_and_the_node_counts_the_rows_that_leave_it(
    nodes: Any, data: Any, sockets: Any
) -> None:
    rows = data.messy_rows(2000)
    data.write_csv(sockets.inbox / "a.csv", rows)
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("query", "transform.sql", "read", sql="SELECT id, name FROM input WHERE id IS NOT NULL"),
        nodes.write("write", "query"),
    )
    (stage,) = go(p, sockets).stages
    kept = [row for row in rows if row[0] != ""]
    assert stage.rows_per_node == {"read": 2000, "query": len(kept), "write": len(kept)}
    written = data.dataset(stage)
    assert written.columns == ["id", "name"]
    assert written["id"].to_list() == [row[0] for row in kept]  # in the order they came in


def test_a_pinned_version_of_the_operator_runs_too(nodes: Any, data: Any, sockets: Any) -> None:
    write_people(sockets, data, [["1", "a", "x", "5"], ["2", "b", "y", "6"]])
    p = nodes.pipeline(
        nodes.read(),
        {
            **nodes.step("query", "transform.sql", "read", sql="SELECT count(*) AS n FROM input"),
            "operator": "transform.sql@1",
        },
        nodes.write("write", "query"),
    )
    (stage,) = go(p, sockets).stages
    assert data.dataset(stage)["n"].to_list() == [2]


def test_a_query_that_does_not_read_input_does_not_read_the_source(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, [["1", "a", "x", "5"]])
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("query", "transform.sql", "read", sql="SELECT 42 AS answer"),
        nodes.write("write", "query"),
    )
    (stage,) = go(p, sockets).stages
    assert data.dataset(stage)["answer"].to_list() == [42]
    assert stage.rows_per_node == {"read": 0, "query": 1, "write": 1}  # the CSV was never read


def test_a_stage_with_no_rows_writes_a_file_with_the_columns_and_no_rows(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, [])
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("query", "transform.sql", "read", sql="SELECT id, upper(name) AS shout FROM input"),
        nodes.step("ordered", "transform.sort", "query", by=["id"]),
        nodes.write("write", "ordered"),
    )
    result = go(p, sockets)
    (stage,) = result.stages
    assert stage.rows_per_node == {"read": 0, "query": 0, "ordered": 0, "write": 0}
    assert data.dataset(stage).columns == ["id", "shout"]
    assert the_manifest(result).totals.rows == 0
    assert [c.name for c in the_manifest(result).columns] == ["id", "shout"]


# --- transform.sort -----------------------------------------------------------------------------------------

SORT_ROWS = [
    ["3", "carol", "Rome", "10.5"],
    ["", "dave", "Wien", ""],
    ["1", "alice", "Berlin", "7"],
    ["2", "bob", "Berlin", "7"],
    ["", "eve", "Rome", "3"],
    ["5", "frank", "", "7"],
    ["4", "grace", "Berlin", ""],
    ["7", "émile", "Wien", "1"],
    ["6", "Zoë", "Rome", "2.5"],
]


def sort_pipeline(nodes: Any, **config: Any) -> Any:
    return nodes.pipeline(
        nodes.read(),
        nodes.step("numbers", "transform.cast", "read", columns={"id": "int", "amount": "float"}),
        nodes.step("ordered", "transform.sort", "numbers", **config),
        nodes.write("write", "ordered"),
    )


def typed(rows: list[list[str]]) -> list[dict[str, Any]]:
    return [
        {
            "id": int(r[0]) if r[0] else None,
            "name": r[1],
            "city": r[2] or None,
            "amount": float(r[3]) if r[3] else None,
        }
        for r in rows
    ]


@pytest.mark.parametrize("nulls", ["first", "last", None])
@pytest.mark.parametrize("descending", [False, True])
def test_sort_puts_the_nulls_where_it_is_told_for_ascending_and_descending(
    nodes: Any, data: Any, sockets: Any, nulls: str | None, descending: bool
) -> None:
    write_people(sockets, data, SORT_ROWS)
    config: dict[str, Any] = {"by": [{"column": "id", "descending": descending}, "name"]}
    if nulls is not None:
        config["nulls"] = nulls
    (stage,) = go(sort_pipeline(nodes, **config), sockets).stages
    expected = python_sort(typed(SORT_ROWS), [("id", descending), ("name", False)], nulls or "last")
    assert data.dataset(stage).to_dicts() == expected
    assert stage.rows_per_node["ordered"] == len(SORT_ROWS)


def test_sort_by_many_columns_each_in_its_own_direction(nodes: Any, data: Any, sockets: Any) -> None:
    write_people(sockets, data, SORT_ROWS)
    by = ["city", {"column": "amount", "descending": True}, {"column": "name", "descending": False}]
    (stage,) = go(sort_pipeline(nodes, by=by, nulls="first"), sockets).stages
    expected = python_sort(typed(SORT_ROWS), [("city", False), ("amount", True), ("name", False)], "first")
    assert data.dataset(stage).to_dicts() == expected


def test_sort_orders_text_by_its_bytes_and_keeps_the_type_of_every_column(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, SORT_ROWS)
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("ordered", "transform.sort", "read", by=["name"]),
        nodes.write("write", "ordered"),
    )
    (stage,) = go(p, sockets).stages
    names = [row[1] for row in SORT_ROWS]
    assert data.dataset(stage)["name"].to_list() == sorted(names, key=lambda name: name.encode())
    assert data.dataset(stage).schema == pl.Schema(dict.fromkeys(PEOPLE, pl.String))  # all text, as read


def test_sort_names_its_columns_as_identifiers_whatever_they_are_called(
    nodes: Any, data: Any, sockets: Any
) -> None:
    header = ["we ird; name --", "select", "Zoë; DROP TABLE input; --"]
    data.write_csv(
        sockets.inbox / "a.csv", [["b", "2", "x"], ["a", "3", "y"], ["c", "1", "z"]], header=header
    )
    p = nodes.pipeline(
        nodes.read(),
        nodes.step(
            "ordered", "transform.sort", "read", by=[{"column": "we ird; name --", "descending": True}]
        ),
        nodes.step("again", "transform.sort", "ordered", by=["select"]),
        nodes.write("write", "again"),
    )
    (stage,) = go(p, sockets).stages
    assert data.dataset(stage)["select"].to_list() == ["1", "2", "3"]
    assert data.dataset(stage).columns == header


def test_a_sort_column_that_is_not_there_is_an_error_that_lists_the_columns_and_writes_nothing(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, SORT_ROWS)
    p = sort_pipeline(nodes, by=["id", "salary", "age"])
    with pytest.raises(ConfigError) as refused:
        go(p, sockets)
    assert str(refused.value) == (
        "ordered (transform.sort): no column 'salary', 'age'; the columns are: id, name, city, amount"
    )
    assert sockets.written() == []


def test_a_big_input_in_many_batches_comes_out_sorted_and_complete(
    nodes: Any, data: Any, sockets: Any
) -> None:
    count = 300_000
    shuffled = pl.DataFrame({"id": range(count)}).sample(fraction=1.0, shuffle=True, seed=3)["id"].to_list()
    pl.DataFrame({"id": shuffled, "payload": [f"row {i % 97}" for i in shuffled]}).write_csv(
        sockets.inbox / "a.csv"
    )
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("numbers", "transform.cast", "read", columns={"id": "int"}),
        nodes.step("ordered", "transform.sort", "numbers", by=["id"]),
        nodes.write("write", "ordered"),
    )
    (stage,) = go(p, sockets).stages
    written = data.dataset(stage)
    assert written["id"].to_list() == list(range(count))
    assert written["payload"].to_list() == [
        f"row {i % 97}" for i in range(count)
    ]  # every row kept its payload
    assert stage.rows_per_node == {"read": count, "numbers": count, "ordered": count, "write": count}


# --- Polars steps around the steps for DuckDB ---------------------------------------------------------------

MESSY_STEPS = [
    ("has_id", "transform.filter", {"expr": "id IS NOT NULL"}),
    ("tidy", "transform.trim", {"columns": ["name", "city"]}),
    ("dates", "transform.parse_dates", {"columns": ["signup"]}),
    ("numbers", "transform.cast", {"columns": {"id": "int", "amount": "float"}}),
    ("shout", "transform.derive", {"name": "city_upper", "expr": "upper(city)"}),
    ("keep", "transform.select", {"columns": ["id", "name", "city_upper", "amount", "signup"]}),
]


def messy_with(nodes: Any, after: str, operator: str = "transform.sql", **config: Any) -> Any:
    """The messy pipeline of conftest, with a node `heavy` for DuckDB right after the node `after`."""
    config = config or {"sql": "SELECT * FROM input"}
    built = [nodes.read()]
    last = "read"
    if after == "read":
        built.append(nodes.step("heavy", operator, last, **config))
        last = "heavy"
    for node_id, step_operator, step_config in MESSY_STEPS:
        built.append(nodes.step(node_id, step_operator, last, **step_config))
        last = node_id
        if node_id == after:
            built.append(nodes.step("heavy", operator, last, **config))
            last = "heavy"
    built.append(nodes.write("write", last, path="messy/"))
    return nodes.pipeline(*built)


@pytest.fixture
def fused_messy(nodes: Any, data: Any, sockets: Any, tmp_path: Path) -> Any:
    """What the fused path writes for the messy pipeline on 5,000 messy rows: its stage result."""
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(5000))
    outbox = tmp_path / "out-fused"
    outbox.mkdir()
    folders = {"inbox": sockets.inbox, "outbox": outbox}
    return run_pipeline_local(nodes.messy(), folders, force_path="fused").stages[0]


@pytest.mark.parametrize("after", ["read", "has_id", "numbers", "keep"])
def test_a_sql_step_that_changes_nothing_in_the_middle_of_a_stage_gives_what_the_fused_path_gives(
    nodes: Any, data: Any, sockets: Any, fused_messy: Any, after: str
) -> None:
    (stage,) = go(messy_with(nodes, after), sockets).stages
    assert stage.path == "hybrid"
    assert data.dataset(stage).equals(data.dataset(fused_messy))  # the same values, types and order
    shared = {node_id: rows for node_id, rows in stage.rows_per_node.items() if node_id != "heavy"}
    assert shared == fused_messy.rows_per_node  # the funnel of every other node is the same
    assert (
        stage.rows_per_node["heavy"] == fused_messy.rows_per_node[after]
    )  # and the new node lets every row by


@pytest.mark.parametrize("after", ["numbers", "keep"])
def test_a_sort_in_the_middle_of_a_stage_gives_the_rows_of_the_fused_path_in_order(
    nodes: Any, data: Any, sockets: Any, fused_messy: Any, after: str
) -> None:
    p = messy_with(nodes, after, "transform.sort", by=[{"column": "id", "descending": True}])
    (stage,) = go(p, sockets).stages
    written = data.dataset(stage)
    assert written.equals(data.dataset(fused_messy).sort("id", descending=True))  # the ids are all different
    assert stage.rows_per_node["heavy"] == fused_messy.rows_per_node[after]


def test_two_steps_for_duckdb_with_polars_steps_before_between_and_after_them(
    nodes: Any, data: Any, sockets: Any
) -> None:
    rows = data.messy_rows(4000)
    data.write_csv(sockets.inbox / "a.csv", rows)
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("numbers", "transform.cast", "read", columns={"id": "int", "amount": "float"}),
        nodes.step(
            "priced", "transform.sql", "numbers", sql="SELECT id, city, amount FROM input WHERE amount > 500"
        ),
        nodes.step("shout", "transform.derive", "priced", name="city_upper", expr="upper(trim(city))"),
        nodes.step("ordered", "transform.sort", "shout", by=[{"column": "amount", "descending": True}, "id"]),
        nodes.step("tidy", "transform.trim", "ordered", columns=["city"]),
        nodes.write("write", "tidy"),
    )
    (stage,) = go(p, sockets).stages
    kept = sorted(
        (
            {"id": int(r[0]) if r[0] else None, "city": r[2] or None, "amount": float(r[3])}
            for r in rows
            if r[3] not in ("", "n/a") and float(r[3]) > 500
        ),
        key=lambda r: (-r["amount"], r["id"] is None, r["id"] or 0),
    )
    written = data.dataset(stage)
    assert written["amount"].to_list() == [r["amount"] for r in kept]
    assert written["id"].to_list() == [r["id"] for r in kept]
    assert written["city"].to_list() == [r["city"].strip() if r["city"] else None for r in kept]
    assert written["city_upper"].to_list() == [r["city"].strip().upper() if r["city"] else None for r in kept]
    count = len(kept)
    assert stage.rows_per_node == {
        "read": 4000,
        "numbers": 4000,
        "priced": count,
        "shout": count,
        "ordered": count,
        "tidy": count,
        "write": count,
    }


def test_one_step_for_duckdb_straight_after_another(nodes: Any, data: Any, sockets: Any) -> None:
    write_people(sockets, data, [[str(n), f"n{n % 3}", "x", str(n)] for n in range(1, 31)])
    p = nodes.pipeline(
        nodes.read(),
        nodes.step(
            "counts", "transform.sql", "read", sql="SELECT name, count(*) AS n FROM input GROUP BY name"
        ),
        nodes.step("top", "transform.sql", "counts", sql="SELECT name, n FROM input WHERE name <> 'n0'"),
        nodes.step("ordered", "transform.sort", "top", by=[{"column": "name", "descending": True}]),
        nodes.write("write", "ordered"),
    )
    (stage,) = go(p, sockets).stages
    assert data.dataset(stage).to_dicts() == [{"name": "n2", "n": 10}, {"name": "n1", "n": 10}]
    assert stage.rows_per_node == {"read": 30, "counts": 3, "top": 2, "ordered": 2, "write": 2}


def test_a_stage_that_starts_after_a_sink_reads_what_the_sink_committed_into_duckdb(
    nodes: Any, data: Any, sockets: Any
) -> None:
    rows = data.messy_rows(500)
    data.write_csv(sockets.inbox / "a.csv", rows)
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("raw", "read", path="raw/"),
        nodes.step(
            "query", "transform.sql", "raw", sql="SELECT city, count(*) AS n FROM input GROUP BY city"
        ),
        nodes.step("ordered", "transform.sort", "query", by=["city"]),
        nodes.write("write", "ordered", path="by-city/"),
    )
    result = go(p, sockets)
    first, second = result.stages
    assert (first.path, second.path) == ("fused", "hybrid")
    cities = {}
    for row in rows:
        cities[row[2] or None] = cities.get(row[2] or None, 0) + 1
    written = data.dataset(second)
    assert dict(zip(written["city"].to_list(), written["n"].to_list(), strict=True)) == cities
    assert second.rows_per_node == {"query": len(cities), "ordered": len(cities), "write": len(cities)}


# --- the table input is read once, or it is made into a table -----------------------------------------------


def numbers_pipeline(nodes: Any, sql: str) -> Any:
    return nodes.pipeline(
        nodes.read(),
        nodes.step("numbers", "transform.cast", "read", columns={"id": "int", "amount": "float"}),
        nodes.step("query", "transform.sql", "numbers", sql=sql),
        nodes.write("write", "query"),
    )


@pytest.fixture
def numbers(sockets: Any, data: Any) -> list[tuple[int, float]]:
    rows = [(n, float(n % 17)) for n in range(1, 1201)]
    write_people(sockets, data, [[str(n), f"n{n}", "x", str(a)] for n, a in rows])
    return rows


@pytest.fixture
def scans(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """What `hybrid._scans` found for the queries that ran."""
    found: list[int] = []
    real = hybrid._scans

    def spy(cursor: Any, sql: str) -> int:
        found.append(real(cursor, sql))
        return found[-1]

    monkeypatch.setattr(hybrid, "_scans", spy)
    return found


MORE_THAN_ONCE = {
    "a self-join": (
        "SELECT a.id, b.amount FROM input a JOIN input b ON a.id = b.id ORDER BY a.id",
        lambda rows: [(n, a) for n, a in rows],
    ),
    "a scalar subquery over the same table": (
        "SELECT id, amount / (SELECT sum(amount) FROM input) AS share FROM input ORDER BY id",
        lambda rows: [(n, a / sum(x for _, x in rows)) for n, a in rows],
    ),
    "UNION ALL of the table with itself": (
        "SELECT id, amount FROM input UNION ALL SELECT id, amount FROM input ORDER BY id",
        lambda rows: sorted([(n, a) for n, a in rows] * 2),
    ),
    "a subquery in a filter": (
        "SELECT id, amount FROM input WHERE id IN (SELECT id FROM input WHERE amount > 15) ORDER BY id",
        lambda rows: [(n, a) for n, a in rows if a > 15],
    ),
    "a cross join with an aggregate": (
        "SELECT i.id, i.amount - m.average AS above "
        "FROM input i, (SELECT avg(amount) AS average FROM input) m ORDER BY i.id",
        lambda rows: [(n, a - sum(x for _, x in rows) / len(rows)) for n, a in rows],
    ),
}


@pytest.mark.parametrize("case", MORE_THAN_ONCE)
def test_a_query_that_reads_input_more_than_once_gives_the_right_answer_by_making_a_table_of_it(
    nodes: Any, data: Any, sockets: Any, numbers: Any, scans: list[int], case: str
) -> None:
    sql, expected = MORE_THAN_ONCE[case]
    (stage,) = go(numbers_pipeline(nodes, sql), sockets).stages
    assert scans == [2]  # the plan said so, before any data moved
    written = data.dataset(stage)
    assert_rows(written.rows(), expected(numbers))
    assert stage.rows_per_node["numbers"] == len(numbers)  # the stream was read once, in full, for the table
    assert stage.rows_per_node["write"] == written.height


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM input",
        "SELECT id FROM input WHERE amount > 3",
        "SELECT sum(amount) OVER (ORDER BY id) AS running FROM input",
        # DuckDB makes one table of a CTE that is used twice, and reads input once:
        "WITH i AS (SELECT * FROM input) SELECT count(*) FROM i a, i b WHERE a.id = b.id",
        "SELECT amount, count(*) FROM input GROUP BY amount ORDER BY amount",
    ],
)
def test_a_query_that_reads_input_once_is_not_made_into_a_table(
    nodes: Any, sockets: Any, numbers: Any, scans: list[int], sql: str
) -> None:
    go(numbers_pipeline(nodes, sql), sockets)
    assert scans == [1]


def test_a_second_read_that_the_plan_did_not_foresee_is_an_error_and_not_a_wrong_answer(
    nodes: Any, sockets: Any, numbers: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(hybrid, "_scans", lambda cursor, sql: 1)  # as if the plan could not be read
    sql = "SELECT count(*) AS n FROM input a JOIN input b ON a.id = b.id"
    with pytest.raises(
        ConfigError, match=r"query \(transform\.sql\): the query reads the table input a second time"
    ):
        go(numbers_pipeline(nodes, sql), sockets)
    assert sockets.written() == []


class Plan:
    """A cursor whose plan is `text`."""

    def __init__(self, text: str) -> None:
        self.text = text

    def execute(self, sql: str) -> "Plan":
        return self

    def fetchall(self) -> list[tuple[str, str]]:
        return [("physical_plan", self.text)]


class NoPlan:
    def execute(self, sql: str) -> Any:
        raise duckdb.InvalidInputException("no plan")


def scans_of(cursor: Any) -> int:
    return hybrid._scans(cursor, "SELECT 1")  # type: ignore[no-any-return]


def test_the_scans_of_a_plan_are_counted_wherever_they_are_in_it() -> None:
    joined = (
        '[{"name": "HASH_JOIN", "children": [{"name": "ARROW_SCAN", "children": []}, '
        '{"name": "PROJECTION", "children": [{"name": "ARROW_SCAN"}]}]}]'
    )
    cte = (
        '[{"name": "CTE", "children": [{"name": "ARROW_SCAN"}, {"name": "CTE_SCAN"}, {"name": "CTE_SCAN"}]}]'
    )
    assert scans_of(Plan(joined)) == 2
    assert scans_of(Plan('[{"name": "ARROW_SCAN"}]')) == 1
    assert scans_of(Plan(cte)) == 1  # a CTE that DuckDB materializes is read once
    assert scans_of(Plan("[]")) == 0


@pytest.mark.parametrize("text", ["not json", "{}", '{"name": "ARROW_SCAN"}', '"text"', "null", "[1, 2]x"])
def test_a_plan_in_a_shape_that_is_not_known_counts_as_more_than_one_read(text: str) -> None:
    # The stream is then made into a table, which is right whatever the plan was: it is only slower.
    assert scans_of(Plan(text)) == 2


def test_a_query_that_can_not_be_planned_counts_as_one_read_and_running_it_gives_the_error() -> None:
    assert scans_of(NoPlan()) == 1


# --- what is found out before anything runs -----------------------------------------------------------------


def test_sql_that_can_not_be_parsed_is_refused_before_anything_runs(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, [["1", "a", "x", "5"]])
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("raw", "read", path="raw/"),
        nodes.step("query", "transform.sql", "raw", sql="SELECT * FORM input"),
        nodes.write("write", "query", path="out/"),
    )
    with pytest.raises(ConfigError, match=r"query \(transform\.sql\): the SQL can't be parsed: Parser Error"):
        go(p, sockets)
    assert sockets.written() == []  # not even the stage before it has run


@pytest.mark.parametrize(
    "sql",
    [
        "COPY (SELECT 1) TO 'x.csv'",
        "ATTACH 'x.duckdb' AS x",
        "INSTALL httpfs",
        "SET threads = 99",
        "SELECT 1; SELECT 2",
    ],
)
def test_sql_that_is_not_one_select_is_refused_before_anything_runs(
    nodes: Any, data: Any, sockets: Any, sql: str
) -> None:
    write_people(sockets, data, [["1", "a", "x", "5"]])
    with pytest.raises(ConfigError, match="the SQL must be exactly one SELECT statement"):
        go(numbers_pipeline(nodes, sql), sockets)
    assert sockets.written() == []


def test_sql_that_can_not_reach_a_file_is_refused_when_it_runs_and_the_canary_stays_where_it_was(
    nodes: Any, data: Any, sockets: Any, tmp_path: Path
) -> None:
    secret = tmp_path / "secret.csv"
    secret.write_text("a,b\nCANARY-7f3a9c-secret,1\n", encoding="utf-8")
    write_people(sockets, data, [["1", "a", "x", "5"]])
    target = tmp_path / "copy.csv"
    for sql in (
        f"SELECT * FROM read_csv('{secret}')",
        f"SELECT * FROM '{secret}'",
        f"SELECT * FROM read_text('{secret}')",
        "SELECT * FROM read_csv('http://127.0.0.1:9/x.csv')",
        f"COPY (SELECT * FROM input) TO '{target}'",
        f"ATTACH '{tmp_path}/other.duckdb' AS other",
        "INSTALL httpfs",
        "LOAD httpfs",
        "SET enable_external_access = true",
        "SET lock_configuration = false",
        "SET enable_external_access = true; SELECT * FROM read_csv('" + str(secret) + "')",
    ):
        with pytest.raises((ConfigError, duckdb.PermissionException)) as refused:
            go(numbers_pipeline(nodes, sql), sockets)
        assert "CANARY-7f3a9c" not in str(refused.value)
    assert not target.exists()
    assert not (tmp_path / "other.duckdb").exists()
    assert sockets.written() == []


# --- what goes wrong while it runs --------------------------------------------------------------------------


def test_an_error_of_duckdb_is_raised_as_it_is_and_nothing_stays(nodes: Any, data: Any, sockets: Any) -> None:
    write_people(sockets, data, [["1", "a", "x", "5"]])
    with pytest.raises(duckdb.BinderException):
        go(numbers_pipeline(nodes, "SELECT nope FROM input"), sockets)
    assert sockets.written() == []


def test_an_error_of_the_polars_query_before_a_duckdb_step_is_the_error_polars_raised(
    nodes: Any, data: Any, sockets: Any
) -> None:
    canary = "CANARY-7f3a9c2e-not-for-the-terminal"
    write_people(sockets, data, [["1", canary, "x", "5"], ["2", "b", "y", "6"]])
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("boom", "transform.derive", "read", name="n", expr="CAST(name AS INT)"),
        nodes.step("query", "transform.sql", "boom", sql="SELECT * FROM input"),
        nodes.write("write", "query"),
    )
    with pytest.raises(pl.exceptions.InvalidOperationError):  # as on the fused path, not an error of DuckDB
        go(p, sockets)
    assert sockets.written() == []


def test_an_error_of_the_polars_query_two_duckdb_steps_up_is_still_the_error_polars_raised(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, [["1", "abc", "x", "5"]])
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("boom", "transform.derive", "read", name="n", expr="CAST(name AS INT)"),
        nodes.step("one", "transform.sql", "boom", sql="SELECT * FROM input"),
        nodes.step("two", "transform.sort", "one", by=["id"]),
        nodes.step("after", "transform.trim", "two", columns=["name"]),
        nodes.write("write", "after"),
    )
    with pytest.raises(pl.exceptions.InvalidOperationError):
        go(p, sockets)
    assert sockets.written() == []


def test_an_error_of_a_polars_step_after_a_duckdb_step_is_raised_as_it_is(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, [["1", "abc", "x", "5"]])
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("query", "transform.sql", "read", sql="SELECT * FROM input"),
        nodes.step("boom", "transform.derive", "query", name="n", expr="CAST(name AS INT)"),
        nodes.write("write", "boom"),
    )
    with pytest.raises(pl.exceptions.InvalidOperationError):
        go(p, sockets)
    assert sockets.written() == []


def test_a_step_after_a_duckdb_step_that_needs_a_column_that_is_not_there_is_a_config_error(
    nodes: Any, data: Any, sockets: Any
) -> None:
    write_people(sockets, data, [["1", "abc", "x", "5"]])
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("query", "transform.sql", "read", sql="SELECT id FROM input"),
        nodes.step("tidy", "transform.trim", "query", columns=["name"]),
        nodes.write("write", "tidy"),
    )
    with pytest.raises(ConfigError, match=r"tidy \(transform\.trim\): no column 'name'; the columns are: id"):
        go(p, sockets)
    assert sockets.written() == []


def test_a_conversion_in_the_sql_that_fails_raises_duckdbs_error_which_quotes_the_data(
    nodes: Any, data: Any, sockets: Any
) -> None:
    # This is why what DuckDB says is not shown (the command line shows the class and no more).
    canary = "CANARY-7f3a9c2e-not-for-the-terminal"
    write_people(sockets, data, [["1", canary, "x", "5"]])
    with pytest.raises(duckdb.ConversionException, match=canary):
        go(numbers_pipeline(nodes, "SELECT CAST(name AS INTEGER) AS n FROM input"), sockets)
    assert sockets.written() == []


def test_a_run_prints_and_logs_no_data_and_only_the_data_file_holds_it(
    nodes: Any,
    data: Any,
    sockets: Any,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "CANARY-7f3a9c2e-not-for-logs"
    rows = [[str(n), canary, canary, "1.5", "2026-01-05", canary] for n in range(1, 200)]
    data.write_csv(sockets.inbox / "a.csv", rows)
    caplog.set_level(logging.DEBUG)
    p = messy_with(nodes, "numbers", "transform.sort", by=[{"column": "id", "descending": True}])
    result = go(p, sockets, on_event=lambda event: None)
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert canary not in caplog.text
    holding = [name for name in sockets.written() if canary.encode() in (sockets.outbox / name).read_bytes()]
    assert holding == [f"messy/part-00000-{result.run_id}.parquet"]  # not the manifest, not a temporary file
    assert canary not in repr(result)


# --- the connection of a stage and its memory ---------------------------------------------------------------


@dataclass
class Session:
    """What a stage asked of DuckDB, and how its connection looked."""

    settings: SpillSettings
    threads: int | None = None
    temp_directory: str | None = None


@pytest.fixture
def sessions(monkeypatch: pytest.MonkeyPatch) -> list[Session]:
    seen: list[Session] = []
    real = hybrid.duckdb_session

    @contextmanager
    def spy(settings: SpillSettings) -> Iterator[duckdb.DuckDBPyConnection]:
        record = Session(settings)
        seen.append(record)
        with real(settings) as connection:
            threads = connection.execute("SELECT current_setting('threads')").fetchone()
            folder = connection.execute("SELECT current_setting('temp_directory')").fetchone()
            record.threads = None if threads is None else int(threads[0])
            record.temp_directory = None if folder is None else str(folder[0])
            yield connection

    monkeypatch.setattr(hybrid, "duckdb_session", spy)
    return seen


def simple_sql_pipeline(nodes: Any, **spec: Any) -> Any:
    return nodes.pipeline(
        nodes.read(),
        nodes.step(
            "query", "transform.sql", "read", sql="SELECT city, count(*) AS n FROM input GROUP BY city"
        ),
        nodes.write("write", "query"),
        **spec,
    )


def wide_rows(count: int, width: int = 280) -> list[list[str]]:
    return [[str(n), f"{n:07d}" + "x" * width, "city", "1"] for n in range(count)]


def sort_wide(nodes: Any, **spec: Any) -> Any:
    return nodes.pipeline(
        nodes.read(),
        nodes.step("ordered", "transform.sort", "read", by=[{"column": "name", "descending": True}]),
        nodes.write("write", "ordered"),
        **spec,
    )


def test_every_stage_with_a_step_for_duckdb_gets_a_connection_of_its_own_that_spills_nowhere(
    nodes: Any, data: Any, sockets: Any, sessions: list[Session]
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(100))
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("one", "transform.sql", "read", sql="SELECT * FROM input"),
        nodes.write("raw", "one", path="raw/"),
        nodes.step("two", "transform.sort", "raw", by=["id"]),
        nodes.write("write", "two", path="sorted/"),
    )
    result = go(p, sockets)
    assert [stage.path for stage in result.stages] == ["hybrid", "hybrid"]
    assert [session.temp_directory for session in sessions] == ["", ""]


def test_a_run_with_no_step_for_duckdb_opens_no_connection(
    nodes: Any, data: Any, sockets: Any, sessions: list[Session]
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(50))
    go(nodes.messy(), sockets)
    assert sessions == []


def test_a_sort_that_fits_in_memory_runs(nodes: Any, data: Any, sockets: Any) -> None:
    write_people(sockets, data, wide_rows(2000))
    (stage,) = go(sort_wide(nodes), sockets).stages
    assert data.dataset(stage)["id"].to_list() == [str(n) for n in reversed(range(2000))]


def test_too_little_memory_is_a_clear_error_and_nothing_stays(
    nodes: Any, data: Any, sockets: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # DuckDB's own limit is what this checks: the watchdog samples once a second, so on a system that counts
    # memory otherwise (Linux: rss less shared pages) it can't stop the stage first. Both stops are safe.
    monkeypatch.setenv("SAFETWIN_TEST_WATCHDOG_INTERVAL_S", "1")
    write_people(sockets, data, wide_rows(400_000))  # about 120 MB to sort
    with pytest.raises(OutOfMemory) as failed:
        go(sort_wide(nodes), sockets, memory_limit_bytes=60 * MB)
    message = str(failed.value)
    assert message.startswith("the DuckDB steps of this stage (ordered (transform.sort)) ran out of memory")
    assert "the limit is 60 MB" in message
    assert "x" * 20 not in message  # what DuckDB says is not repeated
    assert isinstance(failed.value, SpillError)
    assert sockets.written() == []  # no file, no temporary file, no manifest


def test_the_memory_limit_reaches_duckdb(
    nodes: Any, data: Any, sockets: Any, sessions: list[Session]
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(50))
    go(simple_sql_pipeline(nodes), sockets, memory_limit_bytes=777 * MB, run_id="r1")
    go(simple_sql_pipeline(nodes), sockets, memory_limit_bytes=300 * MB, run_id="r2")
    go(simple_sql_pipeline(nodes), sockets, run_id="r3")
    assert [s.settings.memory_limit_bytes for s in sessions] == [
        777 * MB,
        300 * MB,
        default_memory_limit(),  # a quarter of the memory of this machine
    ]
    # DuckDB gets 80% of the limit, and a thread for every 200 MB of that (at most one for every core)
    assert [s.threads for s in sessions] == [duckdb_threads(s.settings.duckdb_memory_bytes) for s in sessions]
    assert [s.threads for s in sessions[:2]] == [min(3, os.cpu_count() or 1), min(1, os.cpu_count() or 1)]


@pytest.mark.parametrize("limit", [0, -5])
def test_a_memory_limit_below_one_byte_is_refused_before_anything_runs(
    nodes: Any, data: Any, sockets: Any, limit: int
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(50))
    with pytest.raises(ConfigError, match="the memory limit must be at least one byte"):
        go(simple_sql_pipeline(nodes), sockets, memory_limit_bytes=limit)
    assert sockets.written() == []


# --- the paths ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["fused", "batch"])
def test_a_stage_with_a_step_for_duckdb_can_not_be_forced_onto_another_path(
    nodes: Any, data: Any, sockets: Any, path: str
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(50))
    with pytest.raises(Unsupported, match=r"transform\.sql runs in DuckDB: only the hybrid path can run it"):
        go(simple_sql_pipeline(nodes), sockets, force_path=path)
    assert sockets.written() == []


def test_the_hybrid_path_can_be_asked_for_on_a_stage_that_has_nothing_for_duckdb(
    nodes: Any, data: Any, sockets: Any, tmp_path: Path
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(3000))
    outbox = tmp_path / "out-fused"
    outbox.mkdir()
    fused = run_pipeline_local(
        nodes.messy(), {"inbox": sockets.inbox, "outbox": outbox}, force_path="fused"
    ).stages[0]
    hybrid_stage = go(nodes.messy(), sockets, force_path="hybrid").stages[0]
    assert (fused.path, hybrid_stage.path) == ("fused", "hybrid")
    assert data.dataset(fused).equals(data.dataset(hybrid_stage))  # the same values, types and order
    assert fused.rows_per_node == hybrid_stage.rows_per_node


def test_progress_is_reported_for_a_hybrid_stage_with_the_nodes_that_duckdb_runs(
    nodes: Any, data: Any, sockets: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safetwin.dataplane import runtime

    monkeypatch.setattr(runtime, "EVENT_INTERVAL_S", 0.0)  # every change is reported
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(20000))
    events: list[ProgressEvent] = []
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("query", "transform.sql", "read", sql="SELECT id, name FROM input WHERE id IS NOT NULL"),
        nodes.step("tidy", "transform.trim", "query", columns=["name"]),
        nodes.write("write", "tidy"),
    )
    (stage,) = go(p, sockets, on_event=events.append).stages
    assert events
    assert {(event.stage, event.path) for event in events} == {(0, "hybrid")}
    assert all(list(event.rows_per_node) == ["read", "query", "tidy"] for event in events)
    assert events[-1].bytes_written > 0
    assert events[-1].bytes_written <= stage.files[0].bytes
    assert all(
        count <= stage.rows_per_node[node_id]
        for event in events
        for node_id, count in event.rows_per_node.items()
    )


def test_two_runs_one_after_the_other_do_not_disturb_each_other(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(500))
    first = go(simple_sql_pipeline(nodes), sockets, run_id="r-one")
    second = go(simple_sql_pipeline(nodes), sockets, run_id="r-two")
    assert data.dataset(first.stages[0]).sort("city").equals(data.dataset(second.stages[0]).sort("city"))
    assert sorted(path.name for path in (sockets.outbox / "data").glob("*.parquet")) == [
        "part-00000-r-one.parquet",
        "part-00000-r-two.parquet",
    ]
