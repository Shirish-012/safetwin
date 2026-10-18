"""The Phase 0 operators as Polars steps, their configs, the local sockets and the sink's paths."""

import os
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import polars as pl
import pytest

from safetwin.dataplane import operators
from safetwin.dataplane.operators import (
    ColumnsConfig,
    ConfigError,
    CsvSource,
    LocalSocketResolver,
    SqlStep,
    Unsupported,
    build_step,
    build_transform,
    csv_files,
    has_polars_builder,
    is_duckdb_operator,
    parse_config,
    plan_sink,
    quote_name,
)
from safetwin.spec.models import Node

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def node(operator: str, node_id: str = "step", **fields: Any) -> Node:
    return Node.model_validate({"id": node_id, "operator": operator, **fields})


def apply(operator: str, frame: dict[str, list[Any]], **config: Any) -> pl.DataFrame:
    """Run one step on a frame."""
    step = build_transform(node(operator, inputs=["x"], config=config))
    return step(pl.LazyFrame(frame)).collect()


# --- configs ------------------------------------------------------------------------------------------------

WRONG_CONFIGS = [
    ("transform.select", {}, "columns: Field required"),
    ("transform.select", {"columns": []}, "columns: List should have at least 1 item"),
    ("transform.select", {"columns": ["a", "a"]}, "columns: must not repeat"),
    ("transform.select", {"columns": ["a"], "extra": 1}, "extra: Extra inputs are not permitted"),
    ("transform.filter", {}, "expr: Field required"),
    ("transform.filter", {"expr": 5}, "expr: Input should be a valid string"),
    ("transform.derive", {"expr": "1"}, "name: Field required"),
    ("transform.derive", {"name": "", "expr": "1"}, "name: String should have at least 1 character"),
    ("transform.trim", {"columns": "a"}, "columns: Input should be a valid list"),
    ("transform.parse_dates", {"columns": ["a"], "format": 5}, "format: Input should be a valid string"),
    ("transform.cast", {"columns": {"a": "decimal"}}, "columns.a: Input should be 'string'"),
    ("transform.cast", {"columns": {}}, "columns: Dictionary should have at least 1 item"),
]


@pytest.mark.parametrize(("operator", "config", "message"), WRONG_CONFIGS)
def test_a_wrong_config_is_refused_with_the_node_the_operator_and_what_is_wrong(
    operator: str, config: dict[str, Any], message: str
) -> None:
    with pytest.raises(ConfigError, match=re.escape(f"tidy ({operator}): ") + ".*" + re.escape(message)):
        build_transform(node(operator, "tidy", config=config))


def test_the_message_about_a_config_does_not_repeat_what_was_wrong_in_it() -> None:
    bad = node("source.csv", config={"path": "x.csv", "delimiter": "TOPSECRETVALUE", "has_header": "ABCDEFG"})
    with pytest.raises(ConfigError) as refused:
        parse_config(CsvSource, bad)
    assert "delimiter" in str(refused.value)
    assert "has_header" in str(refused.value)
    assert "TOPSECRETVALUE" not in str(refused.value)
    assert "ABCDEFG" not in str(refused.value)


def test_config_values_must_have_the_right_type_and_are_not_converted() -> None:
    with pytest.raises(ConfigError, match="has_header: Input should be a valid boolean"):
        parse_config(CsvSource, node("source.csv", config={"path": "x", "has_header": "true"}))
    with pytest.raises(ConfigError, match="delimiter"):
        parse_config(CsvSource, node("source.csv", config={"path": "x", "delimiter": "ab"}))
    tab = parse_config(CsvSource, node("source.csv", config={"path": "x", "delimiter": "\t"}))
    assert tab.delimiter == "\t"


def test_header_is_another_name_for_has_header_and_not_both_at_once() -> None:
    for key in ("header", "has_header"):
        config = parse_config(CsvSource, node("source.csv", config={"path": "x", key: False}))
        assert config.has_header is False
    with pytest.raises(ConfigError, match="header is another name for has_header: give one of them"):
        parse_config(CsvSource, node("source.csv", config={"path": "x", "header": True, "has_header": True}))
    with pytest.raises(ConfigError, match="has_header: Input should be a valid boolean"):
        parse_config(CsvSource, node("source.csv", config={"path": "x", "header": "yes"}))


def test_the_csv_config_has_defaults() -> None:
    config = parse_config(CsvSource, node("source.csv", config={"path": "*.csv"}))
    assert (config.has_header, config.delimiter) == (True, ",")


def test_a_pinned_operator_version_finds_the_operator() -> None:
    assert apply("transform.trim@1", {"a": [" x "]}, columns=["a"])["a"].to_list() == ["x"]
    assert has_polars_builder("transform.filter@1")


def test_an_operator_that_does_not_exist_yet_is_not_implemented() -> None:
    assert not has_polars_builder("transform.dedupe")
    with pytest.raises(Unsupported, match=r"transform\.dedupe can't be run yet"):
        build_transform(node("transform.dedupe"))
    with pytest.raises(Unsupported, match=r"transform\.dedupe can't be run yet"):
        build_step(node("transform.dedupe"))
    assert issubclass(Unsupported, NotImplementedError)


# --- select, filter, derive ---------------------------------------------------------------------------------


def test_select_keeps_the_columns_in_the_order_given() -> None:
    frame = {"a": ["1"], "b": ["2"], "c": ["3"]}
    assert apply("transform.select", frame, columns=["c", "a"]).to_dicts() == [{"c": "3", "a": "1"}]


def test_a_column_that_is_not_there_is_an_error_that_lists_the_columns() -> None:
    with pytest.raises(ConfigError, match=r"no column 'z'; the columns are: a, b"):
        apply("transform.select", {"a": ["1"], "b": ["2"]}, columns=["a", "z"])


def test_a_long_list_of_columns_is_cut_short() -> None:
    wide = {f"c{number}": ["x"] for number in range(100)}
    with pytest.raises(ConfigError, match=r"c29, \.\.\. \(100 in all\)"):
        apply("transform.trim", wide, columns=["nope"])


def test_filter_keeps_the_rows_where_the_expression_is_true() -> None:
    frame = {"id": ["1", None, "3", ""], "name": ["a", "b", None, "d"]}
    assert apply("transform.filter", frame, expr="id IS NOT NULL")["id"].to_list() == ["1", "3", ""]
    both = apply("transform.filter", frame, expr="id IS NOT NULL AND name IS NOT NULL")
    assert both["id"].to_list() == ["1", ""]


def test_a_row_where_the_expression_is_null_is_dropped() -> None:
    frame = {"n": ["1", None, "3"]}
    assert apply("transform.filter", frame, expr="n = '1' OR n = '3'")["n"].to_list() == ["1", "3"]


def test_derive_adds_a_column_or_replaces_one() -> None:
    frame = {"a": ["x", None], "b": ["y", "z"]}
    added = apply("transform.derive", frame, name="c", expr="upper(a) || '-' || b")
    assert added.columns == ["a", "b", "c"]
    assert added["c"].to_list() == ["X-y", None]
    replaced = apply("transform.derive", frame, name="a", expr="coalesce(a, 'none')")
    assert replaced.columns == ["a", "b"]
    assert replaced["a"].to_list() == ["x", "none"]


def test_an_expression_that_cannot_be_parsed_is_a_config_error_before_any_data_moves() -> None:
    with pytest.raises(
        ConfigError, match=r"step \(transform\.filter\): the expression can't be used: .*parse"
    ):
        build_transform(node("transform.filter", config={"expr": "id IS NOT"}))


# --- an expression may not hold a query ---------------------------------------------------------------------

QUERIES = {
    "a subquery": "id IN (SELECT id FROM read_csv('/etc/hosts'))",
    "a subquery in lower case": "id in (select id from read_csv('/etc/hosts'))",
    "a value from a subquery": "id = (SELECT max(a) FROM read_csv('x.csv'))",
    "EXISTS": "EXISTS (SELECT 1 FROM read_csv('/etc/hosts'))",
    "VALUES": "id IN (VALUES ('1'))",
    "WITH": "id IN (WITH t AS (SELECT 1) SELECT * FROM t)",
    "a comment to hide a quote": "id /* ' */ IN (SELECT id FROM read_csv('/etc/hosts')) /* ' */",
    "a line comment": "id IN (SELECT 1 FROM t) -- ' ",
    "only a comment": "id IS NOT NULL -- and more",
    "a block comment": "id IS NOT NULL /* and more */",
    "an unclosed block comment": "id IS NOT NULL /* and more",
    "FROM first": "id IN (FROM read_csv('/etc/hosts'))",
    "a second statement": "id IS NOT NULL; SELECT 1",
    "a backtick": "`id` IN (SELECT 1)",
    "an unclosed string": "id = 'abc",
    "a bracket": "[id]",
    "a dollar quote": "$$ x $$",
    "a cast operator": "a::int > 1",
    "a regex operator": "name ~ '^A.*'",
    "a name that is not ASCII": "日本 = 'x'",
}


@pytest.mark.parametrize("expr", QUERIES.values(), ids=QUERIES.keys())
def test_a_query_in_an_expression_is_refused_before_polars_sees_the_text(
    expr: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Polars opens the files of a subquery while it parses the expression, so it must not be asked to.
    def parsed(text: str) -> pl.Expr:
        raise AssertionError("Polars was asked to parse the expression")

    monkeypatch.setattr(pl, "sql_expr", parsed)
    for operator, config in (
        ("transform.filter", {"expr": expr}),
        ("transform.derive", {"name": "x", "expr": expr}),
    ):
        with pytest.raises(ConfigError, match=r"can't contain|is not allowed in an expression"):
            build_transform(node(operator, config=config))


def test_a_subquery_that_reads_a_file_does_not_read_it(tmp_path: Path) -> None:
    secret = tmp_path / "secret.csv"
    secret.write_text("TOPSECRETHEADER\nvalue\n")
    with pytest.raises(ConfigError) as refused:
        build_transform(
            node("transform.filter", config={"expr": f"id IN (SELECT x FROM read_csv('{secret}'))"})
        )
    assert "TOPSECRETHEADER" not in str(refused.value)  # Polars' own error would list the columns of the file


@pytest.mark.parametrize(
    "expr",
    [
        "city = 'select'",
        "note = 'the table with the values from here'",
        "note = 'it''s a SELECT'",
        '"select" IS NULL',
        "a || '--' || b = 'x'",
        "a || '/* not a comment */' = b",
        "length(name) > 3 AND (amount + 1.5e3) % 2 <> 0",
        "CAST(a AS INT) > 1 AND b != 'x' AND c >= 2 AND d <= 3",
        "name LIKE 'A%'",
        "\"日本\" = 'x'",  # a name in double quotes may hold any text
    ],
)
def test_words_inside_strings_and_quoted_names_are_not_queries(expr: str) -> None:
    build_transform(node("transform.filter", config={"expr": expr}))  # parsed and accepted


# --- trim ---------------------------------------------------------------------------------------------------


def test_trim_strips_the_whitespace_at_both_ends_and_leaves_the_inside() -> None:
    nbsp = chr(0xA0)  # a no-break space counts as whitespace too
    frame = {"name": ["  Bob  ", "\tDave\n", " a  b ", "", None, f"{nbsp}Eve{nbsp}"], "other": [" x "] * 6}
    trimmed = apply("transform.trim", frame, columns=["name"])
    assert trimmed["name"].to_list() == ["Bob", "Dave", "a  b", "", None, "Eve"]
    assert trimmed["other"].to_list() == [" x "] * 6  # the columns not named are left alone


def test_trim_needs_text_columns() -> None:
    with pytest.raises(ConfigError, match=r"'n' must be text"):
        apply("transform.trim", {"n": [1, 2]}, columns=["n"])


# --- parse_dates --------------------------------------------------------------------------------------------

UTC_TYPE = pl.Datetime("us", "UTC")


def parsed(values: list[str | None], **config: Any) -> list[datetime | None]:
    step = build_transform(node("transform.parse_dates", inputs=["x"], config={"columns": ["d"], **config}))
    frame = pl.LazyFrame({"d": pl.Series(values, dtype=pl.String)})  # text even when every value is null
    return step(frame).collect()["d"].to_list()


def utc(*args: int, micro: int = 0) -> datetime:
    return datetime(*args, microsecond=micro, tzinfo=UTC)


def test_dates_without_a_format_are_read_as_iso_8601_and_come_out_in_utc() -> None:
    values = [
        "2026-01-05 10:00:00",  # no offset: taken to be UTC
        "2026-01-05T10:00:00",
        "2026-01-05T10:00:00Z",
        "2026-01-05T10:00:00+05:30",  # converted to UTC
        "2026-01-05 10:00:00-0200",
        "2026-01-05 10:00:00.25",
        "2026-01-05T10:00:00.123456Z",
        "2026-01-05",
    ]
    assert parsed(values) == [
        utc(2026, 1, 5, 10),
        utc(2026, 1, 5, 10),
        utc(2026, 1, 5, 10),
        utc(2026, 1, 5, 4, 30),
        utc(2026, 1, 5, 12),
        utc(2026, 1, 5, 10, micro=250000),
        utc(2026, 1, 5, 10, micro=123456),
        utc(2026, 1, 5),
    ]


def test_what_is_not_a_date_becomes_null() -> None:
    junk = ["junk", "", None, "2026-13-45", "2026-01-05 25:00:00", "05/01/2026", "2026-01-05T10:00"]
    assert parsed(junk) == [None] * len(junk)


def test_the_column_keeps_its_name_and_gets_a_utc_timestamp_type() -> None:
    result = apply("transform.parse_dates", {"d": ["2026-01-05"], "e": ["x"]}, columns=["d"])
    assert result.columns == ["d", "e"]
    assert result.schema["d"] == UTC_TYPE
    assert result.schema["e"] == pl.String


def test_a_format_is_used_instead_of_the_list() -> None:
    assert parsed(["05/01/2026", "2026-01-05"], format="%d/%m/%Y") == [utc(2026, 1, 5), None]
    assert parsed(["2026-01-05T10:00:00+05:30"], format="%Y-%m-%dT%H:%M:%S%z") == [utc(2026, 1, 5, 4, 30)]


def test_the_result_does_not_depend_on_how_the_rows_are_cut_into_chunks() -> None:
    # Polars' own guess of a format comes from the first value of each chunk, so it could differ for the
    # same file. A fixed list cannot.
    values: list[str | None] = [
        "junk",
        "2026-01-05 10:00:00",
        "2026-01-06",
        "06/01/2026",
        None,
        "2026-01-07T01:02:03Z",
    ]
    whole = parsed(values)
    assert [parsed([value])[0] for value in values] == whole
    assert [x for i in range(0, len(values), 2) for x in parsed(values[i : i + 2])] == whole


def test_parse_dates_needs_text_columns() -> None:
    with pytest.raises(ConfigError, match=r"'d' must be text"):
        apply("transform.parse_dates", {"d": [1]}, columns=["d"])


# --- cast ---------------------------------------------------------------------------------------------------


def test_cast_converts_and_makes_null_what_cannot_be_converted() -> None:
    frame = {
        "i": ["12", "+5", "007", " 12 ", "1.5", "abc", "", None],
        "f": ["1.5", "1e3", "x", "", None, "-0", "2", "3"],
    }
    result = apply("transform.cast", frame, columns={"i": "int", "f": "float"})
    assert result.schema == pl.Schema({"i": pl.Int64, "f": pl.Float64})
    assert result["i"].to_list() == [12, 5, 7, None, None, None, None, None]
    assert result["f"].to_list() == [1.5, 1000.0, None, None, None, -0.0, 2.0, 3.0]


def test_cast_to_date_reads_iso_dates_and_to_string_turns_anything_into_text() -> None:
    frame = {"d": ["2026-01-05", "2026-13-45", "05/01/2026", None]}
    assert apply("transform.cast", frame, columns={"d": "date"})["d"].to_list() == [
        date(2026, 1, 5),
        None,
        None,
        None,
    ]
    again = apply("transform.cast", {"n": [1, 2]}, columns={"n": "string"})
    assert again["n"].to_list() == ["1", "2"]
    assert again.schema["n"] == pl.String


def test_cast_to_date_needs_a_text_column() -> None:
    with pytest.raises(ConfigError, match="'n' must be text"):
        apply("transform.cast", {"n": [1]}, columns={"n": "date"})
    with pytest.raises(ConfigError, match="no column 'z'"):
        apply("transform.cast", {"n": ["1"]}, columns={"z": "int"})


# --- the steps that DuckDB runs -----------------------------------------------------------------------------


def sql_step(operator: str, **config: Any) -> SqlStep:
    step = build_step(node(operator, "heavy", inputs=["x"], config=config))
    assert isinstance(step, SqlStep)
    return step


def test_sql_and_sort_are_the_operators_that_duckdb_runs() -> None:
    assert is_duckdb_operator("transform.sql")
    assert is_duckdb_operator("transform.sort")
    assert is_duckdb_operator("transform.sql@1")
    assert not is_duckdb_operator("transform.filter")
    assert not is_duckdb_operator("transform.dedupe")  # it can't be run at all yet
    assert not has_polars_builder("transform.sql")
    assert not has_polars_builder("transform.sort")


def test_a_step_for_duckdb_is_not_a_polars_step_and_says_where_it_runs() -> None:
    for operator in ("transform.sql", "transform.sort@1"):
        with pytest.raises(Unsupported, match="runs in DuckDB, which only the hybrid path uses"):
            build_transform(node(operator))


def test_the_sql_of_a_sql_step_is_kept_as_it_is() -> None:
    sql = "SELECT city, count(*) AS n\nFROM input -- the table\nGROUP BY city"
    assert sql_step("transform.sql", sql=sql) == SqlStep(sql, ())
    assert sql_step("transform.sql@1", sql="FROM input") == SqlStep("FROM input", ())


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM input",
        "select 1;",
        "SELECT 1;;",
        "WITH a AS (SELECT * FROM input) SELECT * FROM a",
        "FROM input WHERE id IS NOT NULL",
        "SELECT * FROM input UNION ALL SELECT * FROM input",
        "SELECT 'a;b' AS x",
        "VALUES (1), (2)",
        "SELECT * FROM input /* a comment */ -- another",
        "PIVOT input ON city IN ('a', 'b') USING count(*)",
        "SELECT sum(amount) OVER (PARTITION BY city) FROM input",
    ],
)
def test_one_select_statement_is_a_query(sql: str) -> None:
    assert sql_step("transform.sql", sql=sql).sql == sql


@pytest.mark.parametrize(
    ("sql", "found"),
    [
        ("", "none"),
        ("   ", "none"),
        ("-- only a comment", "none"),
        (";", "none"),
        ("SELECT 1; SELECT 2", "SELECT, SELECT"),
        ("SELECT 1; DROP TABLE input", "SELECT, DROP"),
        ("CREATE TABLE t AS SELECT * FROM input", "CREATE"),
        ("COPY (SELECT * FROM input) TO '/tmp/x.csv'", "COPY"),
        ("ATTACH '/tmp/x.duckdb' AS x", "ATTACH"),
        ("INSTALL httpfs", "LOAD"),
        ("LOAD httpfs", "LOAD"),
        ("SET threads = 64", "SET"),
        ("SET enable_external_access = true", "SET"),
        ("SET lock_configuration = false", "SET"),
        ("USE memory", "SET"),
        ("EXPLAIN SELECT * FROM input", "EXPLAIN"),
        ("CALL pragma_version()", "CALL"),
        ("CHECKPOINT", "CALL"),
        ("INSERT INTO input VALUES (1)", "INSERT"),
        ("DROP TABLE input", "DROP"),
        ("EXPORT DATABASE '/tmp/x'", "EXPORT"),
        ("PIVOT input ON city USING count(*)", "CREATE, SELECT"),  # it makes a type first
    ],
)
def test_anything_but_one_select_statement_is_refused_before_any_data_moves(sql: str, found: str) -> None:
    with pytest.raises(ConfigError) as refused:
        sql_step("transform.sql", sql=sql)
    assert str(refused.value) == (
        "heavy (transform.sql): the SQL must be exactly one SELECT statement that reads `input` "
        f"(found: {found})"
    )


def test_sql_that_can_not_be_parsed_is_refused_and_says_what_is_wrong_with_the_text() -> None:
    with pytest.raises(
        ConfigError, match=r"heavy \(transform\.sql\): the SQL can't be parsed: Parser Error: syntax error"
    ):
        sql_step("transform.sql", sql="SELECT * FORM input")
    with pytest.raises(
        ConfigError, match="the SQL can't be parsed: Parser Error: syntax error at end of input"
    ):
        sql_step("transform.sql", sql="SELECT * FROM")


def test_the_message_about_a_text_that_can_not_be_parsed_is_one_line() -> None:
    with pytest.raises(ConfigError) as refused:
        sql_step(
            "transform.sql", sql="SELECT *\nFORM input"
        )  # DuckDB's message shows the line, in more lines
    assert "\n" not in str(refused.value)


def test_a_sql_text_with_a_nul_is_an_error_not_a_crash() -> None:
    with pytest.raises(ConfigError, match=r"heavy \(transform\.sql\): the SQL can't be parsed: .*NUL"):
        sql_step("transform.sql", sql="SELECT 1\x00; DROP TABLE x")


def test_checking_the_sql_does_not_run_it(tmp_path: Path) -> None:
    target = tmp_path / "out.csv"
    with pytest.raises(ConfigError):
        sql_step("transform.sql", sql=f"COPY (SELECT 1 AS a) TO '{target}'")
    with pytest.raises(ConfigError):
        sql_step("transform.sql", sql=f"SELECT 1; COPY (SELECT 1 AS a) TO '{target}'")
    assert not target.exists()


def test_sort_by_a_column_is_ascending_with_the_nulls_last() -> None:
    assert sql_step("transform.sort", by=["id"]) == SqlStep(
        'SELECT * FROM input ORDER BY "id" ASC NULLS LAST', ("id",)
    )


def test_sort_by_many_columns_in_the_order_given_each_ascending_or_descending() -> None:
    step = sql_step(
        "transform.sort",
        by=["city", {"column": "amount", "descending": True}, {"column": "name", "descending": False}],
        nulls="first",
    )
    assert step.sql == (
        'SELECT * FROM input ORDER BY "city" ASC NULLS FIRST, "amount" DESC NULLS FIRST, '
        '"name" ASC NULLS FIRST'
    )
    assert step.needs == ("city", "amount", "name")


def test_sort_can_put_the_nulls_last_for_every_column() -> None:
    step = sql_step("transform.sort", by=[{"column": "a", "descending": True}, "b"], nulls="last")
    assert step.sql == 'SELECT * FROM input ORDER BY "a" DESC NULLS LAST, "b" ASC NULLS LAST'


@pytest.mark.parametrize(
    ("name", "quoted"),
    [
        ("id", '"id"'),
        ("first name", '"first name"'),
        ('say "hi"', '"say ""hi"""'),
        ("select", '"select"'),
        ("a;b -- c", '"a;b -- c"'),
        ("Zo\u00eb", '"Zo\u00eb"'),
        ("a'b", '"a\'b"'),
    ],
)
def test_a_column_name_is_quoted_as_an_identifier_so_it_is_never_sql(name: str, quoted: str) -> None:
    assert quote_name(name) == quoted
    assert (
        sql_step("transform.sort", by=[name]).sql == f"SELECT * FROM input ORDER BY {quoted} ASC NULLS LAST"
    )


def test_the_sql_of_a_sort_with_a_hostile_column_name_is_one_select() -> None:
    from safetwin.dataplane.operators import _check_query

    name = '"; DROP TABLE input; --'
    sql = sql_step("transform.sort", by=[name]).sql
    _check_query(sql)  # one SELECT statement, whatever the column is called


def test_the_connection_that_parses_sql_looks_for_extensions_in_the_folder_of_the_app(
    safetwin_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safetwin.dataplane.operators import _check_query

    configs: list[dict[str, Any]] = []
    real = operators.duckdb.connect

    def spy(database: str, config: dict[str, Any]) -> Any:
        configs.append(config)
        return real(database, config=config)

    monkeypatch.delenv("SAFETWIN_DUCKDB_EXTENSIONS", raising=False)
    monkeypatch.setattr(operators.duckdb, "connect", spy)
    _check_query("SELECT * FROM input")
    (config,) = configs
    assert config["extension_directory"] == str(safetwin_home / "duckdb_extensions")  # not ~/.duckdb
    assert config["autoinstall_known_extensions"] is False
    assert config["autoload_known_extensions"] is False
    assert config["enable_external_access"] is False
    assert not (safetwin_home / "duckdb_extensions").exists()  # named, not made


DUCKDB_CONFIGS = [
    ("transform.sql", {}, "sql: Field required"),
    ("transform.sql", {"sql": 5}, "sql: Input should be a valid string"),
    ("transform.sql", {"sql": "SELECT 1", "extra": 1}, "extra: Extra inputs are not permitted"),
    ("transform.sort", {}, "by: Field required"),
    ("transform.sort", {"by": []}, "by: List should have at least 1 item"),
    ("transform.sort", {"by": "id"}, "by: Input should be a valid list"),
    ("transform.sort", {"by": [5]}, "by.0: Input should be a valid dictionary or instance of SortKey"),
    ("transform.sort", {"by": [""]}, "by.0.column: String should have at least 1 character"),
    ("transform.sort", {"by": ["a", "a"]}, "by: must not repeat a column"),
    ("transform.sort", {"by": ["a", {"column": "a", "descending": True}]}, "by: must not repeat a column"),
    (
        "transform.sort",
        {"by": [{"column": ""}]},
        "by.0.column: String should have at least 1 character",
    ),
    (
        "transform.sort",
        {"by": [{"column": "a", "desc": True}]},
        "by.0.desc: Extra inputs are not permitted",
    ),
    ("transform.sort", {"by": [{"descending": True}]}, "by.0.column: Field required"),
    (
        "transform.sort",
        {"by": [{"column": "a", "descending": "yes"}]},
        "descending: Input should be a valid boolean",
    ),
    ("transform.sort", {"by": ["a"], "nulls": "middle"}, "nulls: Input should be 'first' or 'last'"),
    ("transform.sort", {"by": ["a"], "extra": 1}, "extra: Extra inputs are not permitted"),
]


@pytest.mark.parametrize(("operator", "config", "message"), DUCKDB_CONFIGS)
def test_a_wrong_config_of_a_duckdb_step_is_refused_with_the_node_the_operator_and_what_is_wrong(
    operator: str, config: dict[str, Any], message: str
) -> None:
    with pytest.raises(ConfigError, match=re.escape(f"heavy ({operator}): ") + ".*(" + message + ")"):
        build_step(node(operator, "heavy", config=config))


# --- sockets that are folders -------------------------------------------------------------------------------


@pytest.fixture
def folders(tmp_path: Path) -> dict[str, Path]:
    for name in ("in", "out", "outside"):
        (tmp_path / name).mkdir()
    return {"in": tmp_path / "in", "out": tmp_path / "out", "outside": tmp_path / "outside"}


def test_a_socket_is_found_by_its_alias_or_by_its_uri(folders: dict[str, Path]) -> None:
    aliases = {"inbox": "socket://local-inbox"}
    by_alias = LocalSocketResolver({"inbox": folders["in"]}, aliases)
    by_uri = LocalSocketResolver({"socket://local-inbox": folders["in"]}, aliases)
    for resolver in (by_alias, by_uri):
        assert resolver.root("inbox") == folders["in"].resolve()  # the node names the alias...
        assert resolver.root("socket://local-inbox") == folders["in"].resolve()  # ...or the URI
    assert by_alias.uri("inbox") == "socket://local-inbox"
    assert by_alias.uri("socket://x") == "socket://x"


def test_an_unknown_socket_says_which_ones_have_a_folder(folders: dict[str, Path]) -> None:
    resolver = LocalSocketResolver({"inbox": folders["in"], "outbox": folders["out"]})
    known = r"\(folders were given for: inbox, outbox\)"
    with pytest.raises(ConfigError, match=rf"socket 'nowhere' has no folder {known}"):
        resolver.root("nowhere")
    with pytest.raises(ConfigError, match="has no folder"):
        LocalSocketResolver({}).root("inbox")


def test_the_folder_of_a_socket_must_exist_and_is_not_made(tmp_path: Path) -> None:
    missing = tmp_path / "NOT_MOUNTED"  # a disk that is not mounted
    resolver = LocalSocketResolver({"staging": missing})
    with pytest.raises(ConfigError, match="socket 'staging' is not a folder"):
        resolver.root("staging")
    with pytest.raises(ConfigError, match="not a folder"):
        resolver.resolve("staging", "out")
    assert not missing.exists()
    (tmp_path / "file").write_text("x")
    with pytest.raises(ConfigError, match="not a folder"):
        LocalSocketResolver({"staging": tmp_path / "file"}).root("staging")


def test_the_folder_may_be_a_symlink_to_a_folder(tmp_path: Path, folders: dict[str, Path]) -> None:
    (tmp_path / "link").symlink_to(folders["in"])
    resolver = LocalSocketResolver({"inbox": tmp_path / "link"})
    assert resolver.resolve("inbox", "a/b.csv") == folders["in"].resolve() / "a" / "b.csv"


@pytest.mark.parametrize(
    "relative",
    ["..", "../x", "a/../../x", "a/../..", "/etc/passwd", "/", "\x00", "a\x00b", "sub/../../in_the_sibling"],
)
def test_a_path_that_goes_up_or_is_absolute_is_refused(folders: dict[str, Path], relative: str) -> None:
    resolver = LocalSocketResolver({"inbox": folders["in"]})
    with pytest.raises(ConfigError, match="must be a path below the socket"):
        resolver.resolve("inbox", relative)
    with pytest.raises(ConfigError, match="must be a path below the socket"):
        resolver.glob("inbox", relative)


def test_paths_below_the_folder_are_found_even_if_they_do_not_exist_yet(folders: dict[str, Path]) -> None:
    resolver = LocalSocketResolver({"out": folders["out"]})
    root = folders["out"].resolve()
    assert resolver.resolve("out", "a/b/c") == root / "a" / "b" / "c"
    assert resolver.resolve("out", "./a//b/") == root / "a" / "b"
    assert resolver.resolve("out", "") == root
    assert resolver.resolve("out", ".") == root


def test_a_symlink_that_leads_out_of_the_socket_is_refused(tmp_path: Path, folders: dict[str, Path]) -> None:
    (folders["in"] / "escape").symlink_to(folders["outside"])
    (folders["in"] / "file_escape").symlink_to(folders["outside"] / "x.csv")
    (folders["outside"] / "x.csv").write_text("a\n1\n")
    (folders["in"] / "dangling").symlink_to(tmp_path / "nowhere")
    resolver = LocalSocketResolver({"inbox": folders["in"]})
    for relative in ("escape", "escape/new_file", "file_escape", "dangling"):
        with pytest.raises(ConfigError, match=r"leads out of socket 'inbox' \(through a symlink\)"):
            resolver.resolve("inbox", relative)


def test_a_symlink_that_stays_inside_the_socket_is_fine(folders: dict[str, Path]) -> None:
    (folders["in"] / "real").mkdir()
    (folders["in"] / "alias").symlink_to(folders["in"] / "real")
    resolver = LocalSocketResolver({"inbox": folders["in"]})
    assert resolver.resolve("inbox", "alias/x") == folders["in"].resolve() / "real" / "x"


def test_glob_finds_the_files_in_name_order_and_skips_folders_and_hidden_files(
    folders: dict[str, Path],
) -> None:
    root = folders["in"]
    for name in ("b.csv", "a.csv", "c.txt", ".hidden.csv", "._apple.csv"):
        (root / name).write_text("x")
    (root / "folder.csv").mkdir()
    (root / "sub").mkdir()
    (root / "sub" / "d.csv").write_text("x")
    resolver = LocalSocketResolver({"inbox": root})
    real = root.resolve()
    assert resolver.glob("inbox", "*.csv") == [real / "a.csv", real / "b.csv"]
    assert resolver.glob("inbox", "**/*.csv") == [real / "a.csv", real / "b.csv", real / "sub" / "d.csv"]
    assert resolver.glob("inbox", "sub/*.csv") == [real / "sub" / "d.csv"]
    assert resolver.glob("inbox", "a.csv") == [real / "a.csv"]
    assert resolver.glob("inbox", "*.parquet") == []
    assert resolver.glob("inbox", "sub") == []  # a folder is not a file


def test_glob_refuses_a_file_that_is_a_symlink_out_of_the_socket(folders: dict[str, Path]) -> None:
    (folders["outside"] / "secret.csv").write_text("a\n1\n")
    (folders["in"] / "ok.csv").write_text("a\n1\n")
    (folders["in"] / "link.csv").symlink_to(folders["outside"] / "secret.csv")
    resolver = LocalSocketResolver({"inbox": folders["in"]})
    with pytest.raises(ConfigError, match=r"'link\.csv' leads out of socket 'inbox'"):
        resolver.glob("inbox", "*.csv")


def test_csv_files_needs_at_least_one_file(folders: dict[str, Path]) -> None:
    resolver = LocalSocketResolver({"inbox": folders["in"]})
    source = node("source.csv", "read", socket="inbox", config={"path": "*.csv"})
    with pytest.raises(ConfigError, match=r"read \(source\.csv\): no file matches '\*\.csv' in its socket"):
        csv_files(source, parse_config(CsvSource, source), resolver)


# --- where the sink writes ----------------------------------------------------------------------------------


def sink(path: str, node_id: str = "write", **config: Any) -> Node:
    return node("sink.parquet", node_id, socket="outbox", inputs=["x"], config={"path": path, **config})


@pytest.fixture
def outbox(folders: dict[str, Path]) -> LocalSocketResolver:
    return LocalSocketResolver({"outbox": folders["out"]}, {"outbox": "socket://local-outbox"})


def test_a_plain_path_is_the_dataset_and_the_file_goes_in_it(
    outbox: LocalSocketResolver, folders: dict[str, Path]
) -> None:
    plan = plan_sink(sink("clean/"), outbox, "r45", NOW)
    root = folders["out"].resolve()
    assert plan.file == root / "clean" / "part-00000-r45.parquet"
    assert plan.dataset_dir == root / "clean"
    assert plan.relative == "part-00000-r45.parquet"
    assert plan.dataset == "clean"
    assert plan.uri == "socket://local-outbox/clean"
    assert plan_sink(sink("clean"), outbox, "r45", NOW) == plan  # the slash does not matter


def test_the_placeholders_are_filled_in_and_the_dataset_is_what_comes_before_them(
    outbox: LocalSocketResolver, folders: dict[str, Path]
) -> None:
    plan = plan_sink(sink("SafeTwin/sales/dt={yyyy}-{MM}-{dd}/{run_id}/"), outbox, "r45", NOW)
    root = folders["out"].resolve()
    assert plan.file == root / "SafeTwin/sales/dt=2026-09-30/r45/part-00000-r45.parquet"
    assert plan.dataset_dir == root / "SafeTwin" / "sales"  # the manifest goes here
    assert plan.relative == "dt=2026-09-30/r45/part-00000-r45.parquet"  # as the manifest says it
    assert plan.dataset == "SafeTwin/sales"
    assert plan.uri == "socket://local-outbox/SafeTwin/sales"


def test_a_path_that_is_all_placeholders_makes_the_socket_folder_the_dataset(
    outbox: LocalSocketResolver, folders: dict[str, Path]
) -> None:
    plan = plan_sink(sink("{yyyy}/{MM}"), outbox, "r1", datetime(2027, 1, 2, tzinfo=UTC))
    assert plan.dataset_dir == folders["out"].resolve()
    assert plan.relative == "2027/01/part-00000-r1.parquet"
    assert (plan.dataset, plan.uri) == (".", "socket://local-outbox")


def test_an_empty_path_writes_in_the_socket_folder(
    outbox: LocalSocketResolver, folders: dict[str, Path]
) -> None:
    plan = plan_sink(sink(""), outbox, "r1", NOW)
    assert plan.file == folders["out"].resolve() / "part-00000-r1.parquet"
    assert plan.dataset == "."


def test_an_unknown_placeholder_is_an_error_that_lists_the_known_ones(outbox: LocalSocketResolver) -> None:
    message = r"write \(sink\.parquet\): unknown placeholder \{hour\}; the known ones are"
    with pytest.raises(ConfigError, match=message):
        plan_sink(sink("x/{hour}/"), outbox, "r1", NOW)


def test_a_path_that_is_a_file_name_is_refused(outbox: LocalSocketResolver) -> None:
    with pytest.raises(ConfigError, match="path is a folder, not a file"):
        plan_sink(sink("out.parquet"), outbox, "r1", NOW)


@pytest.mark.parametrize("path", ["../x/", "/tmp/x/", "a/../../x", "{yyyy}/../../x"])
def test_a_sink_path_that_leaves_the_socket_is_refused(outbox: LocalSocketResolver, path: str) -> None:
    with pytest.raises(ConfigError, match=r"write \(sink\.parquet\): .*must be a path below the socket"):
        plan_sink(sink(path), outbox, "r1", NOW)


def test_a_sink_folder_that_is_a_symlink_out_is_refused(
    outbox: LocalSocketResolver, folders: dict[str, Path]
) -> None:
    (folders["out"] / "escape").symlink_to(folders["outside"])
    with pytest.raises(ConfigError, match="'escape' leads out of socket 'outbox'"):
        plan_sink(sink("escape/"), outbox, "r1", NOW)
    with pytest.raises(ConfigError, match="leads out of socket 'outbox'"):
        plan_sink(sink("escape/deeper/{run_id}"), outbox, "r1", NOW)
    assert os.listdir(folders["outside"]) == []


def test_the_compression_is_zstd_level_3() -> None:
    assert operators.PARQUET_COMPRESSION == "zstd"
    assert operators.PARQUET_COMPRESSION_LEVEL == 3
    with pytest.raises(ConfigError, match="compression: Input should be 'zstd'"):
        plan_sink(sink("x/", compression="snappy"), LocalSocketResolver({}), "r1", NOW)


def test_columns_config_is_shared_by_select_and_trim() -> None:
    config = parse_config(ColumnsConfig, node("transform.trim", config={"columns": ["a", "b"]}))
    assert config.columns == ["a", "b"]
