"""Reading and writing pipeline files: YAML in, YAML out, JSON Schema out."""

import datetime
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from safetwin.spec import (
    Pipeline,
    Problem,
    SpecError,
    dump_pipeline,
    load_pipeline_file,
    load_pipeline_text,
)
from safetwin.spec import io as io_module
from safetwin.spec import schema as schema_module

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = sorted((REPO / "tests" / "fixtures").glob("*.yaml"))
CSV_CLEAN = REPO / "tests" / "fixtures" / "csv-clean.yaml"
ORDERS = REPO / "tests" / "fixtures" / "orders-report.yaml"
CSV_TEXT = CSV_CLEAN.read_text(encoding="utf-8")

Doc = Callable[..., dict[str, Any]]


def problems_of(text: str) -> list[Problem]:
    with pytest.raises(SpecError) as caught:
        load_pipeline_text(text)
    return caught.value.problems


# --- loading -------------------------------------------------------------------------------------


def test_a_pipeline_loads_from_a_file_or_from_text(tmp_path: Path) -> None:
    expected = load_pipeline_file(CSV_CLEAN)
    copy = tmp_path / "copy.yaml"
    copy.write_text(CSV_TEXT, encoding="utf-8")
    assert expected.metadata.name == "csv-clean"
    assert load_pipeline_file(copy) == expected
    assert load_pipeline_text(CSV_TEXT) == expected


def test_text_is_never_taken_for_a_file_name(tmp_path: Path) -> None:
    copy = tmp_path / "copy.yaml"
    copy.write_text(CSV_TEXT, encoding="utf-8")
    (problem,) = problems_of(str(copy))  # the file exists, but this function only reads the text it is given
    assert problem.message.startswith("(top level): ")


def test_a_file_that_is_not_utf8_text_is_a_yaml_error_not_a_crash(tmp_path: Path) -> None:
    binary = tmp_path / "binary.yaml"
    binary.write_bytes(b"apiVersion: \xff\xfe\x00\x81 binary")
    with pytest.raises(SpecError) as caught:
        load_pipeline_file(binary)
    assert [problem.code for problem in caught.value.problems] == ["yaml_error"]


def test_json_is_yaml_too() -> None:
    document = json.dumps(yaml.safe_load(CSV_TEXT))
    assert "\n" not in document
    assert load_pipeline_text(document) == load_pipeline_file(CSV_CLEAN)


def test_a_missing_file_is_an_ordinary_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_pipeline_file(tmp_path / "nope.yaml")


def test_an_on_key_stays_a_string() -> None:
    # Plain YAML 1.1 loaders turn an unquoted `on:` key into True.
    text = CSV_TEXT.replace("        header: true", "        header: true\n        join: {on: id}")
    assert load_pipeline_text(text).spec.nodes[0].config["join"] == {"on": "id"}


def test_only_true_and_false_are_booleans() -> None:
    extra = ["a: yes", "b: no", "c: on", "d: off", "e: False", "f: y"]
    text = CSV_TEXT.replace(
        "        header: true", "        header: true\n" + "\n".join(f"        {line}" for line in extra)
    )
    config = load_pipeline_text(text).spec.nodes[0].config
    assert config == {
        "path": "*.csv",
        "header": True,
        "a": "yes",
        "b": "no",
        "c": "on",
        "d": "off",
        "e": False,
        "f": "y",
    }
    assert config["header"] is True
    assert config["e"] is False


def test_dates_stay_strings() -> None:
    text = CSV_TEXT.replace(
        "        header: true",
        "        header: true\n        on_day: 2026-09-01\n        at: 2026-09-01T10:00:00Z",
    )
    config = load_pipeline_text(text).spec.nodes[0].config
    assert config["on_day"] == "2026-09-01"
    assert config["at"] == "2026-09-01T10:00:00Z"


def test_only_plain_decimals_are_numbers() -> None:
    lines = [
        "start: 12:30",
        "underscores: 1_000",
        "octal: 0755",
        "padded: 007",
        "hex: 0x1f",
        "binary: 0b101",
        "sexagesimal: 1:30:45.5",
        "int: 42",
        "negative: -7",
        "signed: +5",
        "zero: 0",
        "float: 3.14",
        "leading_dot: .5",
        "trailing_dot: 1.",
        "exponent: 1e-3",
        "signed_exponent: 1.5E+3",
        "infinity: -.inf",
    ]
    text = CSV_TEXT.replace(
        "        header: true", "        header: true\n" + "\n".join(f"        {line}" for line in lines)
    )
    config = load_pipeline_text(text).spec.nodes[0].config
    assert {key: config[key] for key in list(config)[2:9]} == {
        "start": "12:30",
        "underscores": "1_000",
        "octal": "0755",
        "padded": "007",
        "hex": "0x1f",
        "binary": "0b101",
        "sexagesimal": "1:30:45.5",
    }
    assert {key: config[key] for key in list(config)[9:]} == {
        "int": 42,
        "negative": -7,
        "signed": 5,
        "zero": 0,
        "float": 3.14,
        "leading_dot": 0.5,
        "trailing_dot": 1.0,
        "exponent": 0.001,
        "signed_exponent": 1500.0,
        "infinity": -float("inf"),
    }
    assert type(config["int"]) is int
    assert type(config["trailing_dot"]) is float


def test_the_stock_yaml_library_is_left_as_it_was() -> None:
    # Loading a pipeline must not change how yaml.safe_load or yaml.safe_dump behave for anyone else.
    load_pipeline_file(ORDERS)
    dump_pipeline(load_pipeline_file(ORDERS))
    assert yaml.safe_load("a: yes\nb: 12:30\nc: 2026-09-01") == {
        "a": True,
        "b": 750,
        "c": datetime.date(2026, 9, 1),
    }
    assert yaml.safe_load("on: x") == {True: "x"}
    assert yaml.safe_dump("1e3") == "1e3\n...\n"
    assert yaml.safe_dump({"a": ["b"]}) == "a:\n- b\n"


# --- the round trip ------------------------------------------------------------------------------


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_round_trip_of_the_fixtures_keeps_everything(path: Path) -> None:
    loaded = load_pipeline_file(path)
    text = dump_pipeline(loaded)
    again = load_pipeline_text(text)
    assert again == loaded
    assert dump_pipeline(again) == text  # dumping is stable


def test_round_trip_keeps_config_values_and_their_types(doc: Doc) -> None:
    config = {
        "int": 1,
        "float": 1.5,
        "true": True,
        "false": False,
        "none": None,
        "list": [1, "two", [3], {"four": 4}],
        "nested": {"a": {"b": {"c": []}}},
        "empty": {},
    }
    document = doc([{"id": "read", "operator": "source.csv", "socket": "inbox", "config": config}])
    document["metadata"]["tags"] = ["a", "1.5", ""]
    p = Pipeline.model_validate(document)
    again = load_pipeline_text(dump_pipeline(p))
    assert again == p
    assert again.spec.nodes[0].config == config
    assert isinstance(again.spec.nodes[0].config["true"], bool)
    assert isinstance(again.spec.nodes[0].config["float"], float)


def test_round_trip_keeps_numbers_exactly(doc: Doc) -> None:
    numbers = [0, -1, 10**30, 0.0, 1.5, -2.25, 1e-05, 1e16, 3.141592653589793, float("inf"), -float("inf")]
    document = doc(
        [{"id": "read", "operator": "source.csv", "socket": "inbox", "config": {"numbers": numbers}}]
    )
    p = Pipeline.model_validate(document)
    again = load_pipeline_text(dump_pipeline(p))
    assert again == p
    assert [type(n) for n in again.spec.nodes[0].config["numbers"]] == [type(n) for n in numbers]


SPECIAL_STRINGS = [
    "yes",
    "No",
    "on",
    "true",
    "null",
    "~",
    "123",
    "1.5",
    "1e3",
    "0x1f",
    "007",
    "2026-09-01",
    "2026-09-01T10:00:00Z",
    "",
    " leading and trailing ",
    "a: b",
    "- not a list",
    "#not a comment",
    "quote ' and \" marks",
    "{{ params.country }}",
    "tab\tinside",
    "line one\nline two",
    "line one\nline two\n",
    "trailing space \nnext line",
    "windows\r\nline breaks",
    "unicode ü ✓ 中",
    "*.csv",
    "&anchor",
    "!tag",
    "@at",
    "%percent",
    "key: value\n  indented: more",
    "1e-3",
    "1.5E+3",
    "-.5",
    "1.",
    ".inf",
    "-.INF",
    ".nan",
    "+5",
    "-0",
    "0",
    "12:30",
    "1:30:45.5",
    "1_000",
    "0b101",
    "0o17",
    "0755",
]


@pytest.mark.parametrize("value", SPECIAL_STRINGS, ids=repr)
def test_strings_that_look_like_other_yaml_values_survive_a_round_trip(doc: Doc, value: str) -> None:
    node = {"id": "read", "operator": "source.csv", "socket": "inbox", "config": {"value": value, value: 1}}
    p = Pipeline.model_validate(doc([node]))
    again = load_pipeline_text(dump_pipeline(p))
    assert again == p
    assert again.spec.nodes[0].config["value"] == value
    assert type(again.spec.nodes[0].config["value"]) is str


# --- the dumped text -----------------------------------------------------------------------------


def test_dump_orders_keys_like_the_models() -> None:
    data = yaml.safe_load(dump_pipeline(load_pipeline_file(ORDERS)))
    assert list(data) == ["apiVersion", "kind", "metadata", "spec"]
    assert list(data["metadata"]) == ["name", "description", "tags", "owner"]
    assert list(data["spec"]) == ["sockets", "nodes"]
    nodes = {node["id"]: list(node) for node in data["spec"]["nodes"]}
    assert nodes["read_orders"] == ["id", "operator", "socket", "config"]
    assert nodes["land_orders"] == ["id", "operator", "inputs", "socket", "config"]
    assert nodes["per_country"] == ["id", "operator", "inputs", "config"]


def test_dump_writes_only_what_the_file_set(doc: Doc) -> None:
    document = doc([{"id": "read", "operator": "source.csv"}])
    del document["spec"]["sockets"]
    text = dump_pipeline(Pipeline.model_validate(document))
    for absent in ("inputs", "socket", "config", "tags", "description", "owner"):
        assert absent not in text


def test_dump_writes_a_default_when_the_file_set_it(doc: Doc) -> None:
    document = doc([{"id": "read", "operator": "source.csv", "socket": "inbox", "inputs": [], "config": {}}])
    text = dump_pipeline(Pipeline.model_validate(document))
    assert "inputs: []" in text
    assert "config: {}" in text


def test_dump_lays_out_sql_as_a_block_and_indents_lists() -> None:
    text = dump_pipeline(load_pipeline_file(ORDERS))
    assert "        sql: |\n          SELECT country,\n" in text
    assert "\n    - id: read_orders\n" in text
    assert "\n        by:\n          - column: amount\n" in text


def test_dump_does_not_fold_long_lines() -> None:
    long = "word " * 60
    p = Pipeline.model_validate(
        {
            "apiVersion": "safetwin/v1",
            "kind": "Pipeline",
            "metadata": {"name": "long", "description": long.strip()},
            "spec": {
                "nodes": [{"id": "read", "operator": "source.csv", "socket": "socket://x"}],
            },
        }
    )
    assert f"  description: {long.strip()}\n" in dump_pipeline(p)


def test_dumped_text_reads_the_same_in_a_plain_yaml_1_1_loader() -> None:
    # Words like `on` are quoted in the output, so tools with the old YAML rules still see strings.
    text = CSV_TEXT.replace(
        "        header: true", "        header: true\n        flags: {on: yes, off: 'no'}"
    )
    p = load_pipeline_text(text)
    assert yaml.safe_load(dump_pipeline(p)) == p.model_dump(exclude_unset=True)
    p = load_pipeline_file(ORDERS)
    assert yaml.safe_load(dump_pipeline(p)) == p.model_dump(exclude_unset=True)


# --- SpecError: broken YAML ----------------------------------------------------------------------


def test_bad_yaml_reports_the_line_and_column() -> None:
    (problem,) = problems_of("metadata: name: x\n")
    assert problem.severity == "error"
    assert problem.code == "yaml_error"
    assert problem.node_id is None
    assert problem.message.startswith("line 1, column 15: ")
    assert "mapping values are not allowed" in problem.message


def test_bad_yaml_deeper_in_the_file_points_at_the_right_line() -> None:
    broken = CSV_TEXT.replace(
        "    outbox: socket://local-outbox\n", "    outbox: socket://local-outbox\n   bad: indent\n"
    )
    (problem,) = problems_of(broken)
    assert problem.code == "yaml_error"
    assert problem.message.startswith(f"line {line_of(broken, '   bad: indent')}, column ")


def test_an_unclosed_bracket_is_a_yaml_error() -> None:
    (problem,) = problems_of("spec: {nodes: []\nmetadata: x\n")
    assert problem.code == "yaml_error"
    assert problem.message.startswith("line ")


def test_more_than_one_document_is_a_yaml_error() -> None:
    (problem,) = problems_of(CSV_TEXT + "---\n" + CSV_TEXT)
    assert problem.code == "yaml_error"
    assert problem.message.endswith("expected a single document in the stream, but found another document")


def test_the_spec_error_carries_the_problems_and_says_them_in_its_text() -> None:
    with pytest.raises(SpecError) as caught:
        load_pipeline_text("metadata: name: x\n")
    error = caught.value
    assert error.problems == [Problem("error", "yaml_error", error.problems[0].message)]
    assert str(error) == f"[yaml_error] {error.problems[0].message}"


@pytest.mark.parametrize("text", ["", "# only a comment\n", "just a string\n", "- a\n- list\n", "42\n"])
def test_a_file_that_is_not_a_mapping_is_reported_at_the_top_level(text: str) -> None:
    (problem,) = problems_of(text if "\n" in text else text + "\n")
    assert problem.message.startswith("(top level): ")


BILLION_LAUGHS = (
    "a: &a [x, x, x, x, x, x, x, x, x]\n"
    "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
    "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
    "d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
)
ALIASES = {
    "recursive": "a: &a [*a]\n",
    "recursive mapping": "config: &c {self: *c}\n",
    "billion laughs": BILLION_LAUGHS,
    "merge key": "base: &base {a: 1}\nother:\n  <<: *base\n",
    "inside a pipeline": CSV_TEXT.replace(
        "        header: true", "        header: true\n        cols: &cols [id]"
    ).replace("        columns: [name, city]", "        columns: *cols"),
}


@pytest.mark.parametrize("text", ALIASES.values(), ids=ALIASES.keys())
def test_yaml_aliases_are_refused_so_they_cannot_loop_or_blow_up(text: str) -> None:
    (problem,) = problems_of(text)
    assert problem.code == "yaml_error"
    assert problem.message.startswith("line ")
    assert "aliases (*name) are not allowed" in problem.message


def test_an_anchor_that_nothing_refers_to_is_harmless() -> None:
    text = CSV_TEXT.replace("        header: true", "        header: &h true")
    assert load_pipeline_text(text).spec.nodes[0].config["header"] is True


def with_extra(body: str) -> str:
    """The csv-clean pipeline with `extra: <body>` (a flow mapping on one line) in its source's config."""
    return CSV_TEXT.replace("        header: true", f"        header: true\n        extra: {body}")


def extra_of(text: str) -> Any:
    return load_pipeline_text(text).spec.nodes[0].config["extra"]


def line_of(text: str, wanted: str) -> int:
    """The number (counting from 1) of the first line of `text` that is exactly `wanted`."""
    return text.splitlines().index(wanted) + 1


def test_a_key_used_twice_is_a_yaml_error_that_names_both_lines() -> None:
    text = CSV_TEXT.replace("  sockets:", "  nodes: []\n  sockets:", 1)
    (problem,) = problems_of(text)
    first, second = line_of(text, "  nodes: []"), line_of(text, "  nodes:")
    assert problem == Problem(
        "error",
        "yaml_error",
        f"line {second}, column 3: found duplicate key 'nodes' (first used on line {first})",
    )


def test_a_key_repeated_inside_a_node_is_found_where_it_is() -> None:
    text = CSV_TEXT.replace("      socket: inbox\n", "      socket: inbox\n      socket: outbox\n")
    (problem,) = problems_of(text)
    assert problem.code == "yaml_error"
    assert problem.message.startswith(f"line {line_of(text, '      socket: outbox')}, column 7: ")
    assert "found duplicate key 'socket' (first used on line " in problem.message


DUPLICATES = {
    "top level": ("a: 1\nb: 2\na: 3\n", "line 3, column 1: found duplicate key 'a' (first used on line 1)"),
    "nested": ("x:\n  y: 1\n  y: 2\n", "line 3, column 3: found duplicate key 'y' (first used on line 2)"),
    "in a list item": (
        "- a: 1\n  a: 2\n",
        "line 2, column 3: found duplicate key 'a' (first used on line 1)",
    ),
    "far apart": (
        "a: 1\n\n# note\n\na: 2\n",
        "line 5, column 1: found duplicate key 'a' (first used on line 1)",
    ),
    "flow mapping": ("{a: 1, a: 2}\n", "line 1, column 8: found duplicate key 'a' (first used on line 1)"),
    "json": ('{"a": 1, "a": 2}\n', "line 1, column 10: found duplicate key 'a' (first used on line 1)"),
    "quoted and plain": (
        "a: 1\n'a': 2\n",
        "line 2, column 1: found duplicate key 'a' (first used on line 1)",
    ),
    "an int and a float": (
        "{1: a, 1.0: b}\n",
        "line 1, column 8: found duplicate key '1.0' (first used on line 1)",
    ),
    "inside an inline merge": (
        "{<<: {a: 1, a: 2}}\n",
        "line 1, column 13: found duplicate key 'a' (first used on line 1)",
    ),
}


@pytest.mark.parametrize(("text", "message"), DUPLICATES.values(), ids=DUPLICATES.keys())
def test_duplicate_keys_are_found_however_the_mapping_is_written(text: str, message: str) -> None:
    assert problems_of(text) == [Problem("error", "yaml_error", message)]


def test_keys_that_only_look_alike_or_live_in_different_mappings_are_not_duplicates() -> None:
    body = "{nodes: {read_csv: {x: 1}, trim_text: {x: 2}}, other: {'1': a, 1: b, '': c, null: d}}"
    assert extra_of(with_extra(body)) == {
        "nodes": {"read_csv": {"x": 1}, "trim_text": {"x": 2}},
        "other": {"1": "a", 1: "b", "": "c", None: "d"},
    }


def test_merge_keys_and_the_equals_key_are_not_duplicates_of_anything() -> None:
    # `<<` and `=` are not values: they are taken out before a mapping is built, so they have no constructor.
    # An explicit key beats a merged one by design.
    assert extra_of(with_extra("{nodes: {<<: {a: 1, b: 1}, a: 2}}")) == {"nodes": {"a": 2, "b": 1}}
    assert extra_of(with_extra("{nodes: {=: 1, b: 2}}")) == {"nodes": {"=": 1, "b": 2}}


def test_a_secret_looking_key_is_not_repeated_in_a_duplicate_key_error() -> None:
    (problem,) = problems_of(with_extra(f"{{nodes: {{{SECRET}: 1, {SECRET}: 2}}}}"))
    assert problem.code == "yaml_error"
    assert "found duplicate key '<redacted>' (first used on line " in problem.message
    assert SECRET not in problem.message


NESTED = {
    "flow sequences": "[" * 600 + "]" * 600 + "\n",
    "flow mappings": '{"a": ' * 600 + "1" + "}" * 600 + "\n",
    "block mappings": "".join("  " * depth + "a:\n" for depth in range(600)),
}


@pytest.mark.parametrize("text", NESTED.values(), ids=NESTED.keys())
def test_yaml_nested_hundreds_of_levels_deep_is_a_spec_error_not_a_traceback(text: str) -> None:
    (problem,) = problems_of(text)
    assert problem == Problem("error", "too_deep", "the file is nested too deeply")


def test_a_config_that_is_deep_but_loadable_still_loads() -> None:
    nested = "{a: " * 100 + "1" + "}" * 100
    text = CSV_TEXT.replace("        header: true", f"        header: true\n        deep: {nested}")
    assert load_pipeline_text(text).spec.nodes[0].config["deep"] is not None


# --- SpecError: a file that doesn't match the spec -----------------------------------------------


def test_a_missing_field_is_reported_with_its_location() -> None:
    (problem,) = problems_of(CSV_TEXT.replace("kind: Pipeline\n", ""))
    assert problem == Problem("error", "missing", "kind: Field required")


def test_a_wrong_value_is_reported_with_its_location() -> None:
    (problem,) = problems_of(CSV_TEXT.replace("apiVersion: safetwin/v1", "apiVersion: safetwin/v2"))
    assert problem.code == "literal_error"
    assert problem.message == "apiVersion: Input should be 'safetwin/v1'"


def test_locations_name_nodes_by_id_and_mention_typos() -> None:
    text = CSV_TEXT.replace("operator: transform.trim\n", "operator: transform.trim\n      sockett: inbox\n")
    (problem,) = problems_of(text)
    assert problem.code == "extra_forbidden"
    assert problem.message == "spec.nodes[trim_text].sockett: Extra inputs are not permitted"


def test_an_invalid_node_id_is_located_by_that_id() -> None:
    (problem,) = problems_of(CSV_TEXT.replace("- id: trim_text", "- id: Trim-Text"))
    assert problem.code == "string_pattern_mismatch"
    assert problem.message.startswith("spec.nodes[Trim-Text].id: String should match pattern")


def test_a_node_without_an_id_is_located_by_its_position() -> None:
    (problem,) = problems_of(CSV_TEXT.replace("    - id: trim_text\n      operator", "    - operator"))
    assert problem == Problem("error", "missing", "spec.nodes[2].id: Field required")


def test_a_socket_that_is_not_a_socket_uri_is_located_by_its_alias() -> None:
    (problem,) = problems_of(CSV_TEXT.replace("socket://local-inbox", "s3://bucket"))
    assert problem.message.startswith("spec.sockets.inbox: String should match pattern")


def test_every_problem_is_reported_at_once_and_none_shows_the_input() -> None:
    text = (
        CSV_TEXT.replace("kind: Pipeline", "kind: Pipelines")
        .replace("name: csv-clean", "name: hunter2-Secret")
        .replace("- id: read_csv", "- id: read_csv\n      nope: 1")
    )
    problems = problems_of(text)
    assert [p.code for p in problems] == ["literal_error", "string_pattern_mismatch", "extra_forbidden"]
    assert [p.message.split(":")[0] for p in problems] == [
        "kind",
        "metadata.name",
        "spec.nodes[read_csv].nope",
    ]
    assert all("hunter2" not in p.message for p in problems)  # the offending value is never echoed


def test_a_bad_file_on_disk_is_reported_the_same_way(tmp_path: Path) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text(CSV_TEXT.replace("kind: Pipeline", "kind: Pipelines"), encoding="utf-8")
    with pytest.raises(SpecError) as caught:
        load_pipeline_file(broken)
    assert [p.code for p in caught.value.problems] == ["literal_error"]


SECRET = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def test_a_secret_looking_key_is_not_repeated_in_a_location() -> None:
    text = CSV_TEXT.replace("operator: transform.trim\n", f"operator: transform.trim\n      {SECRET}: 1\n")
    (problem,) = problems_of(text)
    assert problem.code == "extra_forbidden"
    assert problem.message == "spec.nodes[trim_text].<redacted>: Extra inputs are not permitted"


def test_a_secret_looking_node_id_is_not_repeated_in_a_location() -> None:
    (problem,) = problems_of(CSV_TEXT.replace("- id: trim_text", f"- id: {SECRET}"))
    assert problem.code == "string_pattern_mismatch"
    assert problem.message.startswith("spec.nodes[<redacted>].id: String should match pattern")


def test_a_secret_looking_socket_alias_is_not_repeated_in_a_location() -> None:
    (problem,) = problems_of(
        CSV_TEXT.replace("    inbox:  socket://local-inbox", f"    {SECRET}: s3://bucket")
    )
    assert problem.message.startswith("spec.sockets.<redacted>: String should match pattern")


def test_a_value_that_pydantic_quotes_is_never_repeated() -> None:
    # No field of the format has a discriminated union any more, but its errors are the kind that quote the
    # input ("Input tag 'x' found using 'type' ..."): `_message` still replaces the tag and the input.
    error: Any = {
        "type": "union_tag_invalid",
        "loc": ("spec",),
        "msg": f"Input tag '{SECRET}' found using 'type' does not match any of the expected tags: 'a', 'b'",
        "input": {"type": SECRET},
        "ctx": {"discriminator": "'type'", "tag": SECRET, "expected_tags": "'a', 'b'"},
    }
    message = io_module._message(error)
    assert message.startswith("Input tag '<redacted>' found using 'type'")
    assert SECRET not in message


def test_a_secret_in_a_yaml_error_is_not_repeated() -> None:
    (problem,) = problems_of(f"a: !{SECRET} value\n")
    assert problem.code == "yaml_error"
    assert problem.message.endswith("could not determine a constructor for the tag '<redacted>'")
    assert SECRET not in problem.message


def test_a_name_that_is_not_a_secret_is_left_alone() -> None:
    (problem,) = problems_of(CSV_TEXT.replace("- id: trim_text", "- id: Trim-Text"))
    assert problem.message.startswith("spec.nodes[Trim-Text].id: ")


# --- the JSON Schema and its drift check ---------------------------------------------------------


@pytest.fixture
def schema_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Points the schema tool at a scratch file, so tests never touch the committed one."""
    path = tmp_path / "schemas" / "safetwin.pipeline.v1.schema.json"
    path.parent.mkdir()
    monkeypatch.setattr(schema_module, "SCHEMA_PATH", path)
    return path


def test_the_schema_identifies_itself_and_the_root_shape() -> None:
    schema = schema_module.pipeline_json_schema()
    assert schema["$id"] == "urn:safetwin:schemas:pipeline:v1"
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"apiVersion", "kind", "metadata", "spec"}
    assert list(schema["properties"]) == ["apiVersion", "kind", "metadata", "spec"]
    assert schema["properties"]["apiVersion"]["const"] == "safetwin/v1"


def test_the_schema_describes_operator_ids_and_node_ids() -> None:
    defs = schema_module.pipeline_json_schema()["$defs"]
    assert set(defs) == {"Metadata", "Node", "Spec"}
    assert list(defs["Spec"]["properties"]) == ["sockets", "nodes"]
    assert list(defs["Node"]["properties"]) == ["id", "operator", "inputs", "socket", "config"]
    assert defs["Node"]["properties"]["operator"]["pattern"] == r"^[a-z0-9_]+(\.[a-z0-9_]+)+(@[0-9]+)?$"
    assert defs["Node"]["properties"]["id"]["pattern"] == "^[a-z][a-z0-9_]*$"


def test_the_committed_schema_is_up_to_date(capsys: pytest.CaptureFixture[str]) -> None:
    """The drift test: `python -m safetwin.spec.schema --check` on the real committed file."""
    assert schema_module.main(["--check"]) == 0
    assert "up to date" in capsys.readouterr().out
    committed = (REPO / "schemas" / "safetwin.pipeline.v1.schema.json").read_text(encoding="utf-8")
    assert committed == schema_module.render_schema()
    assert json.loads(committed) == schema_module.pipeline_json_schema()


def test_check_passes_after_writing(schema_file: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert schema_module.main([]) == 0
    assert schema_file.read_text(encoding="utf-8") == schema_module.render_schema()
    assert schema_module.main(["--check"]) == 0
    assert "up to date" in capsys.readouterr().out


def test_check_fails_when_the_committed_schema_has_drifted(
    schema_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    schema_module.main([])
    stale = json.loads(schema_file.read_text(encoding="utf-8"))
    del stale["$defs"]["Node"]["properties"]["socket"]  # as if a field was added to the models since
    schema_file.write_text(json.dumps(stale, indent=2) + "\n", encoding="utf-8")
    assert schema_module.main(["--check"]) == 1
    assert "out of date" in capsys.readouterr().err
    assert json.loads(schema_file.read_text(encoding="utf-8")) == stale  # --check never writes


def test_check_fails_when_there_is_no_committed_schema(
    schema_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert not schema_file.exists()
    assert schema_module.main(["--check"]) == 1
    assert "out of date" in capsys.readouterr().err
    assert not schema_file.exists()


def test_writing_repairs_a_drifted_schema(schema_file: Path) -> None:
    schema_file.write_text("{}\n", encoding="utf-8")
    assert schema_module.main(["--check"]) == 1
    assert schema_module.main([]) == 0
    assert schema_module.main(["--check"]) == 0


def test_the_tool_stops_when_the_schemas_folder_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        schema_module, "SCHEMA_PATH", tmp_path / "missing" / "safetwin.pipeline.v1.schema.json"
    )
    assert schema_module.main([]) == 2
    assert "source checkout" in capsys.readouterr().err
    assert not (tmp_path / "missing").exists()


def test_the_module_runs_as_a_script_from_any_folder_without_warnings(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-W", "error", "-m", "safetwin.spec.schema", "--check"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert "up to date" in result.stdout


# Fields whose values are names that messages show on purpose: node ids and the references to them, and the
# socket a node uses. Everything else is a value, and no message may repeat it.
NAME_FIELDS = frozenset({"id", "inputs", "socket"})
SWEEP_CANARY = "CANARY-7a1b2c3d"


def _value_paths(value: Any, path: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    found: list[tuple[Any, ...]] = [path] if path else []
    if isinstance(value, dict):
        for key, item in value.items():
            found += _value_paths(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found += _value_paths(item, (*path, index))
    return found


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda path: path.name)
def test_no_message_repeats_a_value_of_the_file(example: Path) -> None:
    """Every value of the fixture, in turn, is replaced by the canary (as text, in a list, in a mapping,
    quoted, and as a tag that tries to break out of its quotes): no problem, from the schema or from the
    validator, may repeat it."""
    from safetwin.spec import validate_pipeline

    base = yaml.safe_load(example.read_text(encoding="utf-8"))
    replacements = [
        SWEEP_CANARY,
        [SWEEP_CANARY],
        {"k": SWEEP_CANARY},
        f"'{SWEEP_CANARY}'",
        f"a' found using '{SWEEP_CANARY}",
    ]
    codes: set[str] = set()
    for path in _value_paths(base):
        if path[-1] in NAME_FIELDS or (len(path) > 1 and path[-2] in NAME_FIELDS):
            continue
        for replacement in replacements:
            changed = json.loads(json.dumps(base))
            target = changed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = replacement
            try:
                problems = validate_pipeline(load_pipeline_text(json.dumps(changed)))
            except SpecError as err:
                problems = err.problems
            for problem in problems:
                codes.add(problem.code)
                assert SWEEP_CANARY not in problem.message, (path, problem)
    # the sweep reached the pydantic errors that could quote their input
    assert {"literal_error", "string_pattern_mismatch", "string_type", "dict_type"} <= codes
    if example.name == "orders-report.yaml":
        assert {"list_type", "model_type"} <= codes


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("a: !ZQXCANARY v\n", "line 1, column 4: could not determine a constructor for the tag '<redacted>'"),
        (
            "a: !<zqxcanary> v\n",
            "line 1, column 4: could not determine a constructor for the tag '<redacted>'",
        ),
        (
            "a: &ZQXCANARY 1\nb: &ZQXCANARY 2\n",
            "line 2, column 4: found duplicate anchor '<redacted>'; first occurrence, second occurrence",
        ),
        # one character, or PyYAML's own name for a token, is a hint about the syntax: kept
        (
            "a:\n\tb: 1\n",
            "line 2, column 1: while scanning for the next token, found character '\\t' that cannot start "
            "any token",
        ),
        (
            "a: [1",
            "line 1, column 6: while parsing a flow sequence, expected ',' or ']', but got '<stream end>'",
        ),
        (
            'a: "x\\q"\n',
            "line 1, column 7: while scanning a double-quoted scalar, found unknown escape character 'q'",
        ),
    ],
    ids=["tag", "verbatim-tag", "anchor", "tab", "token", "escape"],
)
def test_a_yaml_error_repeats_no_tag_or_anchor_name(text: str, message: str) -> None:
    (problem,) = problems_of(text)
    assert problem == Problem("error", "yaml_error", message)
    assert "ZQXCANARY" not in problem.message.upper()
