"""Every validation rule, with a case that fails and a case that passes."""

import base64
import copy
import random
import re
import string
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from safetwin.spec import (
    BUILTIN,
    Catalog,
    OperatorSpec,
    Pipeline,
    Problem,
    load_pipeline_file,
    validate_pipeline,
)

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = sorted((REPO / "tests" / "fixtures").glob("*.yaml"))

Make = Callable[..., Pipeline]
Doc = Callable[..., dict[str, Any]]


def codes(problems: list[Problem]) -> list[str]:
    return [problem.code for problem in problems]


def only(problems: list[Problem], code: str) -> Problem:
    """The one problem with this code; fails when there is none or several."""
    found = [problem for problem in problems if problem.code == code]
    assert len(found) == 1, f"expected one {code}, got {codes(problems)}"
    return found[0]


# --- the baseline and the fixtures ---------------------------------------------------------------


def test_a_valid_pipeline_has_no_problems(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.trim("clean", "read"), nodes.sink("write", "clean")])
    assert validate_pipeline(p) == []


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_the_fixtures_validate_with_no_problems(path: Path) -> None:
    assert validate_pipeline(load_pipeline_file(path)) == []


def test_the_fixture_is_there() -> None:
    assert {path.name for path in EXAMPLES} >= {"csv-clean.yaml"}


def test_problems_are_errors_with_the_node_they_are_about(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.step("clean", "transform.nope", "read")])
    (problem,) = validate_pipeline(p)
    assert problem == Problem("error", "unknown_operator", problem.message, "clean")


# --- duplicate_id, unknown_operator --------------------------------------------------------------


def test_duplicate_id_fails(make: Make, nodes: Any) -> None:
    p = make(
        [nodes.source(), nodes.trim("clean", "read"), nodes.trim("clean", "read"), nodes.sink("w", "clean")]
    )
    problem = only(validate_pipeline(p), "duplicate_id")
    assert problem.node_id == "clean"
    assert "2 times" in problem.message


def test_unique_ids_pass(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.trim("clean", "read"), nodes.trim("clean_more", "clean")])
    assert "duplicate_id" not in codes(validate_pipeline(p))


def test_unknown_operator_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.step("clean", "transform.nope", "read")])
    problems = validate_pipeline(p)
    assert codes(problems) == ["unknown_operator"]
    assert problems[0].node_id == "clean"
    assert "transform.nope" in problems[0].message


def test_known_operators_pass_including_pinned_versions(make: Make, nodes: Any) -> None:
    p = make([nodes.source(operator="source.csv@1"), nodes.step("q", "transform.sql@1", "read")])
    assert validate_pipeline(p) == []


@pytest.mark.parametrize("operator", ["source.json", "transform.aggregate", "sink.files", "notify.desktop"])
def test_operators_the_data_plane_does_not_run_are_unknown(make: Make, nodes: Any, operator: str) -> None:
    p = make([nodes.source(), nodes.step("other", operator, "read")])
    assert codes(validate_pipeline(p)) == ["unknown_operator"]


# --- unknown_reference, self_reference -----------------------------------------------------------

# An operator with two output ports, for the rules about named ports (no built-in one has two).
SPLIT = OperatorSpec("transform.split", "transform", {"in": "records"}, {"out": "records", "rest": "records"})
# An operator with no output port at all.
NOWHERE = OperatorSpec("transform.nowhere", "transform", {"in": "records"})
WITH_PORTS = Catalog([*BUILTIN.values(), SPLIT, NOWHERE])


def test_unknown_reference_in_inputs_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.trim("clean", "read", "ghost")])
    problem = only(validate_pipeline(p), "unknown_reference")
    assert problem.node_id == "clean"
    assert "ghost" in problem.message


def test_a_missing_output_port_fails(make: Make, nodes: Any) -> None:
    split = nodes.step("split", "transform.split", "read")
    p = make([nodes.source(), split, nodes.sink("write", "split.bogus")])
    problem = only(validate_pipeline(p, WITH_PORTS), "unknown_reference")
    assert problem.node_id == "write"
    assert "bogus" in problem.message
    assert "out, rest" in problem.message


def test_a_missing_output_port_of_a_built_in_operator_fails(make: Make, nodes: Any) -> None:
    problem = only(
        validate_pipeline(make([nodes.source(), nodes.sink("write", "read.rest")])), "unknown_reference"
    )
    assert "(output ports: out)" in problem.message


def test_reading_a_step_that_has_no_output_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.step("end", "transform.nowhere", "read"), nodes.trim("t", "end")])
    problem = only(validate_pipeline(p, WITH_PORTS), "unknown_reference")
    assert "none" in problem.message


def test_references_to_nodes_and_named_ports_pass(make: Make, nodes: Any) -> None:
    split = nodes.step("split", "transform.split", "read")
    p = make([nodes.source(), split, nodes.sink("good", "split"), nodes.sink("rest", "split.rest")])
    assert validate_pipeline(p, WITH_PORTS) == []


def test_self_reference_in_inputs_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.trim("clean", "read", "clean")])
    problems = validate_pipeline(p)
    assert codes(problems) == ["self_reference"]  # not reported a second time as a cycle
    assert problems[0].node_id == "clean"


# --- cycle ---------------------------------------------------------------------------------------


def test_cycle_through_data_edges_fails_and_names_the_path(make: Make, nodes: Any) -> None:
    p = make([nodes.trim("a", "b"), nodes.trim("b", "a")])
    problems = validate_pipeline(p)
    assert codes(problems) == ["cycle"]
    assert "a → b → a" in problems[0].message
    assert problems[0].node_id == "a"


def test_a_cycle_reachable_from_outside_names_only_the_loop(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.trim("a", "read", "c"), nodes.trim("b", "a"), nodes.trim("c", "b")])
    problem = only(validate_pipeline(p), "cycle")
    assert "read" not in problem.message
    assert re.search(r"a → b → c → a|b → c → a → b|c → a → b → c", problem.message)


def test_a_dag_has_no_cycle(make: Make, nodes: Any) -> None:
    diamond = [
        nodes.source(),
        nodes.trim("left", "read"),
        nodes.trim("right", "read"),
        nodes.trim("join", "left", "right"),
        nodes.sink("write", "join"),
    ]
    assert validate_pipeline(make(diamond)) == []


def test_a_very_long_chain_is_not_a_problem_for_cycle_detection(make: Make, nodes: Any) -> None:
    chain = [nodes.source("n0")] + [nodes.trim(f"n{i}", f"n{i - 1}") for i in range(1, 3000)]
    assert validate_pipeline(make(chain)) == []


# --- missing_input, source_has_inputs ------------------------------------------------------------


def test_missing_input_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.trim("clean"), nodes.sink("write")])
    problems = validate_pipeline(p)
    assert codes(problems) == ["missing_input", "missing_input"]
    assert {problem.node_id for problem in problems} == {"clean", "write"}


def test_sources_need_no_data_input(make: Make, nodes: Any) -> None:
    assert validate_pipeline(make([nodes.source()])) == []


def test_source_with_inputs_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.source("read_more", inputs=["read"])])
    problem = only(validate_pipeline(p), "source_has_inputs")
    assert problem.node_id == "read_more"


# --- missing_socket, unknown_socket_alias --------------------------------------------------------


def test_source_and_sink_without_a_socket_fail(make: Make, nodes: Any) -> None:
    read = {"id": "read", "operator": "source.csv"}
    write = {"id": "write", "operator": "sink.parquet", "inputs": ["read"]}
    problems = validate_pipeline(make([read, write]))
    assert codes(problems) == ["missing_socket", "missing_socket"]
    assert {problem.node_id for problem in problems} == {"read", "write"}


def test_an_alias_and_a_socket_uri_pass(make: Make, nodes: Any) -> None:
    p = make([nodes.source(socket="inbox"), nodes.sink("write", "read", socket="socket://staging-copy")])
    assert validate_pipeline(p) == []


def test_an_alias_that_is_not_defined_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(socket="nowhere"), nodes.sink("write", "read")])
    problem = only(validate_pipeline(p), "unknown_socket_alias")
    assert problem.node_id == "read"
    assert "nowhere" in problem.message
    assert "inbox" in problem.message


def test_a_malformed_socket_uri_fails(make: Make, nodes: Any) -> None:
    p = make([nodes.source(socket="socket://"), nodes.sink("write", "read")])
    assert codes(validate_pipeline(p)) == ["unknown_socket_alias"]


def test_no_aliases_defined_says_so(make: Make, nodes: Any) -> None:
    p = make([nodes.source(socket="inbox")], sockets={})
    assert "none defined" in only(validate_pipeline(p), "unknown_socket_alias").message


def test_steps_that_need_no_socket_may_leave_it_out(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.trim("clean", "read"), nodes.step("q", "transform.sql", "clean")])
    assert validate_pipeline(p) == []


# --- inline_secret -----------------------------------------------------------------------

GITHUB_BODY = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
KNOWN_SECRETS = [
    pytest.param("an AWS access key ID", "AKIAIOSFODNN7EXAMPLE", id="aws-access-key"),
    pytest.param("an AWS access key ID", "ASIAIOSFODNN7EXAMPLE", id="aws-temporary-key"),
    pytest.param("a GitHub token", "ghp_" + GITHUB_BODY, id="github-personal"),
    pytest.param("a GitHub token", "gho_" + GITHUB_BODY, id="github-oauth"),
    pytest.param(
        "a GitHub token", "github_pat_11ABCDEFG0abcdefghijkl_mnopqrstuvwxyz0123", id="github-fine-grained"
    ),
    pytest.param(
        "a Slack token", "xox" + "b-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", id="slack"
    ),
    pytest.param("an API key (sk-...)", "sk-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z", id="sk-key"),
    pytest.param("a Google API key", "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q", id="google-api-key"),
    pytest.param("a Google OAuth token", "ya29.a0AfH6SMBx3kLm9Zp2QrStUvWxYz", id="google-oauth"),
    pytest.param(
        "a private key",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIB\n-----END RSA PRIVATE KEY-----",
        id="pem-rsa",
    ),
    pytest.param(
        "a private key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIB\n-----END PRIVATE KEY-----", id="pem-bare"
    ),
    pytest.param(
        "a private key",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----",
        id="pem-openssh",
    ),
]

# Random 40-character base64 tokens, made once with a fixed seed so the test data never changes.
_rng = random.Random(20260930)
RANDOM_TOKENS = [base64.b64encode(_rng.randbytes(30)).decode() for _ in range(25)]
RANDOM_TOKENS += [base64.urlsafe_b64encode(_rng.randbytes(32)).decode().rstrip("=") for _ in range(10)]
RANDOM_TOKENS += ["".join(_rng.choices(string.ascii_letters + string.digits, k=32)) for _ in range(10)]
RANDOM_TOKENS += [_rng.randbytes(n).hex() for n in (16, 16, 20, 20, 32, 32)]  # 32, 40 and 64 hex characters
RANDOM_TOKENS += [_rng.randbytes(n).hex().upper() for n in (16, 20, 32)]
SEEDED_EXAMPLES = [
    "gsSCZvxS//DfgUS5aDkAF5+soI53ChbA1Vy8XyRN",
    "sLm2s4qsBHMiJ8a9SKP187j4zskcZ6E4ODre4dQz",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # the example secret access key from the AWS docs
]

LONG_SQL = """SELECT date_trunc('hour', placed_at) AS hour,
       country,
       count(*)                        AS orders,
       sum(amount_net + amount_tax)    AS amount
FROM input
GROUP BY 1, 2
ORDER BY amount DESC"""

NOT_SECRETS = [
    "secret://keys/shop-pseudonyms",
    "keychain://safetwin/shop-key",
    "socket://local-inbox",
    "secret://" + RANDOM_TOKENS[0],  # a reference is fine however random the name looks
    LONG_SQL,
    "SELECT customer_id, sum(amount) FROM sales WHERE country = 'IN' GROUP BY customer_id ORDER BY 2 DESC",
    "The quick brown fox jumps over the lazy dog and keeps on running for miles",
    "hunter2",
    "SafeTwin/shop/orders/dt={yyyy}-{MM}-{dd}/hr={HH}/",
    "SafeTwin/shop/orders/dt=2026-09-01/hr=13/",
    "/Users/me/projects/safetwin/examples/",
    "s3://my-analytics-bucket/SafeTwin/shop/orders/",
    "https://storage.googleapis.com/bucket-name/path/to/file.csv",
    "postgresql://analytics_ro@db-prod-01.internal:5432/warehouse",
    "customer_lifetime_value_estimate_usd_2026q3",
    "risk-assessment-for-customer-orders-2026",
    "ghp_summary",
    "AKIA_not_a_key",
]


def config_of(make: Make, nodes: Any, config: dict[str, Any]) -> Pipeline:
    return make([nodes.source(config=config)])


@pytest.mark.parametrize(("kind", "secret"), KNOWN_SECRETS)
def test_secrets_with_a_known_shape_fail(make: Make, nodes: Any, kind: str, secret: str) -> None:
    problem = only(validate_pipeline(config_of(make, nodes, {"token": secret})), "inline_secret")
    assert kind in problem.message
    assert secret not in problem.message  # never repeat the secret itself


def test_an_aws_key_fails_and_the_message_points_at_it(make: Make, nodes: Any) -> None:
    p = make([nodes.source("reader", config={"token": "AKIAIOSFODNN7EXAMPLE"})])
    problem = only(validate_pipeline(p), "inline_secret")
    assert problem.severity == "error"
    assert problem.node_id == "reader"
    assert "spec.nodes[reader].config.token" in problem.message
    assert "secret://" in problem.message


@pytest.mark.parametrize("token", RANDOM_TOKENS + SEEDED_EXAMPLES)
def test_a_random_looking_token_fails(make: Make, nodes: Any, token: str) -> None:
    problem = only(validate_pipeline(config_of(make, nodes, {"api_key": token})), "inline_secret")
    assert "random-looking" in problem.message
    assert token not in problem.message


@pytest.mark.parametrize("value", NOT_SECRETS)
def test_references_prose_sql_and_paths_pass(make: Make, nodes: Any, value: str) -> None:
    assert validate_pipeline(config_of(make, nodes, {"value": value})) == []


def test_secret_references_pass(make: Make, nodes: Any) -> None:
    config = {"key": "secret://keys/shop-pseudonyms", "password": "keychain://safetwin/db"}
    assert validate_pipeline(config_of(make, nodes, config)) == []


def test_a_long_sql_string_with_spaces_passes(make: Make, nodes: Any) -> None:
    p = make([nodes.source(), nodes.step("q", "transform.sql", "read", config={"sql": LONG_SQL})])
    assert validate_pipeline(p) == []


def test_random_short_values_and_numbers_pass(make: Make, nodes: Any) -> None:
    assert (
        validate_pipeline(config_of(make, nodes, {"n": 123456789012345678901234567890123, "s": "aB3dE6gH"}))
        == []
    )


def test_nested_strings_are_found_with_their_path(make: Make, nodes: Any) -> None:
    config = {"headers": {"auth": ["ok", "AKIAIOSFODNN7EXAMPLE"]}}
    problem = only(validate_pipeline(config_of(make, nodes, config)), "inline_secret")
    assert "spec.nodes[read].config.headers.auth[1]" in problem.message


def test_every_secret_is_reported_once(make: Make, nodes: Any) -> None:
    config = {"a": "AKIAIOSFODNN7EXAMPLE", "b": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8", "c": "fine"}
    problems = validate_pipeline(config_of(make, nodes, config))
    assert codes(problems) == ["inline_secret", "inline_secret"]


def test_secrets_outside_the_nodes_are_found_too(doc: Doc) -> None:
    key = "AKIAIOSFODNN7EXAMPLE"
    read = {"id": "read", "operator": "source.csv", "socket": "inbox"}
    document = doc([read])
    document["metadata"]["description"] = f"uses {key}"
    document["metadata"]["tags"] = ["fine", key]
    problems = validate_pipeline(Pipeline.model_validate(document))
    assert sorted(problem.message.split()[0] for problem in problems) == [
        "metadata.description",
        "metadata.tags[1]",
    ]
    assert {problem.node_id for problem in problems} == {None}


# --- robustness ----------------------------------------------------------------------------------


def test_a_config_nested_thousands_of_levels_deep_is_reported_not_a_crash(make: Make, nodes: Any) -> None:
    config: dict[str, Any] = {}
    for _ in range(5000):
        config = {"k": config}
    problems = validate_pipeline(make([nodes.source(config=config)]))
    assert "too_deep" in codes(problems)
    assert all(problem.severity == "error" for problem in problems)


# --- property: backward edges never make a cycle, one closing edge always does -------------------


def build(nodes: list[dict[str, Any]]) -> Pipeline:
    return Pipeline.model_validate(
        {
            "apiVersion": "safetwin/v1",
            "kind": "Pipeline",
            "metadata": {"name": "dag"},
            "spec": {
                "sockets": {"inbox": "socket://local-inbox"},
                "nodes": nodes,
            },
        }
    )


@st.composite
def dags(draw: st.DrawFn) -> list[dict[str, Any]]:
    """Nodes n0..nK declared in any order, where every node depends only on lower-numbered ones.

    Each node reads its predecessor (so n0 is upstream of everything after it) and, at random, some
    earlier nodes too.
    """
    size = draw(st.integers(min_value=3, max_value=10))
    nodes: list[dict[str, Any]] = [{"id": "n0", "operator": "source.csv", "socket": "inbox"}]
    for i in range(1, size):
        node: dict[str, Any] = {"id": f"n{i}", "operator": "transform.trim", "inputs": [f"n{i - 1}"]}
        for j in range(i - 1):  # n0 .. n(i-2); n(i-1) is the data input already
            if draw(st.sampled_from([False, False, True])):
                node["inputs"].append(f"n{j}")
        nodes.append(node)
    return draw(st.permutations(nodes))


@settings(max_examples=200, deadline=None)
@given(nodes=dags())
def test_backward_edges_never_form_a_cycle(nodes: list[dict[str, Any]]) -> None:
    problems = validate_pipeline(build(nodes))
    assert "cycle" not in codes(problems)
    assert problems == []  # the generated pipelines are valid in every other way too


@st.composite
def cyclic_graphs(draw: st.DrawFn) -> list[dict[str, Any]]:
    """A `dags()` graph plus one closing edge: a lower-numbered node now depends on a higher-numbered one.

    The chain guarantees n_low is upstream of n_high, so the new edge makes a loop (when n_low is n0, a
    source, the edge is an error of its own too: `source_has_inputs`).
    """
    nodes = copy.deepcopy(draw(dags()))
    last = len(nodes) - 1
    low = draw(st.integers(min_value=0, max_value=last - 1))
    high = draw(st.integers(min_value=low + 1, max_value=last))
    node = next(n for n in nodes if n["id"] == f"n{low}")
    node.setdefault("inputs", []).append(f"n{high}")
    return nodes


@settings(max_examples=200, deadline=None)
@given(nodes=cyclic_graphs())
def test_one_closing_edge_always_forms_a_cycle(nodes: list[dict[str, Any]]) -> None:
    assert "cycle" in codes(validate_pipeline(build(nodes)))
