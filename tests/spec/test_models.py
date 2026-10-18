from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from safetwin.spec import Pipeline

Doc = Callable[..., dict[str, Any]]
CSV = {"id": "read", "operator": "source.csv", "socket": "inbox"}


def errors(document: dict[str, Any]) -> list[tuple[tuple[int | str, ...], str]]:
    """The (location, error type) pairs Pydantic reports for `document`."""
    with pytest.raises(ValidationError) as caught:
        Pipeline.model_validate(document)
    return [(e["loc"], e["type"]) for e in caught.value.errors()]


def test_minimal_pipeline_loads_with_defaults(doc: Doc) -> None:
    p = Pipeline.model_validate(doc([CSV]))
    node = p.spec.nodes[0]
    assert (node.inputs, node.config) == ([], {})
    assert (p.metadata.tags, p.metadata.description, p.metadata.owner) == ([], None, None)


@pytest.mark.parametrize("name", ["a", "0abc", "my-pipeline-2", "shop-to-staging"])
def test_valid_pipeline_names(doc: Doc, name: str) -> None:
    document = doc([CSV])
    document["metadata"]["name"] = name
    assert Pipeline.model_validate(document).metadata.name == name


@pytest.mark.parametrize("name", ["", "-x", "My-Pipeline", "a_b", "a b", "a.b", "a\n"])
def test_invalid_pipeline_names(doc: Doc, name: str) -> None:
    document = doc([CSV])
    document["metadata"]["name"] = name
    assert errors(document) == [(("metadata", "name"), "string_pattern_mismatch")]


@pytest.mark.parametrize("node_id", ["read_orders", "a1_b", "x"])
def test_valid_node_ids(doc: Doc, node_id: str) -> None:
    assert Pipeline.model_validate(doc([{**CSV, "id": node_id}])).spec.nodes[0].id == node_id


@pytest.mark.parametrize("node_id", ["", "1a", "A", "a-b", "_a", "a.b", "a b"])
def test_invalid_node_ids(doc: Doc, node_id: str) -> None:
    assert errors(doc([{**CSV, "id": node_id}])) == [(("spec", "nodes", 0, "id"), "string_pattern_mismatch")]


@pytest.mark.parametrize(
    "operator", ["source.csv", "transform.sql@1", "transform.parse_dates", "a.b.c", "a.b@12", "x_1.y_2"]
)
def test_valid_operator_ids(doc: Doc, operator: str) -> None:
    assert Pipeline.model_validate(doc([{**CSV, "operator": operator}])).spec.nodes[0].operator == operator


@pytest.mark.parametrize(
    "operator", ["csv", "transform.", ".sql", "Transform.sql", "transform.sql@", "transform.sql@x", "a.b@1.2"]
)
def test_invalid_operator_ids(doc: Doc, operator: str) -> None:
    assert errors(doc([{**CSV, "operator": operator}])) == [
        (("spec", "nodes", 0, "operator"), "string_pattern_mismatch")
    ]


def test_unknown_keys_are_errors_at_every_level(doc: Doc) -> None:
    document = doc([{**CSV, "typo": 1}])
    document["extra"] = 1
    document["metadata"]["extra"] = 1
    document["spec"]["extra"] = 1
    assert sorted(errors(document), key=str) == sorted(
        [
            (("extra",), "extra_forbidden"),
            (("metadata", "extra"), "extra_forbidden"),
            (("spec", "extra"), "extra_forbidden"),
            (("spec", "nodes", 0, "typo"), "extra_forbidden"),
        ],
        key=str,
    )


def test_the_api_version_of_the_earlier_scope_is_refused(doc: Doc) -> None:
    document = doc([CSV])
    document["apiVersion"] = "datatransform/v1"
    assert errors(document) == [(("apiVersion",), "literal_error")]


def test_api_version_and_kind_are_fixed(doc: Doc) -> None:
    document = doc([CSV])
    document["apiVersion"] = "safetwin/v2"
    document["kind"] = "Socket"
    assert sorted(errors(document)) == [(("apiVersion",), "literal_error"), (("kind",), "literal_error")]


# Fields of the earlier scope that the format no longer has: each is an unknown key now.
REMOVED_SPEC_FIELDS = {
    "mode": "batch",
    "trigger": {"type": "manual"},
    "delivery": "at_least_once",
    "spill": "none",
    "on_sink_offline": "pause_source",
    "defaults": {"timeout": "1h"},
    "params": {},
    "pattern": "etl",
}
REMOVED_NODE_FIELDS = {
    "after": ["read"],
    "trigger_rule": "all_success",
    "window": {"type": "tumbling", "size": "1m"},
    "retries": {"count": 1, "backoff": "fixed", "initial": "1s", "max": "1s"},
    "timeout": "5m",
    "pool": "default",
}


@pytest.mark.parametrize("field", REMOVED_SPEC_FIELDS)
def test_removed_spec_fields_are_unknown_keys(doc: Doc, field: str) -> None:
    assert errors(doc([CSV], **{field: REMOVED_SPEC_FIELDS[field]})) == [(("spec", field), "extra_forbidden")]


@pytest.mark.parametrize("field", REMOVED_NODE_FIELDS)
def test_removed_node_fields_are_unknown_keys(doc: Doc, field: str) -> None:
    node = {**CSV, field: REMOVED_NODE_FIELDS[field]}
    assert errors(doc([node])) == [(("spec", "nodes", 0, field), "extra_forbidden")]


def test_the_ui_section_is_an_unknown_key(doc: Doc) -> None:
    document = doc([CSV])
    document["ui"] = {"nodes": {"read": {"x": 1, "y": 2}}}
    assert errors(document) == [(("ui",), "extra_forbidden")]


@pytest.mark.parametrize("uri", ["socket://local-inbox", "socket://staging-copy", "socket://a/b"])
def test_socket_values_that_are_uris(doc: Doc, uri: str) -> None:
    assert Pipeline.model_validate(doc([CSV], sockets={"a": uri})).spec.sockets == {"a": uri}


@pytest.mark.parametrize("uri", ["s3://bucket", "socket://", "socket://a b", "local-inbox", "SOCKET://x"])
def test_socket_values_must_be_socket_uris(doc: Doc, uri: str) -> None:
    assert errors(doc([CSV], sockets={"a": uri})) == [(("spec", "sockets", "a"), "string_pattern_mismatch")]


def test_nodes_may_not_be_empty(doc: Doc) -> None:
    assert errors(doc([])) == [(("spec", "nodes"), "too_short")]
