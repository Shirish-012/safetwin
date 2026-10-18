"""The committed JSON Schema against the models: editors and tools use one and the engine the other."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError

from safetwin.spec import Pipeline, load_pipeline_file

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = sorted((REPO / "tests" / "fixtures").glob("*.yaml"))
SCHEMA = json.loads((REPO / "schemas" / "safetwin.pipeline.v1.schema.json").read_text(encoding="utf-8"))
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)

Doc = Callable[..., dict[str, Any]]


def schema_errors(document: dict[str, Any]) -> list[jsonschema.ValidationError]:
    return sorted(VALIDATOR.iter_errors(document), key=lambda error: list(error.absolute_path))


def models_accept(document: dict[str, Any]) -> bool:
    try:
        Pipeline.model_validate(document)
    except ValidationError:
        return False
    return True


def test_the_committed_schema_is_a_valid_json_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda path: path.name)
def test_the_fixtures_validate_against_the_committed_schema(path: Path) -> None:
    # The file is read by the engine's own loader first: plain YAML 1.1 would turn a key such as `on:` into
    # `True`. What is checked is the document the loader made of the file, as plain JSON.
    document = json.loads(load_pipeline_file(path).model_dump_json(exclude_unset=True))
    assert [error.message for error in schema_errors(document)] == []


def test_the_schema_rejects_a_broken_fixture() -> None:
    # A control for the test above: the validator is not letting everything through.
    document = json.loads(load_pipeline_file(EXAMPLES[0]).model_dump_json(exclude_unset=True))
    del document["spec"]["nodes"]
    assert [error.message for error in schema_errors(document)] == ["'nodes' is a required property"]


# Documents that the models and the schema must both accept, or both refuse.
DOCUMENTS = {
    "a node with every field": ({"inputs": [], "socket": "inbox", "config": {"a": [1, {"b": None}]}}, True),
    "an unknown node field": ({"window": {"type": "tumbling", "size": "1m"}}, False),
    "a socket that is not text": ({"socket": 1}, False),
    "inputs that are not a list": ({"inputs": "read"}, False),
    "a config that is not a mapping": ({"config": [1]}, False),
}


@pytest.mark.parametrize(("fields", "valid"), DOCUMENTS.values(), ids=DOCUMENTS.keys())
def test_the_schema_and_the_models_agree(doc: Doc, nodes: Any, fields: dict[str, Any], valid: bool) -> None:
    document = doc([nodes.source(), {"id": "clean", "operator": "transform.trim", **fields}])
    assert models_accept(document) is valid
    errors = schema_errors(document)
    assert (errors == []) is valid, [error.message for error in errors]


@pytest.mark.parametrize("field", ["mode", "trigger", "spill", "delivery"])
def test_the_schema_refuses_the_removed_spec_fields(doc: Doc, nodes: Any, field: str) -> None:
    document = doc([nodes.source()], **{field: "x"})
    assert not models_accept(document)
    assert [error.validator for error in schema_errors(document)] == ["additionalProperties"]
