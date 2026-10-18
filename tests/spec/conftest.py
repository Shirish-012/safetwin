"""Fixtures shared by the spec tests: a pipeline factory and small node builders."""

from collections.abc import Callable
from typing import Any

import pytest

from safetwin.spec import Pipeline

Node = dict[str, Any]


def base_doc(nodes: list[Node], **spec: Any) -> dict[str, Any]:
    """A pipeline document (as YAML would load it) around `nodes`; keyword arguments set other spec fields."""
    return {
        "apiVersion": "safetwin/v1",
        "kind": "Pipeline",
        "metadata": {"name": "test"},
        "spec": {
            "sockets": {"inbox": "socket://local-inbox", "outbox": "socket://local-outbox"},
            "nodes": nodes,
            **spec,
        },
    }


class Nodes:
    """Builders for node documents. The defaults are valid: a CSV source and Parquet sink with sockets."""

    @staticmethod
    def source(node_id: str = "read", **fields: Any) -> Node:
        return {"id": node_id, "operator": "source.csv", "socket": "inbox", **fields}

    @staticmethod
    def step(node_id: str, operator: str, *inputs: str, **fields: Any) -> Node:
        return {"id": node_id, "operator": operator, "inputs": list(inputs), **fields}

    @staticmethod
    def trim(node_id: str, *inputs: str, **fields: Any) -> Node:
        return Nodes.step(node_id, "transform.trim", *inputs, **fields)

    @staticmethod
    def sink(node_id: str, *inputs: str, **fields: Any) -> Node:
        return Nodes.step(node_id, "sink.parquet", *inputs, **{"socket": "outbox", **fields})


@pytest.fixture
def doc() -> Callable[..., dict[str, Any]]:
    """Builds a pipeline document; tests change it before validating to provoke one specific error."""
    return base_doc


@pytest.fixture
def make() -> Callable[..., Pipeline]:
    """Builds a `Pipeline` from a list of node documents (see `base_doc`)."""

    def build(nodes: list[Node], **spec: Any) -> Pipeline:
        return Pipeline.model_validate(base_doc(nodes, **spec))

    return build


@pytest.fixture
def nodes() -> type[Nodes]:
    return Nodes
