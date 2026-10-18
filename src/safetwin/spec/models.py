"""The pipeline format v1 as Pydantic models: the internal format that masking policies compile to.

A pipeline is a batch job that runs when it is started: a small DAG of steps (source → steps → sink) with the
folders it reads and writes named by socket (docs/internals.md). The JSON Schema is generated from these
models (see ``schema.py``).
"""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

SOCKET_URI_PATTERN = r"^socket://\S+$"

PipelineName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]*$")]
NodeId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
OperatorId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)+(@[0-9]+)?$")]
SocketUri = Annotated[str, StringConstraints(pattern=SOCKET_URI_PATTERN)]


class _Model(BaseModel):
    """Base of the structural models: keys the format doesn't know are errors."""

    model_config = ConfigDict(extra="forbid")


class Metadata(_Model):
    """Name and description of the pipeline."""

    name: PipelineName
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    owner: str | None = None


class Node(_Model):
    """One step of the pipeline."""

    id: NodeId
    operator: OperatorId
    inputs: list[str] = Field(default_factory=list)  # data edges: `node` or `node.port`
    socket: str | None = None  # an alias from spec.sockets, or a socket:// URI
    config: dict[str, Any] = Field(default_factory=dict)


class Spec(_Model):
    """What the pipeline does: the sockets it names and its steps."""

    sockets: dict[str, SocketUri] = Field(default_factory=dict)
    nodes: Annotated[list[Node], Field(min_length=1)]


class Pipeline(_Model):
    """A pipeline file."""

    apiVersion: Literal["safetwin/v1"]
    kind: Literal["Pipeline"]
    metadata: Metadata
    spec: Spec
