"""The built-in operator catalog: the operators the data plane runs, and the facts validation needs.

Ports, and whether a step needs a socket. Config schemas live with the operators themselves
(`dataplane/operators.py`).
"""

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Literal

Category = Literal["source", "transform", "sink"]
PortType = Literal["records"]


@dataclass(frozen=True)
class OperatorSpec:
    """One operator: its ports and the properties the validator cares about."""

    id: str
    category: Category
    inputs: dict[str, PortType] = field(default_factory=dict)
    outputs: dict[str, PortType] = field(default_factory=dict)
    needs_socket: bool = False


class Catalog(Mapping[str, OperatorSpec]):
    """Operators by id. A pinned version (``transform.sql@1``) finds the unpinned operator."""

    def __init__(self, operators: Iterable[OperatorSpec]) -> None:
        self._operators = {op.id: op for op in operators}

    def __getitem__(self, operator: str) -> OperatorSpec:
        return self._operators[operator.partition("@")[0]]

    def __iter__(self) -> Iterator[str]:
        return iter(self._operators)

    def __len__(self) -> int:
        return len(self._operators)


def _source(op_id: str) -> OperatorSpec:
    return OperatorSpec(op_id, "source", outputs={"out": "records"}, needs_socket=True)


def _transform(op_id: str) -> OperatorSpec:
    return OperatorSpec(op_id, "transform", {"in": "records"}, {"out": "records"})


def _sink(op_id: str) -> OperatorSpec:
    # A sink's `out` is what it committed, so a later step can read it back (a new stage starts there).
    return OperatorSpec(op_id, "sink", {"in": "records"}, {"out": "records"}, needs_socket=True)


BUILTIN = Catalog(
    [
        _source("source.csv"),
        _source("source.parquet"),
        _transform("transform.select"),
        _transform("transform.filter"),
        _transform("transform.derive"),
        _transform("transform.trim"),
        _transform("transform.parse_dates"),
        _transform("transform.cast"),
        _transform("transform.sort"),
        _transform("transform.sql"),
        _transform("transform.mask"),
        _sink("sink.parquet"),
        _sink("sink.csv"),
    ]
)
