"""Stages that fail or give up halfway, run in a process of their own: `python exit_scenarios.py NAME FOLDER`.

`test_hybrid_exit.py` starts this and sees whether the process ends. It must: the thread pool of Arrow waits
for work that is not finished when the process ends, and a DuckDB query that was dropped while it was running
leaves such work behind (see `hybrid.py`). Every scenario ends by printing one line, and then the process
ends as any process does, by leaving `main`.
"""

import sys
from pathlib import Path

from safetwin.dataplane import batch
from safetwin.dataplane.run import run_pipeline_local
from safetwin.dataplane.spill import OutOfMemory
from safetwin.spec import Pipeline

MEMORY = 400_000_000


class Boom(Exception):
    """The disk is full, or something else that goes wrong in the writer."""


def pipeline(*nodes: dict[str, object], **spec: object) -> Pipeline:
    return Pipeline.model_validate(
        {
            "apiVersion": "safetwin/v1",
            "kind": "Pipeline",
            "metadata": {"name": "exit"},
            "spec": {
                "sockets": {"inbox": "socket://inbox", "outbox": "socket://outbox"},
                "nodes": list(nodes),
                **spec,
            },
        }
    )


READ = {"id": "read", "operator": "source.csv", "socket": "inbox", "config": {"path": "*.csv"}}


def step(node_id: str, operator: str, source: str, **config: object) -> dict[str, object]:
    return {"id": node_id, "operator": operator, "inputs": [source], "config": config}


def write(source: str) -> dict[str, object]:
    return {
        "id": "write",
        "operator": "sink.parquet",
        "inputs": [source],
        "socket": "outbox",
        "config": {"path": "out/"},
    }


def fail_the_writer_at(calls: int) -> None:
    """Make the third row group (or so) fail to be written."""
    real, seen = batch.RowGroups.add, [0]

    def add(self: batch.RowGroups, table: object) -> None:
        seen[0] += 1
        if seen[0] == calls:
            raise Boom("the disk is full")
        real(self, table)  # type: ignore[arg-type]

    batch.RowGroups.add = add  # type: ignore[method-assign]


FILTER = "SELECT id, name, amount FROM input WHERE name <> 'nothing'"


def scenario(name: str) -> Pipeline:
    if name in ("writer_fails", "success"):
        return pipeline(READ, step("q", "transform.sql", "read", sql=FILTER), write("q"))
    if name == "limit":
        return pipeline(
            READ, step("q", "transform.sql", "read", sql="SELECT * FROM input LIMIT 10"), write("q")
        )
    if name == "step_after_fails":
        return pipeline(
            READ,
            step("q", "transform.sql", "read", sql="SELECT * FROM input"),
            step("boom", "transform.derive", "q", name="n", expr="CAST(name AS INT)"),
            write("boom"),
        )
    if name == "step_before_fails":
        return pipeline(
            READ,
            step("boom", "transform.derive", "read", name="n", expr="CAST(name AS INT)"),
            step("q", "transform.sql", "boom", sql="SELECT * FROM input"),
            write("q"),
        )
    if name == "two_steps_writer_fails":
        return pipeline(
            READ,
            step("one", "transform.sql", "read", sql=FILTER),
            step("two", "transform.sql", "one", sql="SELECT * FROM input WHERE id <> '0'"),
            write("two"),
        )
    if name == "polars_between_fails":
        return pipeline(
            READ,
            step("one", "transform.sql", "read", sql=FILTER),
            step("trim", "transform.trim", "one", columns=["name"]),
            step("two", "transform.sql", "trim", sql="SELECT * FROM input"),
            write("two"),
        )
    if name == "out_of_memory":
        return pipeline(
            READ,
            step("ordered", "transform.sort", "read", by=[{"column": "name", "descending": True}]),
            write("ordered"),
        )
    raise SystemExit(f"unknown scenario {name!r}")


def main(name: str, folder: str) -> None:
    root = Path(folder)
    if name in ("writer_fails", "two_steps_writer_fails", "polars_between_fails"):
        fail_the_writer_at(3)
    limit = 10_000_000 if name == "out_of_memory" else MEMORY
    try:
        result = run_pipeline_local(
            scenario(name),
            {"inbox": root / "in", "outbox": root / "out"},
            memory_limit_bytes=limit,
        )
    except Boom:
        print("failed in the writer", flush=True)
    except OutOfMemory:
        print("out of memory", flush=True)
    except Exception as err:  # the class is what the command line shows
        print(f"failed with {type(err).__name__}", flush=True)
    else:
        print(f"rows {result.stages[0].rows_per_node['write']}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
