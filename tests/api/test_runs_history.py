"""`GET /v1/runs` and `GET /v1/runs/{run_id}` over the history in the metadata database, at the ASGI level.

The runs are written into the store directly (no stage worker runs): the routes, their strict query, the
cursor, the filters, what an answer holds, and that a 422 never repeats what was sent. And a pipeline with an
inline secret is refused before anything reaches the database.
"""

import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, select

from safetwin.api.app import create_app
from safetwin.api.server import new_token
from safetwin.executor.executor import Executor
from safetwin.executor.history import DbRunStore, metadata_path
from safetwin.executor.settings import ExecutorSettings
from safetwin.executor.store import FileRecord, RunRecord, StageRecord, Totals
from safetwin.metadata import open_metadata_db, session_factory
from safetwin.metadata.models import Pipeline, PipelineVersion, Run

with warnings.catch_warnings():  # Starlette 1.7 would like httpx2; httpx is what the project allows
    warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")
    from starlette.testclient import TestClient

REPO = Path(__file__).resolve().parents[2]
PORT = 48124
TOKEN = new_token()
AUTH = {"Authorization": f"Bearer {TOKEN}"}
CANARY = "CANARY-9d3f1a-never-echoed"
YAML = (REPO / "tests" / "fixtures" / "csv-clean.yaml").read_text()


@pytest.fixture
def store(safetwin_home: Path, migrated_db: Callable[[Path], Path]) -> Iterator[DbRunStore]:
    made = DbRunStore.open(migrated_db(metadata_path(safetwin_home)))
    try:
        yield made
    finally:
        made.close()


@pytest.fixture
def client(safetwin_home: Path, store: DbRunStore) -> Iterator[TestClient]:
    executor = Executor(safetwin_home, ExecutorSettings(memory_limit_bytes=1_000_000), store=store)
    guard = create_app(TOKEN, PORT, (), executor=executor)
    with TestClient(guard, base_url=f"http://127.0.0.1:{PORT}") as made:
        yield made
    executor.shutdown()


def add_run(store: DbRunStore, run_id: str, *, pipeline: str = "csv-clean", ended: str | None = None) -> None:
    run = RunRecord(run_id=run_id, pipeline=pipeline, created_at="2026-10-02T09:00:00.000Z")
    store.add(run, YAML)
    if ended is not None:
        store.save(run.model_copy(update={"state": ended, "finished_at": "2026-10-02T09:00:01.000Z"}))


def succeeded_run(store: DbRunStore, run_id: str) -> None:
    run = RunRecord(run_id=run_id, pipeline="csv-clean", created_at="2026-10-02T09:00:00.000Z")
    store.add(run, YAML)
    stage = StageRecord(
        index=0,
        node_ids=["read_csv", "keep", "write_parquet"],
        operators=["source.csv", "transform.filter", "sink.parquet"],
        path="fused",
    )
    run = run.model_copy(
        update={"state": "running", "started_at": "2026-10-02T09:00:00.500Z", "stages": [stage]}
    )
    store.save(run)
    running = stage.model_copy(update={"state": "running", "started_at": "2026-10-02T09:00:00.600Z"})
    store.save(run.model_copy(update={"stages": [running]}))
    done = running.model_copy(
        update={
            "state": "succeeded",
            "finished_at": "2026-10-02T09:00:01.000Z",
            "duration_s": 0.4,
            "rows_per_node": {"read_csv": 3, "keep": 2, "write_parquet": 2},
            "bytes_written": 99,
            "files": [FileRecord(path="/out/part.parquet", bytes=99, sha256="f" * 64)],
            "exit_reason": "exit_0",
        }
    )
    run = run.model_copy(update={"stages": [done], "totals": Totals(rows=2, bytes=99, files=1)})
    store.save(run)
    store.save(run.model_copy(update={"state": "succeeded", "finished_at": "2026-10-02T09:00:01.100Z"}))


def problems(response: Any) -> list[dict[str, Any]]:
    assert response.status_code == 422
    body = response.json()
    assert set(body) == {"error", "problems"}
    assert body["error"] == "invalid_request"
    assert all(set(problem) == {"loc", "type"} for problem in body["problems"])
    return list(body["problems"])


def test_runs_are_listed_newest_first_twenty_at_a_time_with_a_cursor(
    client: TestClient, store: DbRunStore
) -> None:
    for number in range(25):
        add_run(store, f"r{number:02d}")
    page = client.get("/v1/runs", headers=AUTH).json()
    assert [run["run_id"] for run in page["runs"]] == [f"r{n:02d}" for n in range(24, 4, -1)]
    assert page["next_before"] == "r05"
    rest = client.get("/v1/runs", params={"before": page["next_before"]}, headers=AUTH).json()
    assert [run["run_id"] for run in rest["runs"]] == ["r04", "r03", "r02", "r01", "r00"]
    assert rest["next_before"] is None
    assert len(client.get("/v1/runs", params={"limit": 100}, headers=AUTH).json()["runs"]) == 25
    assert len(client.get("/v1/runs", params={"limit": 1}, headers=AUTH).json()["runs"]) == 1


def test_runs_can_be_filtered_by_pipeline_and_state(client: TestClient, store: DbRunStore) -> None:
    add_run(store, "ra", pipeline="one", ended="cancelled")
    add_run(store, "rb", pipeline="two")
    add_run(store, "rc", pipeline="one")
    listed = client.get("/v1/runs", params={"pipeline": "one"}, headers=AUTH).json()["runs"]
    assert [run["run_id"] for run in listed] == ["rc", "ra"]
    listed = client.get("/v1/runs", params={"state": "queued"}, headers=AUTH).json()["runs"]
    assert [run["run_id"] for run in listed] == ["rc", "rb"]
    listed = client.get("/v1/runs", params={"pipeline": "one", "state": "cancelled"}, headers=AUTH).json()[
        "runs"
    ]
    assert [run["run_id"] for run in listed] == ["ra"]
    assert client.get("/v1/runs", params={"state": "interrupted"}, headers=AUTH).json()["runs"] == []


def test_a_run_shows_its_stages_rows_bytes_files_and_checksums(client: TestClient, store: DbRunStore) -> None:
    succeeded_run(store, "rdone")
    (summary,) = client.get("/v1/runs", headers=AUTH).json()["runs"]
    assert summary["totals"] == {"rows": 2, "bytes": 99, "files": 1}
    record = client.get("/v1/runs/rdone", headers=AUTH).json()
    assert record["state"] == "succeeded"
    (stage,) = record["stages"]
    assert stage["rows_per_node"] == {"read_csv": 3, "keep": 2, "write_parquet": 2}
    assert stage["bytes_written"] == 99
    assert stage["files"] == [{"path": "/out/part.parquet", "bytes": 99, "sha256": "f" * 64}]
    assert stage["exit_reason"] == "exit_0"
    assert record["totals"] == {"rows": 2, "bytes": 99, "files": 1}


def test_a_query_that_does_not_fit_is_refused_and_not_repeated(client: TestClient, store: DbRunStore) -> None:
    add_run(store, "r1")
    cases: list[tuple[dict[str, Any] | str, list[dict[str, Any]]]] = [
        ({"limit": 0}, [{"loc": ["query", "limit"], "type": "greater_than_equal"}]),
        ({"limit": 101}, [{"loc": ["query", "limit"], "type": "less_than_equal"}]),
        ({"limit": CANARY}, [{"loc": ["query", "limit"], "type": "int_parsing"}]),
        ({"before": f"{CANARY}!"}, [{"loc": ["query", "before"], "type": "string_pattern_mismatch"}]),
        ({"before": CANARY}, [{"loc": ["query", "before"], "type": "unknown_run"}]),
        ({"pipeline": CANARY}, [{"loc": ["query", "pipeline"], "type": "string_pattern_mismatch"}]),
        ({"pipeline": "a" * 300}, [{"loc": ["query", "pipeline"], "type": "string_too_long"}]),
        ({"state": CANARY}, [{"loc": ["query", "state"], "type": "literal_error"}]),
        ({CANARY: "1"}, [{"loc": ["query"], "type": "unknown_parameter"}]),
        ("limit=1&limit=2", [{"loc": ["query", "limit"], "type": "repeated"}]),
    ]
    for params, expected in cases:
        if isinstance(params, str):
            response = client.get(f"/v1/runs?{params}", headers=AUTH)
        else:
            response = client.get("/v1/runs", params=params, headers=AUTH)
        assert problems(response) == expected, params
        assert CANARY not in response.text
        assert "a" * 300 not in response.text


def test_the_routes_still_need_the_token_and_say_nothing_of_an_unknown_run(
    client: TestClient, store: DbRunStore
) -> None:
    add_run(store, "r1")
    assert client.get("/v1/runs").status_code == 401
    assert client.get("/v1/runs/r1").status_code == 401
    assert (
        client.get("/v1/runs", params={"limit": 5}, headers={"Authorization": "Bearer nope"}).status_code
        == 401
    )
    for unknown in (CANARY, f"{CANARY}.x", "r" * 200):
        response = client.get(f"/v1/runs/{unknown}", headers=AUTH)
        assert (response.status_code, response.json()) == (404, {"error": "run_not_found"})


def test_a_pipeline_with_an_inline_secret_never_reaches_the_database(
    client: TestClient, store: DbRunStore, tmp_path: Path
) -> None:
    token = "ghp_8sK2mQ9xZ4vL7pR1tY6wN3bC5dF0gH2jK4lM"
    leaky = YAML.replace('expr: "id IS NOT NULL"', f"expr: \"token = '{token}'\"")
    assert leaky != YAML
    response = client.post(
        "/v1/runs",
        json={"pipeline_yaml": leaky, "sockets": {"inbox": str(tmp_path), "outbox": str(tmp_path)}},
        headers=AUTH,
    )
    assert response.status_code == 422
    assert "inline_secret" in {problem["code"] for problem in response.json()["problems"]}
    assert token not in response.text
    engine = open_metadata_db(store.path)
    try:
        with session_factory(engine)() as session:
            for model in (Pipeline, PipelineVersion, Run):
                assert session.scalar(select(func.count()).select_from(model)) == 0
    finally:
        engine.dispose()
    raw = b"".join(path.read_bytes() for path in store.path.parent.glob("metadata.db*"))
    assert token.encode() not in raw
