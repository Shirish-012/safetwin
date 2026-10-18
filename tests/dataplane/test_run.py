"""run_pipeline_local: validation first, every stage planned before the first runs, and what stays in."""

import logging
import re
from pathlib import Path
from typing import Any

import pytest

from safetwin.dataplane.manifest import Manifest
from safetwin.dataplane.operators import ConfigError
from safetwin.dataplane.run import PipelineInvalid, RunResult, run_pipeline_local
from safetwin.spec import load_pipeline_file

REPO = Path(__file__).resolve().parents[2]
PATHS = ["fused", "batch"]


def go(pipeline: Any, sockets: Any, **kwargs: Any) -> RunResult:
    return run_pipeline_local(pipeline, sockets.folders, **kwargs)  # type: ignore[no-any-return]


# --- the pipeline is validated first ------------------------------------------------------------------------


def test_a_pipeline_with_errors_is_refused_and_nothing_is_written(
    nodes: Any, data: Any, sockets: Any
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("drop", "transform.nope", "read"),
        nodes.write("write", "drop"),
    )
    with pytest.raises(PipelineInvalid) as refused:
        go(p, sockets)
    assert [problem.code for problem in refused.value.problems] == ["unknown_operator"]
    assert "[unknown_operator]" in str(refused.value)
    assert list(sockets.outbox.iterdir()) == []


def test_a_secret_in_the_config_is_refused_before_anything_runs(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("drop", "transform.filter", "read", expr="id IS NOT NULL", token="AKIAIOSFODNN7EXAMPLE"),
        nodes.write("write", "drop"),
    )
    with pytest.raises(PipelineInvalid, match="inline_secret") as refused:
        go(p, sockets)
    assert "AKIAIOSFODNN7EXAMPLE" not in str(refused.value)
    assert list(sockets.outbox.iterdir()) == []


def test_a_pipeline_that_is_not_a_chain_is_not_run(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    p = nodes.pipeline(
        nodes.read(), nodes.write("one", "read", path="one/"), nodes.write("two", "read", path="two/")
    )
    with pytest.raises(NotImplementedError, match="fan-out"):
        go(p, sockets)
    assert list(sockets.outbox.iterdir()) == []


@pytest.mark.parametrize(
    ("operator", "where"),
    [
        ("transform.aggregate", "step"),
        ("transform.dedupe", "step"),
        ("source.json", "source"),
        ("sink.files", "sink"),
    ],
)
def test_an_operator_that_the_data_plane_does_not_run_is_refused_before_anything_is_written(
    nodes: Any, data: Any, sockets: Any, operator: str, where: str
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    if where == "step":
        p = nodes.pipeline(nodes.read(), nodes.step("x", operator, "read"), nodes.write("write", "x"))
    elif where == "source":
        p = nodes.pipeline({**nodes.read(), "operator": operator}, nodes.write("write", "read"))
    else:
        p = nodes.pipeline(nodes.read(), {**nodes.write("write", "read"), "operator": operator})
    with pytest.raises(PipelineInvalid, match="unknown_operator") as refused:
        go(p, sockets)
    assert operator in str(refused.value)
    assert list(sockets.outbox.iterdir()) == []


# --- the id of the run --------------------------------------------------------------------------------------


def test_a_run_gets_an_id_unless_one_is_given(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    first, second = go(nodes.copy(), sockets), go(nodes.copy(), sockets)
    assert re.fullmatch(r"r[0-9a-f]{8}", first.run_id)
    assert first.run_id != second.run_id
    assert go(nodes.copy(), sockets, run_id="r-2026_09").run_id == "r-2026_09"
    assert {name.split("/")[1] for name in sockets.written() if name.endswith(".parquet")} == {
        f"part-00000-{first.run_id}.parquet",
        f"part-00000-{second.run_id}.parquet",
        "part-00000-r-2026_09.parquet",
    }


@pytest.mark.parametrize("run_id", ["", "../x", "a/b", ".hidden", "-x", "a b", "a" * 65, "é"])
def test_a_run_id_that_is_not_safe_in_a_file_name_is_refused(
    nodes: Any, data: Any, sockets: Any, run_id: str
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    with pytest.raises(ConfigError, match="the run id must be"):
        go(nodes.copy(), sockets, run_id=run_id)
    assert list(sockets.outbox.iterdir()) == []


# --- planned before it starts -------------------------------------------------------------------------------


def test_a_mistake_in_a_later_stage_is_found_before_the_first_stage_writes(
    nodes: Any, data: Any, sockets: Any
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("raw", "read", path="raw/"),
        nodes.step("drop", "transform.filter", "raw", expr="id IS NOT NULL"),
        nodes.write("clean", "drop", path="clean/{hour}/"),
    )
    with pytest.raises(ConfigError, match=r"clean \(sink\.parquet\): unknown placeholder \{hour\}"):
        go(p, sockets)
    assert list(sockets.outbox.iterdir()) == []  # the first stage has not run, and no folder was made


def test_a_wrong_config_in_a_later_stage_is_found_first_too(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    p = nodes.pipeline(
        nodes.read(),
        nodes.write("raw", "read", path="raw/"),
        nodes.step("tidy", "transform.trim", "raw", columns=[]),
        nodes.write("clean", "tidy", path="clean/"),
    )
    with pytest.raises(
        ConfigError, match=r"tidy \(transform\.trim\): columns: List should have at least 1 item"
    ):
        go(p, sockets)
    assert list(sockets.outbox.iterdir()) == []


def test_no_files_to_read_is_an_error_before_anything_is_written(nodes: Any, sockets: Any) -> None:
    with pytest.raises(ConfigError, match=r"read \(source\.csv\): no file matches '\*\.csv'"):
        go(nodes.copy(), sockets)
    assert list(sockets.outbox.iterdir()) == []


def test_a_socket_without_a_folder_is_an_error_that_says_which(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    with pytest.raises(ConfigError, match=r"socket 'outbox' has no folder \(folders were given for: inbox\)"):
        run_pipeline_local(nodes.copy(), {"inbox": sockets.inbox})


def test_a_folder_that_is_not_there_is_not_made(nodes: Any, data: Any, sockets: Any, tmp_path: Path) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    with pytest.raises(ConfigError, match="socket 'outbox' is not a folder"):
        run_pipeline_local(nodes.copy(), {"inbox": sockets.inbox, "outbox": tmp_path / "NOT_MOUNTED"})
    assert not (tmp_path / "NOT_MOUNTED").exists()


def test_the_sockets_can_be_named_by_alias_or_by_uri(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    by_uri = {"socket://local-inbox": sockets.inbox, "socket://local-outbox": sockets.outbox}
    assert run_pipeline_local(nodes.copy(), by_uri).stages[0].rows_per_node["read"] == 10
    mixed = {"inbox": sockets.inbox, "socket://local-outbox": sockets.outbox}
    assert run_pipeline_local(nodes.copy(), mixed).stages[0].rows_per_node["read"] == 10


def test_a_node_may_name_its_socket_by_uri(nodes: Any, data: Any, sockets: Any) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(10))
    source = {**nodes.read(), "socket": "socket://local-inbox"}
    p = nodes.pipeline(source, nodes.write("write", "read"))
    assert go(p, sockets).stages[0].rows_per_node["write"] == 10  # the folder was given for the alias `inbox`


# --- a pipeline can't reach outside its sockets -------------------------------------------------------------


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """A folder next to the sockets: a file in it must not be read, and nothing may be written in it."""
    folder = tmp_path / "outside"
    folder.mkdir()
    (folder / "secret.csv").write_text("id,name\n1,TOPSECRETVALUE\n")
    return folder


READ_ESCAPES = [
    "../outside/secret.csv",
    "/etc/hosts",
    "sub/../../outside/*.csv",
    "escape_dir/*.csv",
    "escape_file.csv",
]


@pytest.mark.parametrize("path", READ_ESCAPES)
def test_a_source_cannot_read_outside_its_socket(
    nodes: Any, data: Any, sockets: Any, outside: Path, path: str
) -> None:
    (sockets.inbox / "sub").mkdir()
    data.write_csv(sockets.inbox / "ok.csv", data.messy_rows(5))
    (sockets.inbox / "escape_dir").symlink_to(outside)
    (sockets.inbox / "escape_file.csv").symlink_to(outside / "secret.csv")
    p = nodes.pipeline(nodes.read(path=path), nodes.write("write", "read"))
    with pytest.raises(ConfigError) as refused:
        go(p, sockets)
    assert "TOPSECRETVALUE" not in str(refused.value)
    assert list(sockets.outbox.iterdir()) == []


def test_a_symlink_out_hides_among_files_that_are_fine(
    nodes: Any, data: Any, sockets: Any, outside: Path
) -> None:
    data.write_csv(sockets.inbox / "ok.csv", data.messy_rows(5))
    (sockets.inbox / "link.csv").symlink_to(outside / "secret.csv")
    with pytest.raises(ConfigError, match=r"'link\.csv' leads out of socket 'inbox'"):
        go(nodes.copy(), sockets)  # the glob `*.csv` finds both files
    assert list(sockets.outbox.iterdir()) == []


WRITE_ESCAPES = [
    "../outside/",
    "../outside/{run_id}",
    "/tmp/elsewhere/",
    "a/../../outside/",
    "escape/",
    "escape/deeper/",
]


@pytest.mark.parametrize("path", WRITE_ESCAPES)
def test_a_sink_cannot_write_outside_its_socket(
    nodes: Any, data: Any, sockets: Any, outside: Path, path: str
) -> None:
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(5))
    (sockets.outbox / "escape").symlink_to(outside)
    p = nodes.pipeline(nodes.read(), nodes.write("write", "read", path=path))
    before = sorted(outside.iterdir())
    with pytest.raises(ConfigError):
        go(p, sockets)
    assert sorted(outside.iterdir()) == before
    assert not Path("/tmp/elsewhere").exists()


# --- the example --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", [None, *PATHS])
def test_the_csv_clean_example_runs(nodes: Any, data: Any, sockets: Any, path: str | None) -> None:
    pipeline = load_pipeline_file(REPO / "tests" / "fixtures" / "csv-clean.yaml")
    rows = data.messy_rows(500)
    data.write_csv(sockets.inbox / "people.csv", rows)
    result = go(pipeline, sockets, force_path=path)
    (stage,) = result.stages
    kept = [row for row in rows if row[0] != ""]
    assert stage.path == (path or "fused")  # the planner chooses the fused path
    assert stage.rows_per_node == {
        "read_csv": 500,
        "drop_incomplete": len(kept),
        "trim_text": len(kept),
        "write_parquet": len(kept),
    }
    written = data.dataset(stage)
    assert written["id"].to_list() == [
        row[0] for row in kept
    ]  # text: nothing is converted that was not asked for
    assert written["name"].to_list() == [row[1].strip() or None for row in kept]
    assert written["city"].to_list() == [row[2].strip() or None for row in kept]
    manifest = Manifest.model_validate_json(stage.manifest.read_text(encoding="utf-8"))
    assert (manifest.dataset, manifest.pipeline, manifest.totals.rows) == ("clean", "csv-clean", len(kept))
    assert sockets.written() == [
        f"clean/_manifest/{stage.manifest.name}",
        f"clean/part-00000-{result.run_id}.parquet",
    ]


# --- zero retention -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", PATHS)
def test_a_run_prints_and_logs_no_data_and_only_the_data_file_holds_it(
    nodes: Any,
    data: Any,
    sockets: Any,
    path: str,
    capfd: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    canary = "CANARY-7f3a9c2e-not-for-logs"
    rows = [[str(n), canary, canary, "1.5", "2026-01-05", canary] for n in range(1, 50)]
    data.write_csv(sockets.inbox / "a.csv", rows)
    caplog.set_level(logging.DEBUG)
    result = go(nodes.messy(), sockets, force_path=path, on_event=lambda event: None)
    captured = capfd.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert canary not in caplog.text
    holding = [name for name in sockets.written() if canary.encode() in (sockets.outbox / name).read_bytes()]
    assert holding == [f"messy/part-00000-{result.run_id}.parquet"]  # not the manifest, not a temporary file
    assert canary not in repr(result)
    assert canary not in str(result.stages[0].manifest)


# --- the commit lock of a stage (for the stage worker) ------------------------------------------------------


class RecordingLock:
    """A commit lock that records what the sink's folder held when it was taken and when it was let go."""

    def __init__(self, dataset: Path) -> None:
        self.dataset = dataset
        self.seen: list[tuple[str, list[str], list[str]]] = []

    def _look(self, when: str) -> None:
        data = sorted(path.name for path in self.dataset.glob("*.parquet"))
        manifests = sorted(path.name for path in self.dataset.glob("_manifest/*.json"))
        self.seen.append((when, data, manifests))

    def __enter__(self) -> None:
        self._look("taken")

    def __exit__(self, *exc: object) -> None:
        self._look("let go")


@pytest.mark.parametrize(
    ("path", "operator", "config"),
    [
        ("fused", "transform.filter", {"expr": "id IS NOT NULL"}),
        ("batch", "transform.filter", {"expr": "id IS NOT NULL"}),
        ("hybrid", "transform.filter", {"expr": "id IS NOT NULL"}),
        ("hybrid", "transform.sort", {"by": ["id"]}),  # through DuckDB
    ],
)
def test_the_commit_lock_is_held_from_the_rename_until_the_manifest(
    nodes: Any, data: Any, sockets: Any, path: str, operator: str, config: dict[str, Any]
) -> None:
    from datetime import UTC, datetime

    from safetwin.dataplane.run import run_pipeline_stage

    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(500))
    p = nodes.pipeline(
        nodes.read(),
        nodes.step("keep", operator, "read", **config),
        nodes.write("write", "keep"),
    )
    lock = RecordingLock(sockets.outbox / "data")
    result = run_pipeline_stage(
        p,
        sockets.folders,
        0,
        run_id="r1",
        started_at=datetime.now(UTC),
        committed={},
        memory_limit_bytes=1 << 30,
        force_path=path,  # type: ignore[arg-type]
        commit_lock=lock,
    )
    (taken, let_go) = lock.seen
    assert taken == ("taken", [], [])  # nothing renamed into place yet, no manifest
    assert let_go == ("let go", ["part-00000-r1.parquet"], [result.manifest.name])  # both, together
    assert result.files[0].path.name == "part-00000-r1.parquet"


def test_a_stage_that_fails_in_its_commit_lets_go_of_the_lock_and_leaves_nothing(
    nodes: Any, data: Any, sockets: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading
    from datetime import UTC, datetime

    from safetwin.dataplane import runtime
    from safetwin.dataplane.run import run_pipeline_stage

    def broken(dataset_dir: Path, manifest: Any) -> Path:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(runtime, "write_manifest", broken)
    data.write_csv(sockets.inbox / "a.csv", data.messy_rows(50))
    p = nodes.pipeline(nodes.read(), nodes.write("write", "read"))
    lock = threading.Lock()
    with pytest.raises(OSError, match="No space"):
        run_pipeline_stage(
            p,
            sockets.folders,
            0,
            run_id="r1",
            started_at=datetime.now(UTC),
            committed={},
            memory_limit_bytes=1 << 30,
            commit_lock=lock,
        )
    assert not lock.locked()
    assert [path for path in sockets.outbox.rglob("*") if path.is_file()] == []
