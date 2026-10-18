"""safetwin run-local: run a pipeline with folders as sockets, and say what happened without showing any
data."""

import csv
import errno
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from safetwin.cli import main
from safetwin.cli.main import app
from safetwin.dataplane.runtime import ProgressEvent

REPO = Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "tests" / "fixtures" / "csv-clean.yaml"
runner = CliRunner()

CANARY = "CANARY-7f3a9c2e-not-for-the-terminal"

PIPELINE_HEAD = """\
apiVersion: safetwin/v1
kind: Pipeline
metadata:
  name: {name}
spec:
  sockets:
    inbox: socket://local-inbox
    outbox: socket://local-outbox
  nodes:
    - {{id: read_csv, operator: source.csv, socket: inbox, config: {{path: "*.csv"}}}}
"""
TWO_STAGES = (
    PIPELINE_HEAD.format(name="two-stages")
    + """\
    - {id: write_raw, operator: sink.parquet, inputs: [read_csv], socket: outbox, config: {path: raw/}}
    - {id: drop, operator: transform.filter, inputs: [write_raw], config: {expr: "amount IS NOT NULL"}}
    - {id: write_clean, operator: sink.parquet, inputs: [drop], socket: outbox, config: {path: clean/}}
"""
)
STRICT_CAST = (
    PIPELINE_HEAD.format(name="strict-cast")
    + """\
    - {id: boom, operator: transform.derive, inputs: [read_csv], config: {name: n, expr: "CAST(name AS INT)"}}
    - {id: write, operator: sink.parquet, inputs: [boom], socket: outbox, config: {path: out/}}
"""
)
FAN_OUT = (
    PIPELINE_HEAD.format(name="fan-out")
    + """\
    - {id: one, operator: sink.parquet, inputs: [read_csv], socket: outbox, config: {path: one/}}
    - {id: two, operator: sink.parquet, inputs: [read_csv], socket: outbox, config: {path: two/}}
"""
)


SQL_TOTALS = (
    PIPELINE_HEAD.format(name="sql-totals")
    + """\
    - {id: numbers, operator: transform.cast, inputs: [read_csv], config: {columns: {amount: float}}}
    - id: totals
      operator: transform.sql
      inputs: [numbers]
      config:
        sql: "SELECT city, count(*) AS n, sum(amount) AS total FROM input GROUP BY city"
    - id: ordered
      operator: transform.sort
      inputs: [totals]
      config: {by: [{column: total, descending: true}, city]}
    - {id: write, operator: sink.parquet, inputs: [ordered], socket: outbox, config: {path: totals/}}
"""
)


def one_sql_step(sql: str) -> str:
    """A pipeline with one step for DuckDB, running `sql`."""
    nodes = (
        PIPELINE_HEAD.format(name="one-query")
        + "    - {id: query, operator: transform.sql, inputs: [read_csv], config: {sql: "
        + json.dumps(sql)
        + "}}\n"
        + "    - {id: write, operator: sink.parquet, inputs: [query], socket: outbox, config: {path: out/}}\n"
    )
    return nodes


STREAM_THEN_FAIL = (
    PIPELINE_HEAD.format(name="stream-then-fail")
    + """\
    - {id: query, operator: transform.sql, inputs: [read_csv], config: {sql: "SELECT * FROM input"}}
    - id: boom
      operator: transform.derive
      inputs: [query]
      config: {name: n, expr: "CAST(name AS INT)"}
    - {id: write, operator: sink.parquet, inputs: [boom], socket: outbox, config: {path: out/}}
"""
)

SORT_WIDE = (
    PIPELINE_HEAD.format(name="sort-wide")
    + """\
    - id: ordered
      operator: transform.sort
      inputs: [read_csv]
      config: {by: [{column: name, descending: true}]}
    - {id: write, operator: sink.parquet, inputs: [ordered], socket: outbox, config: {path: sorted/}}
"""
)


class Folders:
    def __init__(self, root: Path) -> None:
        self.inbox, self.outbox = root / "in", root / "out"
        self.inbox.mkdir(parents=True)
        self.outbox.mkdir(parents=True)

    def args(self, pipeline: Path, *more: str) -> list[str]:
        return [
            "run-local",
            str(pipeline),
            "--socket",
            f"inbox={self.inbox}",
            "--socket",
            f"outbox={self.outbox}",
            *more,
        ]

    def written(self) -> list[str]:
        return sorted(str(p.relative_to(self.outbox)) for p in self.outbox.rglob("*") if p.is_file())


@pytest.fixture
def folders(tmp_path: Path) -> Folders:
    return Folders(tmp_path)


def write_csv(folder: Path, rows: int, name: str = "people.csv", value: str = "  Alice ") -> list[list[str]]:
    """`rows` rows of id, name, city, amount; one in ten has no id and one in seven no amount."""
    made = [
        ["" if n % 10 == 0 else str(n), value, f" city {n % 5} ", "" if n % 7 == 0 else f"{n}.5"]
        for n in range(rows)
    ]
    with (folder / name).open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["id", "name", "city", "amount"])
        writer.writerows(made)
    return made


def pipeline_file(tmp_path: Path, text: str, name: str = "pipeline.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def plain(output: str) -> str:
    """The output as one line of words: no styling, no box that Typer draws round an error, no line breaks."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", re.sub(r"\x1b\[[0-9;]*m", "", output)).split())


def lines(output: str, prefix: str) -> list[str]:
    return [line for line in output.splitlines() if line.lstrip().startswith(prefix)]


# --- a run --------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", [None, "fused", "batch"])
def test_a_run_prints_the_funnel_of_each_node_and_the_files_and_the_manifest(
    folders: Folders, path: str | None
) -> None:
    made = write_csv(folders.inbox, 12_000)
    kept = sum(1 for row in made if row[0] != "")
    args = folders.args(EXAMPLE, *(["--path", path] if path else []))
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    out = result.stdout.splitlines()
    assert re.fullmatch(r"run r[0-9a-f]{8} of csv-clean: 1 stage\(s\)", out[0])
    assert out[1].startswith(f"stage 1: {path or 'fused'}, ")
    assert out[2:6] == [
        f"  read_csv         source.csv        {len(made):,}",
        f"  drop_incomplete  transform.filter  {len(made):,} → {kept:,}",
        f"  trim_text        transform.trim    {kept:,} → {kept:,}",
        f"  write_parquet    sink.parquet      {kept:,} → {kept:,}",
    ]
    assert f"{len(made):,} → {kept:,}" in result.stdout
    assert kept > 10_000  # so the numbers have a thousands separator
    (wrote,) = lines(result.stdout, "wrote ")
    parquet = Path(wrote.split("wrote ")[1])
    assert parquet.parent == (folders.outbox / "clean").resolve()
    assert re.fullmatch(r"part-00000-r[0-9a-f]{8}\.parquet", parquet.name)
    (details,) = lines(result.stdout, f"{parquet.stat().st_size:,} bytes")
    assert f"sha256 {hashlib.sha256(parquet.read_bytes()).hexdigest()}" in details
    (manifest_line,) = lines(result.stdout, "manifest ")
    manifest = Path(manifest_line.split("manifest ")[1])
    assert manifest.parent == parquet.parent / "_manifest"
    assert manifest.exists()
    assert folders.written() == [f"clean/_manifest/{manifest.name}", f"clean/{parquet.name}"]


def test_both_paths_print_the_same_funnel(tmp_path: Path) -> None:
    funnels = []
    for path in ("fused", "batch"):
        folders = Folders(tmp_path / path)
        write_csv(folders.inbox, 2000)
        result = runner.invoke(app, folders.args(EXAMPLE, "--path", path))
        assert result.exit_code == 0, result.output
        funnels.append([line for line in result.stdout.splitlines() if "→" in line or "source.csv" in line])
    assert funnels[0] == funnels[1]
    assert len(funnels[0]) == 4


def test_the_funnel_goes_on_across_a_stage_boundary(tmp_path: Path, folders: Folders) -> None:
    made = write_csv(folders.inbox, 700)
    kept = sum(1 for row in made if row[3] != "")
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, TWO_STAGES)))
    assert result.exit_code == 0, result.output
    assert lines(result.stdout, "stage ")[0].startswith("stage 1: fused")
    assert lines(result.stdout, "stage ")[1].startswith("stage 2: fused")
    assert lines(result.stdout, "drop ")[0].endswith(
        f"transform.filter  {len(made)} → {kept}"
    )  # from the sink before
    assert len(lines(result.stdout, "wrote ")) == 2
    assert len(lines(result.stdout, "manifest ")) == 2


def test_progress_goes_to_stderr_and_the_summary_to_stdout(folders: Folders) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(EXAMPLE))
    assert result.exit_code == 0
    assert "stage 1 (" not in result.stdout  # no progress line in the report
    assert result.stderr == ""  # and a run that takes no time has nothing to report while it runs


def test_the_installed_safetwin_script_runs_a_pipeline(folders: Folders) -> None:
    write_csv(folders.inbox, 1000)
    safetwin = Path(sys.executable).parent / "safetwin"
    done = subprocess.run([safetwin, *folders.args(EXAMPLE)], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stderr == ""
    assert "→" in done.stdout
    assert "sha256 " in done.stdout


def test_help_lists_the_command_and_its_options() -> None:
    assert "run-local" not in runner.invoke(app, ["--help"]).output  # hidden until M1 replaces it
    text = re.sub(
        r"\x1b\[[0-9;]*m", "", runner.invoke(app, ["run-local", "--help"]).output
    )  # without styling
    for word in ("--socket", "ALIAS=FOLDER", "--path", "fused", "batch"):
        assert word in text


# --- usage errors -------------------------------------------------------------------------------------------


def test_a_socket_that_is_not_alias_equals_folder_is_a_usage_error(folders: Folders) -> None:
    for bad in ("inbox", "=folder", "inbox="):
        result = runner.invoke(app, ["run-local", str(EXAMPLE), "--socket", bad])
        assert result.exit_code == 2, bad
        assert "is not ALIAS=FOLDER" in result.output


def test_an_unknown_path_is_a_usage_error_and_so_is_a_missing_file(folders: Folders, tmp_path: Path) -> None:
    assert runner.invoke(app, folders.args(EXAMPLE, "--path", "slow")).exit_code == 2
    assert runner.invoke(app, ["run-local", str(tmp_path / "nope.yaml")]).exit_code == 2


# --- when it cannot run -------------------------------------------------------------------------------------


def test_a_socket_without_a_folder_exits_1_and_says_which(folders: Folders) -> None:
    write_csv(folders.inbox, 10)
    result = runner.invoke(app, ["run-local", str(EXAMPLE), "--socket", f"inbox={folders.inbox}"])
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        "ERROR write_parquet (sink.parquet): socket 'outbox' has no folder (folders were given for: inbox)"
    ]
    assert result.stdout == ""
    assert folders.written() == []


def test_a_pipeline_with_errors_is_reported_like_validate_does(tmp_path: Path, folders: Folders) -> None:
    broken = EXAMPLE.read_text(encoding="utf-8").replace("transform.filter", "transform.nope")
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, broken)))
    assert result.exit_code == 1
    assert lines(result.stdout, "ERROR") == [
        "ERROR [unknown_operator] drop_incomplete: 'drop_incomplete' uses 'transform.nope', "
        "which is not a known operator"
    ]
    assert folders.written() == []


def test_a_file_that_is_not_a_pipeline_is_reported_like_validate_does(
    tmp_path: Path, folders: Folders
) -> None:
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, "metadata: name: x\n")))
    assert result.exit_code == 1
    assert lines(result.stdout, "ERROR [yaml_error]")


def test_what_cannot_run_yet_is_said_plainly(tmp_path: Path, folders: Folders) -> None:
    write_csv(folders.inbox, 10)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, FAN_OUT)))
    assert result.exit_code == 1
    assert result.stderr.startswith("ERROR 'read_csv' feeds 2 nodes: fan-out is not supported yet")


def test_a_path_that_leaves_its_socket_is_refused(tmp_path: Path, folders: Folders) -> None:
    (tmp_path / "secret.csv").write_text("id,name\n1,TOPSECRETVALUE\n")
    write_csv(folders.inbox, 10)
    text = EXAMPLE.read_text(encoding="utf-8").replace('path: "*.csv"', 'path: "../secret.csv"')
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, text)))
    assert result.exit_code == 1
    assert "must be a path below the socket" in result.stderr
    assert "TOPSECRETVALUE" not in result.output
    assert folders.written() == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write in a folder that is read-only")
def test_a_folder_that_cannot_be_written_in_is_one_line_with_the_reason_and_the_path(
    folders: Folders,
) -> None:
    write_csv(folders.inbox, 10)
    folders.outbox.chmod(0o500)
    try:
        result = runner.invoke(app, folders.args(EXAMPLE))
    finally:
        folders.outbox.chmod(0o700)
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [f"ERROR Permission denied: {(folders.outbox / 'clean').resolve()}"]


# --- steps that DuckDB runs ---------------------------------------------------------------------------------


def test_a_pipeline_with_sql_and_sort_runs_on_the_hybrid_path_and_prints_the_funnel_of_each_node(
    tmp_path: Path, folders: Folders
) -> None:
    made = write_csv(folders.inbox, 12_000)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, SQL_TOTALS)))
    assert result.exit_code == 0, result.output
    out = result.stdout.splitlines()
    assert re.fullmatch(r"run r[0-9a-f]{8} of sql-totals: 1 stage\(s\)", out[0])
    assert out[1].startswith("stage 1: hybrid, ")
    assert out[2:7] == [
        f"  read_csv  source.csv      {len(made):,}",
        f"  numbers   transform.cast  {len(made):,} → {len(made):,}",
        "  totals    transform.sql   12,000 → 5",
        "  ordered   transform.sort  5 → 5",
        "  write     sink.parquet    5 → 5",
    ]
    (wrote,) = lines(result.stdout, "wrote ")
    parquet = Path(wrote.split("wrote ")[1])
    assert parquet.parent == (folders.outbox / "totals").resolve()
    import polars as pl

    totals = pl.read_parquet(parquet)
    assert totals["city"].n_unique() == 5
    assert totals["total"].to_list() == sorted(totals["total"].to_list(), reverse=True)  # the sort
    assert totals["n"].sum() == len(made)


def test_duckdb_leaves_nothing_in_the_folder_of_the_app(
    tmp_path: Path, folders: Folders, safetwin_home: Path
) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, SQL_TOTALS)))
    assert result.exit_code == 0, result.output
    assert not safetwin_home.exists() or list(safetwin_home.rglob("*")) == []  # no spill folder, no extension


@pytest.mark.parametrize("limit", ["512MB", "2GB", "400MiB", "1.5 GB", "300000000B"])
def test_a_memory_limit_is_a_number_and_a_unit(tmp_path: Path, folders: Folders, limit: str) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, SQL_TOTALS), "--memory-limit", limit))
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize("limit", ["512", "lots", "0MB", "-1GB", "2 bananas", ""])
def test_a_memory_limit_that_is_not_a_size_is_a_usage_error_before_anything_runs(
    tmp_path: Path, folders: Folders, limit: str
) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, SQL_TOTALS), "--memory-limit", limit))
    assert result.exit_code == 2
    assert "Invalid value for --memory-limit:" in plain(result.output)
    assert f"'{limit}' is not a size: " in plain(result.output)
    assert "such as 512MB or 2GB" in plain(result.output) or "more than 0 bytes" in plain(result.output)
    assert folders.written() == []


def test_help_lists_the_memory_limit_and_the_hybrid_path_and_no_spill_folder() -> None:
    text = re.sub(r"\x1b\[[0-9;]*m", "", runner.invoke(app, ["run-local", "--help"]).output)
    for word in ("--memory-limit", "SIZE", "512MB", "hybrid", "DuckDB", "does not spill", "stopped at 100%"):
        assert word in text
    assert "--spill-dir" not in text


def test_the_hybrid_path_can_be_chosen_for_a_pipeline_with_nothing_for_duckdb(folders: Folders) -> None:
    write_csv(folders.inbox, 300)
    result = runner.invoke(app, folders.args(EXAMPLE, "--path", "hybrid"))
    assert result.exit_code == 0, result.output
    assert lines(result.stdout, "stage ")[0].startswith("stage 1: hybrid")


def test_a_step_for_duckdb_can_not_be_forced_onto_the_fused_path(tmp_path: Path, folders: Folders) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, SQL_TOTALS), "--path", "fused"))
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        "ERROR transform.sql runs in DuckDB: only the hybrid path can run it"
    ]
    assert folders.written() == []


def test_sql_that_can_not_be_parsed_is_reported_before_anything_runs(
    tmp_path: Path, folders: Folders
) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, one_sql_step("SELEC * FROM input"))))
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        'ERROR query (transform.sql): the SQL can\'t be parsed: Parser Error: syntax error at or near "SELEC"'
    ]
    assert result.stdout == ""
    assert folders.written() == []


@pytest.mark.parametrize(
    "sql", ["COPY (SELECT 1) TO 'x.csv'", "ATTACH 'x.duckdb' AS x", "INSTALL httpfs", "SET threads = 99"]
)
def test_sql_that_is_not_a_select_is_reported_before_anything_runs(
    tmp_path: Path, folders: Folders, sql: str
) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, one_sql_step(sql))))
    assert result.exit_code == 1
    assert result.stderr.startswith(
        "ERROR query (transform.sql): the SQL must be exactly one SELECT statement that reads `input` "
        "(found: "
    )
    assert folders.written() == []


def test_sql_can_not_read_a_file_and_the_canary_in_it_is_not_shown(tmp_path: Path, folders: Folders) -> None:
    secret = tmp_path / "secret.csv"
    secret.write_text("a,b\nCANARY-7f3a9c2e-not-for-the-terminal,1\n", encoding="utf-8")
    write_csv(folders.inbox, 100)
    result = runner.invoke(
        app, folders.args(pipeline_file(tmp_path, one_sql_step(f"SELECT * FROM read_csv('{secret}')")))
    )
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        "ERROR the run failed with PermissionException (its message can quote data, so it is not shown)"
    ]
    assert "CANARY" not in result.output
    assert folders.written() == []


def write_wide(folder: Path, rows: int = 400_000) -> None:
    with (folder / "wide.csv").open("w", encoding="utf-8", newline="") as file:
        file.write("id,name,city,amount\n")
        file.write("".join(f"{n},{CANARY}-{n:07d}-{'x' * 250},city,1\n" for n in range(rows)))


def test_too_little_memory_is_one_clear_line_with_what_to_do_and_nothing_stays(
    tmp_path: Path, folders: Folders, monkeypatch: pytest.MonkeyPatch
) -> None:
    # DuckDB's own limit is what this checks: the watchdog samples once a second, so on a slow machine (or one
    # that counts memory otherwise) it can't stop the stage first. Both stops are safe.
    monkeypatch.setenv("SAFETWIN_TEST_WATCHDOG_INTERVAL_S", "1")
    write_wide(folders.inbox)  # about 120 MB to sort
    text = SORT_WIDE
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, text), "--memory-limit", "60MB"))
    assert result.exit_code == 1
    *progress, line = result.stderr.splitlines()  # a slow machine shows a progress line or two first
    assert all(shown.startswith("stage 1 (") for shown in progress)
    assert line.startswith(
        "ERROR the DuckDB steps of this stage (ordered (transform.sort)) ran out of memory"
    )
    assert "the limit is 60 MB" in line
    assert "DuckDB does not spill to disk" in line
    for advice in ("--memory-limit", "add a filter", "select fewer columns"):
        assert advice in line
    assert "CANARY" not in result.output
    assert result.stdout == ""
    assert folders.written() == []


def test_a_spill_setting_of_the_earlier_format_is_refused(tmp_path: Path, folders: Folders) -> None:
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, SORT_WIDE + "  spill: none\n")))
    assert result.exit_code == 1
    assert result.stdout.splitlines() == [
        "ERROR [extra_forbidden] spec.spill: Extra inputs are not permitted"
    ]
    assert folders.written() == []


def test_a_failure_in_duckdb_shows_what_kind_of_error_and_never_the_data(
    tmp_path: Path, folders: Folders
) -> None:
    write_csv(folders.inbox, 100, value=CANARY)
    text = one_sql_step("SELECT CAST(name AS INTEGER) AS n FROM input")
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, text)))
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        "ERROR the run failed with ConversionException (its message can quote data, so it is not shown)"
    ]
    assert CANARY not in result.output
    assert folders.written() == []


def test_the_real_error_of_duckdb_quotes_the_data_which_is_why_it_is_not_shown(
    tmp_path: Path, folders: Folders
) -> None:
    write_csv(folders.inbox, 100, value=CANARY)
    from safetwin.dataplane.run import run_pipeline_local
    from safetwin.spec import load_pipeline_file

    pipeline = load_pipeline_file(
        pipeline_file(tmp_path, one_sql_step("SELECT CAST(name AS INTEGER) AS n FROM input"))
    )
    with pytest.raises(Exception, match=CANARY):
        run_pipeline_local(pipeline, {"inbox": folders.inbox, "outbox": folders.outbox})


def test_a_failure_in_the_polars_query_before_a_step_for_duckdb_is_reported_as_the_polars_error(
    tmp_path: Path, folders: Folders
) -> None:
    write_csv(folders.inbox, 100, value=CANARY)
    text = STRICT_CAST.replace(
        "    - {id: write,",
        '    - {id: query, operator: transform.sql, inputs: [boom], config: {sql: "SELECT * FROM input"}}\n'
        "    - {id: write,",
    ).replace("inputs: [boom], socket", "inputs: [query], socket")
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, text)))
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        "ERROR the run failed with InvalidOperationError (its message can quote data, so it is not shown)"
    ]
    assert CANARY not in result.output
    assert folders.written() == []


def test_progress_lines_name_the_hybrid_path(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main.time, "monotonic", lambda: 100.0)
    main._Progress()(ProgressEvent(0, "hybrid", 0, {"read_csv": 10, "query": 4}, 1.2))
    assert capsys.readouterr().err.splitlines() == ["stage 1 (hybrid) 1s: 10 → 4 rows, 0 bytes written"]


def test_progress_lines_show_the_memory_of_the_stage(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main.time, "monotonic", lambda: 100.0)
    main._Progress()(ProgressEvent(0, "fused", 2048, {"read_csv": 10, "drop": 4}, 1.2, 123_456_789))
    assert capsys.readouterr().err.splitlines() == [
        "stage 1 (fused) 1s: 10 → 4 rows, 2,048 bytes written, 123 MB of memory"
    ]


def test_a_real_run_shows_the_memory_on_its_progress_lines(
    folders: Folders, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safetwin.dataplane import runtime

    monkeypatch.setattr(runtime, "EVENT_INTERVAL_S", 0.0)
    write_csv(folders.inbox, 5000)
    result = runner.invoke(app, folders.args(EXAMPLE, "--path", "batch"))
    assert result.exit_code == 0, result.output
    progress = lines(result.stderr, "stage 1 (batch)")
    assert progress
    assert all(re.search(r"bytes written, [\d,]+ MB of memory$", line) for line in progress)


def test_a_stage_that_reaches_its_memory_limit_is_one_clear_line(
    tmp_path: Path, folders: Folders, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safetwin.dataplane import run
    from safetwin.dataplane.watchdog import memory_limit_reached

    def stopped(*args: object, **kwargs: object) -> None:
        raise memory_limit_reached(60_000_000, "the stage of read_csv (source.csv), write (sink.parquet)")

    monkeypatch.setattr(run, "run_pipeline_local", stopped)
    write_csv(folders.inbox, 10)
    result = runner.invoke(app, folders.args(EXAMPLE, "--memory-limit", "60MB"))
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        "ERROR the stage of read_csv (source.csv), write (sink.parquet) used more memory than it may (the "
        "limit is 60 MB), so it was stopped. Raise the memory limit (--memory-limit), or add a filter before "
        "the heavy step or select fewer columns so that less data reaches it."
    ]
    assert result.stdout == ""


@pytest.mark.parametrize(
    ("error", "line"),
    [
        (OSError(errno.ETIMEDOUT, "timed out"), f"ERROR {os.strerror(errno.ETIMEDOUT)}"),
        (TimeoutError(), "ERROR TimeoutError"),
    ],
)
def test_a_reader_that_times_out_is_one_error_line_and_not_a_hang(
    folders: Folders, monkeypatch: pytest.MonkeyPatch, error: OSError, line: str
) -> None:
    from safetwin.dataplane import batch

    def failing(*args: object) -> object:
        raise error
        yield  # a generator, as the real one is

    monkeypatch.setattr(batch, "_csv_batches", failing)
    write_csv(folders.inbox, 100)
    result = runner.invoke(app, folders.args(EXAMPLE, "--path", "batch"))
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [line]
    assert folders.written() == []


def test_an_interrupted_run_is_one_line_and_exit_status_130(
    folders: Folders, monkeypatch: pytest.MonkeyPatch
) -> None:
    from safetwin.dataplane import run

    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(run, "run_pipeline_local", interrupted)
    write_csv(folders.inbox, 10)
    result = runner.invoke(app, folders.args(EXAMPLE))
    assert result.exit_code == 130
    assert result.stderr.splitlines() == [
        "ERROR the run was interrupted: the stage that was running wrote nothing"
    ]


def test_the_installed_safetwin_script_ends_after_a_failed_run_with_duckdb_in_it(
    tmp_path: Path, folders: Folders
) -> None:
    # A DuckDB query that is dropped while it runs leaves work behind that stops a process from ending (see
    # `hybrid.py`). This is the command as it is run, in a process of its own, on a run that fails halfway.
    write_csv(folders.inbox, 400_000, value=CANARY)
    safetwin = Path(sys.executable).parent / "safetwin"
    env = {**os.environ, "SAFETWIN_HOME": str(tmp_path / "home")}
    try:
        done = subprocess.run(
            [safetwin, *folders.args(pipeline_file(tmp_path, STREAM_THEN_FAIL))],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
            env=env,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("the command did not end: a DuckDB query that was dropped while it ran keeps it waiting")
    assert done.returncode == 1, done.stderr
    assert done.stderr.strip().splitlines() == [
        "ERROR the run failed with InvalidOperationError (its message can quote data, so it is not shown)"
    ]
    assert CANARY not in done.stdout + done.stderr
    assert folders.written() == []


# --- what must not reach the terminal -----------------------------------------------------------------------


@pytest.mark.parametrize("path", ["fused", "batch"])
def test_a_failure_shows_what_kind_of_error_and_never_the_data(
    tmp_path: Path, folders: Folders, path: str
) -> None:
    write_csv(folders.inbox, 100, value=CANARY)
    result = runner.invoke(app, folders.args(pipeline_file(tmp_path, STRICT_CAST), "--path", path))
    assert result.exit_code == 1
    assert result.stderr.splitlines() == [
        "ERROR the run failed with InvalidOperationError (its message can quote data, so it is not shown)"
    ]
    assert CANARY not in result.output
    assert folders.written() == []  # and the failed run left nothing behind


def test_the_real_error_quotes_the_data_which_is_why_it_is_not_shown(
    tmp_path: Path, folders: Folders
) -> None:
    # If this stops being true the care above could be dropped. Until then it is the reason for it.
    write_csv(folders.inbox, 100, value=CANARY)
    from safetwin.dataplane.run import run_pipeline_local
    from safetwin.spec import load_pipeline_file

    pipeline = load_pipeline_file(pipeline_file(tmp_path, STRICT_CAST))
    with pytest.raises(Exception, match=CANARY):
        run_pipeline_local(pipeline, {"inbox": folders.inbox, "outbox": folders.outbox}, force_path="fused")


def test_a_traceback_that_might_show_local_variables_is_not_used() -> None:
    assert app.pretty_exceptions_show_locals is False


def test_progress_is_printed_at_most_once_a_second_to_stderr(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [100.0]
    monkeypatch.setattr(main.time, "monotonic", lambda: now[0])
    progress = main._Progress()

    def event(rows: int) -> ProgressEvent:
        return ProgressEvent(1, "fused", 2048, {"read_csv": rows, "drop": rows // 2}, 3.2)

    progress(event(1000))
    now[0] += 0.9
    progress(event(2000))  # too soon
    now[0] += 0.2
    progress(event(3000))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [
        "stage 2 (fused) 3s: 1,000 → 500 rows, 2,048 bytes written",
        "stage 2 (fused) 3s: 3,000 → 1,500 rows, 2,048 bytes written",
    ]
