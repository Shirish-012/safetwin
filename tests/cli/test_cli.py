"""The safetwin command: `safetwin validate FILE` and `safetwin schema` (hidden from --help until M1)."""

import errno
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
from safetwin.spec import Pipeline, Problem

REPO = Path(__file__).resolve().parents[2]
EXAMPLES = REPO / "tests" / "fixtures"
CSV_TEXT = (EXAMPLES / "csv-clean.yaml").read_text(encoding="utf-8")
runner = CliRunner()


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "pipeline.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def lines(output: str, prefix: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith(prefix)]


@pytest.mark.parametrize(
    ("name", "summary"),
    [
        ("orders-report.yaml", "valid (7 nodes)"),
        ("csv-clean.yaml", "valid (4 nodes)"),
    ],
)
def test_a_valid_example_exits_0_and_says_so(name: str, summary: str) -> None:
    result = runner.invoke(app, ["validate", str(EXAMPLES / name)])
    assert result.exit_code == 0, result.output
    assert result.output.strip() == summary


def test_a_pipeline_with_errors_exits_1_and_prints_error_lines(tmp_path: Path) -> None:
    cyclic = CSV_TEXT.replace("inputs: [read_csv]", "inputs: [write_parquet]")
    result = runner.invoke(app, ["validate", str(write(tmp_path, cyclic))])
    assert result.exit_code == 1
    assert lines(result.output, "ERROR") == [
        "ERROR [cycle] drop_incomplete: steps form a loop: "
        "drop_incomplete → trim_text → write_parquet → drop_incomplete. Remove one of these connections"
    ]
    assert "valid" not in result.output


def test_every_problem_gets_its_own_line_in_the_documented_format(tmp_path: Path) -> None:
    broken = CSV_TEXT.replace("operator: transform.filter", "operator: transform.nope").replace(
        "      socket: outbox\n", ""
    )
    result = runner.invoke(app, ["validate", str(write(tmp_path, broken))])
    assert result.exit_code == 1
    errors = lines(result.output, "ERROR")
    assert [line.split(" ", 2)[1] for line in errors] == ["[unknown_operator]", "[missing_socket]"]
    assert errors[0].startswith(
        "ERROR [unknown_operator] drop_incomplete: 'drop_incomplete' uses 'transform.nope'"
    )
    assert errors[1].startswith(
        "ERROR [missing_socket] write_parquet: 'write_parquet' (sink.parquet) needs a socket"
    )


def test_a_file_that_is_not_valid_yaml_exits_1_with_an_error_line(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(write(tmp_path, "metadata: name: x\n"))])
    assert result.exit_code == 1
    assert lines(result.output, "ERROR") == [
        "ERROR [yaml_error] line 1, column 15: mapping values are not allowed here"
    ]


def test_a_file_that_does_not_match_the_spec_exits_1_with_its_location(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(write(tmp_path, CSV_TEXT.replace("kind: Pipeline\n", "")))])
    assert result.exit_code == 1
    assert lines(result.output, "ERROR") == ["ERROR [missing] kind: Field required"]
    assert "valid" not in result.output


def test_a_secret_in_the_file_is_an_error_and_is_not_printed(tmp_path: Path) -> None:
    leaky = CSV_TEXT.replace(
        "        header: true", "        header: true\n        token: AKIAIOSFODNN7EXAMPLE"
    )
    result = runner.invoke(app, ["validate", str(write(tmp_path, leaky))])
    assert result.exit_code == 1
    (error,) = lines(result.output, "ERROR")
    assert error.startswith("ERROR [inline_secret] read_csv: spec.nodes[read_csv].config.token looks like")
    assert "AKIAIOSFODNN7EXAMPLE" not in result.output


SECRET = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
HEX_KEY = "3c82458822067a8405b54f1594dd5af84be10246"
LOOKS_RANDOM_ID = "k3j9x0q7w2m5n8b1v4c6z0l2a9s7d5f3"


def test_a_token_written_where_a_name_belongs_never_appears_in_the_output(tmp_path: Path) -> None:
    leaky = CSV_TEXT.replace("socket: inbox", f"socket: {SECRET}").replace(
        "inputs: [drop_incomplete]", f"inputs: [{HEX_KEY}]"
    )
    result = runner.invoke(app, ["validate", str(write(tmp_path, leaky))])
    assert result.exit_code == 1
    assert SECRET not in result.output
    assert HEX_KEY not in result.output
    assert "ERROR [unknown_socket_alias] read_csv: 'read_csv' uses socket '<redacted>'" in result.output
    assert "ERROR [unknown_reference] trim_text: 'trim_text' lists '<redacted>' in inputs" in result.output


def test_a_node_id_that_looks_like_a_token_is_not_printed_either(tmp_path: Path) -> None:
    leaky = CSV_TEXT.replace("read_csv", LOOKS_RANDOM_ID)
    result = runner.invoke(app, ["validate", str(write(tmp_path, leaky))])
    assert result.exit_code == 1
    assert LOOKS_RANDOM_ID not in result.output
    assert "ERROR [inline_secret] <redacted>: spec.nodes[<redacted>].id looks like a secret" in result.output


def test_a_token_in_a_yaml_error_or_a_location_is_not_printed(tmp_path: Path) -> None:
    for text in (
        f"a: !{SECRET} value\n",
        CSV_TEXT.replace("operator: transform.trim\n", f"operator: transform.trim\n      {SECRET}: 1\n"),
    ):
        result = runner.invoke(app, ["validate", str(write(tmp_path, text))])
        assert result.exit_code == 1
        assert SECRET not in result.output
        assert "<redacted>" in result.output


def test_yaml_aliases_are_an_error_line_not_a_traceback(tmp_path: Path) -> None:
    looping = CSV_TEXT.replace("        header: true", "        header: &c {self: *c}")
    result = runner.invoke(app, ["validate", str(write(tmp_path, looping))])
    assert result.exit_code == 1
    assert result.exception is None or isinstance(result.exception, SystemExit)
    (error,) = lines(result.output, "ERROR")
    assert re.fullmatch(
        r"ERROR \[yaml_error\] line \d+, column \d+: aliases \(\*name\) are not allowed .*", error
    )


def test_yaml_nested_hundreds_of_levels_deep_is_an_error_line_not_a_traceback(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(write(tmp_path, "[" * 600 + "]" * 600 + "\n"))])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert lines(result.output, "ERROR") == ["ERROR [too_deep] the file is nested too deeply"]


def test_warnings_are_printed_but_do_not_fail_the_check(monkeypatch: pytest.MonkeyPatch) -> None:
    warning = Problem("warning", "restricted_unmasked", "email is written unmasked", "write_parquet")
    monkeypatch.setattr(main, "validate_pipeline", lambda pipeline: [warning])
    result = runner.invoke(app, ["validate", str(EXAMPLES / "csv-clean.yaml")])
    assert result.exit_code == 0
    assert lines(result.output, "WARN") == [
        "WARN [restricted_unmasked] write_parquet: email is written unmasked"
    ]
    assert lines(result.output, "valid") == ["valid (4 nodes)"]


@pytest.mark.parametrize("field", ["mode: batch", "spill: none", "trigger: {type: manual}"])
def test_a_field_of_the_earlier_format_is_an_error_line(tmp_path: Path, field: str) -> None:
    text = CSV_TEXT.replace("  sockets:", f"  {field}\n  sockets:", 1)
    result = runner.invoke(app, ["validate", str(write(tmp_path, text))])
    assert result.exit_code == 1
    name = field.split(":")[0]
    assert lines(result.output, "ERROR") == [
        f"ERROR [extra_forbidden] spec.{name}: Extra inputs are not permitted"
    ]


def test_a_warning_next_to_an_error_still_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    problems = [
        Problem("warning", "restricted_unmasked", "email is written unmasked"),
        Problem("error", "cycle", "steps form a loop"),
    ]
    monkeypatch.setattr(main, "validate_pipeline", lambda pipeline: problems)
    result = runner.invoke(app, ["validate", str(EXAMPLES / "csv-clean.yaml")])
    assert result.exit_code == 1
    assert result.output.splitlines() == [
        "WARN [restricted_unmasked] email is written unmasked",
        "ERROR [cycle] steps form a loop",
    ]


def test_a_missing_file_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2
    assert "valid (" not in result.output


def test_a_directory_is_a_file_error_line_not_a_traceback(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(tmp_path)])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert result.output.splitlines() == [
        f"ERROR [file_error] cannot read {tmp_path}: {os.strerror(errno.EISDIR)}"
    ]


def test_a_file_that_may_not_be_read_is_a_file_error_line_not_a_traceback(tmp_path: Path) -> None:
    path = write(tmp_path, CSV_TEXT)
    path.chmod(0o000)
    if os.access(path, os.R_OK):
        pytest.skip("this user can read every file, whatever its mode (root?)")
    result = runner.invoke(app, ["validate", str(path)])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert result.output.splitlines() == [
        f"ERROR [file_error] cannot read {path}: {os.strerror(errno.EACCES)}"
    ]


FAILURES = {
    "no permission": (PermissionError(errno.EACCES, "Permission denied"), "Permission denied"),
    "a directory": (IsADirectoryError(errno.EISDIR, "Is a directory"), "Is a directory"),
    "an i/o error": (OSError(errno.EIO, "Input/output error"), "Input/output error"),
    "an error without a reason": (OSError("the disk went away"), "the disk went away"),
    "text that is not utf-8": (
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
        "'utf-8' codec can't decode byte 0xff in position 0: invalid start byte",
    ),
}


@pytest.mark.parametrize(("error", "reason"), FAILURES.values(), ids=FAILURES.keys())
def test_whatever_goes_wrong_reading_the_file_is_one_file_error_line(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, error: Exception, reason: str
) -> None:
    def fail(path: Path) -> Pipeline:
        raise error

    monkeypatch.setattr(main, "load_pipeline_file", fail)
    path = write(tmp_path, CSV_TEXT)
    result = runner.invoke(app, ["validate", str(path)])
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert result.output.splitlines() == [f"ERROR [file_error] cannot read {path}: {reason}"]


def test_the_installed_safetwin_script_reports_an_unreadable_file_without_a_traceback(tmp_path: Path) -> None:
    safetwin = Path(sys.executable).parent / "safetwin"
    result = subprocess.run([safetwin, "validate", tmp_path], capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert result.stdout.startswith(f"ERROR [file_error] cannot read {tmp_path}: ")
    assert result.stdout.count("\n") == 1
    assert result.stderr == ""


def test_a_key_used_twice_is_an_error_line_that_names_the_line(tmp_path: Path) -> None:
    text = CSV_TEXT.replace("      socket: inbox\n", "      socket: inbox\n      socket: outbox\n")
    first = text.splitlines().index("      socket: inbox") + 1
    result = runner.invoke(app, ["validate", str(write(tmp_path, text))])
    assert result.exit_code == 1
    where = f"line {first + 1}, column 7"
    assert result.output.splitlines() == [
        f"ERROR [yaml_error] {where}: found duplicate key 'socket' (first used on line {first})"
    ]


def test_schema_prints_the_json_schema() -> None:
    result = runner.invoke(app, ["schema"])
    assert result.exit_code == 0, result.output
    printed = json.loads(result.output)
    assert printed["$id"] == "urn:safetwin:schemas:pipeline:v1"
    assert set(printed["required"]) == {"apiVersion", "kind", "metadata", "spec"}
    committed = (REPO / "schemas" / "safetwin.pipeline.v1.schema.json").read_text(encoding="utf-8")
    assert result.output == committed


def test_help_lists_the_masking_commands_and_hides_the_engine_and_pipeline_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    commands = commands_in_help(result.output)
    assert commands == COMMANDS
    for hidden in ("validate", "schema", "run", "run-local", "engine", "runs"):
        assert runner.invoke(app, [hidden, "--help"]).exit_code == 0  # hidden, but still there


COMMANDS = ["ui", "demo", "scan", "check", "mask", "unmask", "rekey", "export", "key"]


def commands_in_help(text: str) -> list[str]:
    """The names in the Commands box of Typer's help: a name right after the box's left edge (a line that
    goes on with a description is indented further)."""
    section = re.sub(r"\x1b\[[0-9;]*m", "", text).partition("Commands")[2]
    return re.findall(r"^│ ([a-z][a-z-]*) ", section, re.MULTILINE)


def test_the_help_and_the_module_say_safetwin() -> None:
    result = runner.invoke(app, ["--help"])
    assert "safetwin" in result.output
    done = subprocess.run(
        [sys.executable, "-m", "safetwin", "--help"], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert "Usage: safetwin " in re.sub(r"\x1b\[[0-9;]*m", "", done.stdout)
    assert commands_in_help(done.stdout) == COMMANDS


def test_the_installed_safetwin_script_works_and_reports_the_exit_code(tmp_path: Path) -> None:
    safetwin = Path(sys.executable).parent / "safetwin"
    ok = subprocess.run(
        [safetwin, "validate", EXAMPLES / "csv-clean.yaml"], capture_output=True, text=True, check=False
    )
    assert (ok.returncode, ok.stdout.strip()) == (0, "valid (4 nodes)")
    bad = subprocess.run(
        [safetwin, "validate", write(tmp_path, "metadata: name: x\n")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode == 1
    assert bad.stdout.startswith("ERROR [yaml_error] ")


@pytest.mark.parametrize("kind", ["CANARY-1f2e3d4c5b6a", "a' found using 'LEAKED"])
def test_validate_never_repeats_a_wrong_kind(tmp_path: Path, kind: str) -> None:
    text = CSV_TEXT.replace("kind: Pipeline", f"kind: {json.dumps(kind)}")
    result = runner.invoke(app, ["validate", str(write(tmp_path, text))])
    assert result.exit_code == 1
    assert kind not in result.output
    assert "LEAKED" not in result.output
    assert lines(result.output, "ERROR") == ["ERROR [literal_error] kind: Input should be 'Pipeline'"]


@pytest.mark.parametrize(
    ("change", "what"),
    [
        (("owner: me", "owner: !ZQXCANARY me"), "could not determine a constructor for the tag '<redacted>'"),
        (("owner: me", "owner: &ZQXCANARY me\n  tags2: &ZQXCANARY x"), "found duplicate anchor '<redacted>'"),
    ],
    ids=["tag", "anchor"],
)
def test_validate_never_repeats_a_yaml_tag_or_anchor_name(
    tmp_path: Path, change: tuple[str, str], what: str
) -> None:
    result = runner.invoke(app, ["validate", str(write(tmp_path, CSV_TEXT.replace(*change)))])
    assert result.exit_code == 1
    assert "ZQXCANARY" not in result.output
    assert what in result.output
