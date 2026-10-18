"""The ``safetwin`` command.

The user-facing commands are `ui`, `demo`, `key`, `scan`, `check`, `mask`, `unmask`, `rekey` and `export`
(`cli/masking.py`). The commands that work on the internal pipeline format (`run`, `run-local`, `validate`,
`schema`) are kept for development and tests, and hidden from `--help`.
"""

import json
import os
import shlex
import subprocess
import sys
import threading
import time
from collections.abc import Iterable
from contextlib import ExitStack, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, NoReturn

import typer

from safetwin.spec import (
    Pipeline,
    Problem,
    SpecError,
    load_pipeline_file,
    redacted,
    validate_pipeline,
)
from safetwin.spec.schema import render_schema

from .masking import check as check_command
from .masking import demo as demo_command
from .masking import export as export_command
from .masking import key_app
from .masking import mask as mask_command
from .masking import rekey as rekey_command
from .masking import scan as scan_command
from .masking import ui as ui_command
from .masking import unmask as unmask_command

if TYPE_CHECKING:  # the data libraries are imported when a pipeline runs, not when `safetwin validate` starts
    from safetwin.api.connection import ConnectionInfo
    from safetwin.dataplane.run import RunResult
    from safetwin.dataplane.runtime import ProgressEvent

# A traceback that shows local variables would show data: a failing run is reported by `run_local` instead.
app = typer.Typer(
    help="safetwin: safe twins of production data.",
    no_args_is_help=True,
    rich_markup_mode="markdown",
    add_completion=False,
    pretty_exceptions_show_locals=False,
)
engine_app = typer.Typer(
    help="Start, check and stop the engine: the local control API that the browser UI and safetwin talk to.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)


def _show_version(value: bool) -> None:
    if value:
        from importlib.metadata import PackageNotFoundError, version

        try:
            typer.echo(f"safetwin {version('safetwin')}")
        except PackageNotFoundError:
            typer.echo("safetwin (version unknown: not installed as a package)")
        raise typer.Exit()


@app.callback()
def _options(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_show_version, is_eager=True, help="Show the version and exit."),
    ] = False,
) -> None:
    pass


app.command("ui")(ui_command)
app.command("demo")(demo_command)
app.command("scan")(scan_command)
app.command("check")(check_command)
app.command("mask")(mask_command)
app.command("unmask")(unmask_command)
app.command("rekey")(rekey_command)
app.command("export")(export_command)
app.add_typer(key_app, name="key")
app.add_typer(engine_app, name="engine", hidden=True)  # the control API of the engine (not used by `ui`)
runs_app = typer.Typer(
    help="See and cancel the runs of the engine.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
app.add_typer(runs_app, name="runs", hidden=True)


def _report(problems: list[Problem]) -> None:
    for problem in problems:
        level = "ERROR" if problem.severity == "error" else "WARN"
        where = f"{redacted(problem.node_id)}: " if problem.node_id else ""
        typer.echo(f"{level} [{problem.code}] {where}{problem.message}")


def _load(file: Path) -> Pipeline:
    """Load a pipeline file. If it can't be read or is not a pipeline, say why and exit with 1."""
    try:
        return load_pipeline_file(file)
    except SpecError as err:
        _report(err.problems)
        raise typer.Exit(1) from err
    except (OSError, UnicodeDecodeError) as err:
        reason = err.strerror if isinstance(err, OSError) and err.strerror else str(err)
        _report([Problem("error", "file_error", f"cannot read {file}: {reason}")])
        raise typer.Exit(1) from err


@app.command(hidden=True)
def validate(
    # A file that is missing is a usage error (2). The other things that can be wrong with the path (a
    # directory, no permission) are found by reading it, and are reported like any other problem (1).
    file: Annotated[Path, typer.Argument(exists=True, readable=False, help="The pipeline YAML file.")],
) -> None:
    """Check a pipeline file. Exits with 1 if it has errors or can't be read."""
    pipeline = _load(file)
    problems = validate_pipeline(pipeline)
    _report(problems)
    if any(problem.severity == "error" for problem in problems):
        raise typer.Exit(1)
    typer.echo(f"valid ({len(pipeline.spec.nodes)} nodes)")


@app.command(hidden=True)
def schema() -> None:
    """Print the JSON Schema of pipeline files."""
    typer.echo(render_schema(), nl=False)


@app.command("run-local", hidden=True)
def run_local(
    file: Annotated[Path, typer.Argument(exists=True, readable=False, help="The pipeline YAML file.")],
    socket: Annotated[
        list[str] | None,
        typer.Option(
            "--socket", metavar="ALIAS=FOLDER", help="The folder of a socket. Once for each socket."
        ),
    ] = None,
    path: Annotated[
        Literal["fused", "batch", "hybrid"] | None,
        typer.Option("--path", help="Run every stage this way instead of the way the planner chooses."),
    ] = None,
    memory_limit: Annotated[
        str | None,
        typer.Option(
            "--memory-limit",
            metavar="SIZE",
            help="The memory a stage may use, such as 512MB or 2GB. A stage that uses more is paused at 90% "
            "and stopped at 100%. The steps that DuckDB runs (transform.sql, transform.sort) get 80% of it, "
            "and a step that needs more fails: DuckDB does not spill to disk. Default: a quarter of the "
            "memory of this machine.",
        ),
    ] = None,
) -> None:
    """Run a batch pipeline on this machine, with folders as its sockets.

    For example: safetwin run-local pipeline.yaml --socket inbox=./in --socket outbox=./out

    Prints progress while it runs and, at the end, what each node did, and the size, SHA-256 and path of
    every file written and of the manifest. Exits with 1 if the run fails: then the message never shows
    data, only what went wrong and where. Exits with 130 if it is interrupted (Ctrl-C): the stage that was
    running leaves no file behind.
    """
    from safetwin.dataplane.operators import ConfigError, Unsupported
    from safetwin.dataplane.run import PipelineInvalid, run_pipeline_local
    from safetwin.dataplane.spill import SpillError, parse_size
    from safetwin.dataplane.watchdog import MemoryLimitReached

    folders = _parse_sockets(socket or [])
    try:
        memory_limit_bytes = None if memory_limit is None else parse_size(memory_limit)
    except ValueError as err:
        raise typer.BadParameter(str(err), param_hint="--memory-limit") from None
    pipeline = _load(file)
    try:
        result = run_pipeline_local(
            pipeline,
            folders,
            on_event=_Progress(),
            force_path=path,
            memory_limit_bytes=memory_limit_bytes,
        )
    except PipelineInvalid as err:
        _report(err.problems)
        raise typer.Exit(1) from err
    except (ConfigError, Unsupported, SpillError, MemoryLimitReached) as err:  # these name things, no data
        _fail(str(err))
    except KeyboardInterrupt:
        typer.echo("ERROR the run was interrupted: the stage that was running wrote nothing", err=True)
        raise typer.Exit(130) from None
    except OSError as err:
        _fail(_os_error(err))
    except Exception as err:  # Polars and PyArrow messages can quote a row: say what kind of error, no more
        _fail(f"the run failed with {type(err).__name__} (its message can quote data, so it is not shown)")
    for line in _summary(pipeline, result):
        typer.echo(line)


def _fail(message: str) -> NoReturn:
    typer.echo(f"ERROR {message}", err=True)
    raise typer.Exit(1)


def _os_error(err: OSError) -> str:
    """What an OSError says, without its free text: the reason of the operating system and the file."""
    reason = os.strerror(err.errno) if err.errno else type(err).__name__
    return f"{reason}: {err.filename}" if err.filename else reason


def _parse_sockets(options: list[str]) -> dict[str, Path]:
    folders: dict[str, Path] = {}
    for option in options:
        name, equals, folder = option.partition("=")
        if not equals or not name or not folder:
            raise typer.BadParameter(f"'{option}' is not ALIAS=FOLDER", param_hint="--socket")
        folders[name] = Path(folder)
    return folders


class _Progress:
    """Prints a line to stderr for a progress event, at most one a second."""

    def __init__(self) -> None:
        self._last: float | None = None

    def __call__(self, event: "ProgressEvent") -> None:
        self.show(
            event.stage,
            event.path,
            event.elapsed_s,
            event.rows_per_node,
            event.bytes_written,
            event.memory_bytes,
        )

    def show(
        self,
        stage: int,
        path: str,
        elapsed_s: float,
        rows_per_node: dict[str, int],
        bytes_written: int,
        memory_bytes: int | None,
    ) -> None:
        now = time.monotonic()
        if self._last is not None and now - self._last < 1.0:
            return
        self._last = now
        rows = " → ".join(f"{count:,}" for count in rows_per_node.values())
        memory = "" if memory_bytes is None else f", {memory_bytes / 1e6:,.0f} MB of memory"
        typer.echo(
            f"stage {stage + 1} ({path}) {elapsed_s:.0f}s: "
            f"{rows} rows, {bytes_written:,} bytes written{memory}",
            err=True,
        )


@dataclass(frozen=True)
class _StageView:
    """What the summary shows of a stage, from a local run or from the engine.

    From the engine's history (after a restart), the way a stage ran is not known (None), nor its duration
    if it did not finish, and a stage that did not finish has no manifest.
    """

    path: str | None
    duration_s: float | None
    rows_per_node: dict[str, int]
    files: list[tuple[str, int, str]]  # path, bytes, sha256
    manifest: str | None
    state: str | None = None  # shown for a stage of a run that did not succeed


def _summary(pipeline: Pipeline, result: "RunResult") -> list[str]:
    """The final report: for each stage the rows in and out of each node, then its files and manifest."""
    stages = [
        _StageView(
            stage.path,
            stage.duration_s,
            stage.rows_per_node,
            [(str(file.path), file.bytes, file.sha256) for file in stage.files],
            str(stage.manifest),
        )
        for stage in result.stages
    ]
    operators = {node.id: node.operator for node in pipeline.spec.nodes}
    return _summary_lines(result.run_id, pipeline.metadata.name, operators, stages)


def _summary_lines(
    run_id: str, name: str, operators: dict[str, str], stages: list[_StageView], state: str | None = None
) -> list[str]:
    """The report: a line for the run (with its `state` when it did not succeed), then for each stage the rows
    in and out of each node, its files and its manifest."""
    width = max((len(node_id) for node_id in operators), default=0)
    kind = max((len(operator) for operator in operators.values()), default=0)
    lines = [f"run {run_id} of {name}: " + (f"{len(stages)} stage(s)" if state is None else state)]
    previous: int | None = None  # the rows that left the node before, also across a stage boundary
    for number, stage in enumerate(stages, start=1):
        about = [
            stage.path,
            stage.state,
            None if stage.duration_s is None else f"{stage.duration_s:.2f} s",
        ]
        lines.append(f"stage {number}: {', '.join(part for part in about if part is not None)}".rstrip(": "))
        for node_id, rows in stage.rows_per_node.items():
            funnel = f"{rows:,}" if previous is None else f"{previous:,} → {rows:,}"
            lines.append(f"  {node_id:<{width}}  {operators.get(node_id, '?'):<{kind}}  {funnel}")
            previous = rows
        for path, size, sha256 in stage.files:
            lines.append(f"  wrote {path}")
            lines.append(f"        {size:,} bytes, sha256 {sha256}")
        if stage.manifest is not None:
            lines.append(f"  manifest {stage.manifest}")
    return lines


# --- safetwin engine ----------------------------------------------------------------------------------------
# These commands read the connection file and call the engine with the standard library only
# (safetwin.api.connection and .client): FastAPI and uvicorn are loaded by `safetwin engine start` alone.

START_TIMEOUT_S = 30.0  # the first start after an install can take 3-16 s while macOS checks the files
STOP_TIMEOUT_S = 10.0
NOT_RUNNING = "the engine is not running"

DevOrigin = Annotated[
    list[str] | None,
    typer.Option(
        "--dev-origin",
        metavar="ORIGIN",
        help="Also allow this browser origin, such as the Vite dev server: http://localhost:5173.",
    ),
]


@engine_app.command("start")
def engine_start(
    dev_origin: DevOrigin = None,
    background: Annotated[
        bool, typer.Option("--background", help="Start the engine detached, wait until it answers, and exit.")
    ] = False,
    memory_limit: Annotated[
        str | None,
        typer.Option(
            "--memory-limit",
            metavar="SIZE",
            help="The engine's memory limit, such as 4GB. It is split between the stage workers that may run "
            "at once (2): each stage gets half. Default: a quarter of the memory of this machine.",
        ),
    ] = None,
) -> None:
    """Run the engine on 127.0.0.1 (a random port) until it is stopped.

    Prints "engine running on 127.0.0.1:<port> (pid N)" once it answers. The port and the session token are in
    the connection file (engine.json in the folder of the app), readable only by you. Exits with 1 if an
    engine is already running.
    """
    from safetwin.api.settings import allowed_origins
    from safetwin.memory import parse_size

    origins = dev_origin or []
    try:
        allowed_origins(tuple(origins))
    except ValueError as err:
        raise typer.BadParameter(str(err), param_hint="--dev-origin") from None
    try:
        memory_limit_bytes = None if memory_limit is None else parse_size(memory_limit)
    except ValueError as err:
        raise typer.BadParameter(str(err), param_hint="--memory-limit") from None
    if background:
        _start_in_background(origins, memory_limit)
        return
    from safetwin.api.connection import ConnectionFileError
    from safetwin.api.server import AlreadyRunning, configure_logging, ready_line, run_engine, start_error

    configure_logging()
    try:
        run_engine(
            dev_origins=origins,
            on_ready=lambda info: typer.echo(ready_line(info)),
            memory_limit_bytes=memory_limit_bytes,
        )
    except (AlreadyRunning, ConnectionFileError, OSError) as err:
        _fail(start_error(err))


def _start_in_background(origins: list[str], memory_limit: str | None = None) -> None:
    """Start the engine in a process of its own, detached from this terminal; print its line once up."""
    from safetwin.api.client import EngineError, get_status
    from safetwin.api.connection import (
        ConnectionFileError,
        connection_path,
        ensure_home,
        read_connection_file,
    )
    from safetwin.api.server import ready_line, running_engine

    path = connection_path()
    try:
        ensure_home(path.parent)  # what the engine would refuse, said here (its own output goes nowhere)
    except ConnectionFileError as err:
        _fail(str(err))
    if (found := running_engine(path)) is not None:  # a stale or unsafe file is replaced by the engine
        _fail(f"the engine is already running (pid {found.pid})")
    options = [option for origin in origins for option in ("--dev-origin", origin)]
    if memory_limit is not None:
        options += ["--memory-limit", memory_limit]
    if getattr(sys, "frozen", False):  # a frozen build (M6): the executable is safetwin itself
        command = [sys.executable, "engine", "start", *options]
    else:
        command = [sys.executable, "-m", "safetwin.api.server", *options]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + START_TIMEOUT_S
    while time.monotonic() < deadline:
        if (status := process.poll()) is not None:
            _fail(f"the engine stopped while it was starting (exit status {status}): is one running already?")
        try:
            info = read_connection_file(path)
        except ConnectionFileError:
            info = None
        if info is not None and info.pid == process.pid:
            try:
                get_status(info, timeout=1.0)
            except EngineError:
                pass
            else:
                typer.echo(ready_line(info))
                return
        time.sleep(0.05)
    process.terminate()
    _fail(f"the engine did not answer within {START_TIMEOUT_S:.0f} s, so it was stopped")


def _connection() -> "ConnectionInfo":
    """The info of the connection file, of an engine whose process is there.

    If there is no file, or its pid is gone (a stale file), say the engine is not running and exit with 1:
    the token is never sent to a port that may now belong to another program.
    """
    from safetwin.api.connection import (
        ConnectionFileError,
        connection_path,
        pid_alive,
        read_connection_file,
    )

    try:
        info = read_connection_file(connection_path())
    except ConnectionFileError as err:
        _fail(str(err))
    if info is None:
        typer.echo(NOT_RUNNING)
        raise typer.Exit(1)
    if not pid_alive(info.pid):
        typer.echo(f"{NOT_RUNNING} (its pid {info.pid} is gone: the connection file is stale)")
        raise typer.Exit(1)
    return info


@engine_app.command("status")
def engine_status() -> None:
    """Say whether the engine is running and, if it is, its version, pid, port, uptime and memory.

    Exits with 1 if it is not running.
    """
    from safetwin.api.client import EngineError, EngineNotRunning, get_status

    info = _connection()
    try:
        status = get_status(info)
    except EngineNotRunning as err:
        typer.echo(f"{NOT_RUNNING} ({err}: the connection file is left from an engine that is gone)")
        raise typer.Exit(1) from None
    except EngineError as err:
        _fail(str(err))
    typer.echo(f"engine running on 127.0.0.1:{info.port} (pid {status.pid})")
    typer.echo(f"version: {status.version}")
    typer.echo(f"started: {status.started_at}, up {_duration(status.uptime_s)}")
    typer.echo(f"memory: {status.memory_bytes / 1e6:,.1f} MB ({status.memory_kind})")


@engine_app.command("stop")
def engine_stop() -> None:
    """Stop the engine gracefully and wait (up to 10 s) until its process has ended."""
    from safetwin.api.client import EngineError, EngineNotRunning, request_shutdown
    from safetwin.api.connection import pid_alive

    info = _connection()
    try:
        request_shutdown(info)
    except EngineNotRunning as err:
        typer.echo(f"{NOT_RUNNING} ({err}: the connection file is left from an engine that is gone)")
        raise typer.Exit(1) from None
    except EngineError as err:
        _fail(str(err))
    deadline = time.monotonic() + STOP_TIMEOUT_S
    while pid_alive(info.pid):
        if time.monotonic() > deadline:
            _fail(
                f"the engine (pid {info.pid}) was asked to stop but still runs after {STOP_TIMEOUT_S:.0f} s"
            )
        time.sleep(0.05)
    typer.echo("stopped")


def _duration(seconds: float) -> str:
    """`seconds` as `3h 05m 09s`, `5m 09s` or `9s`."""
    whole = int(seconds)
    hours, rest = divmod(whole, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    return f"{minutes}m {secs:02d}s" if minutes else f"{secs}s"


# --- safetwin run and safetwin runs -------------------------------------------------------------------------
# These talk to a running engine with the standard library (safetwin.api.client) and follow its events with
# the websockets client: no data library is loaded here.

ENGINE_NEEDED = (
    "the engine is not running: start it with `safetwin engine start --background`, "
    "or use `safetwin run-local`"
)
ENDED = ("succeeded", "failed", "cancelled", "interrupted")  # the states a run ends in
RUN_STATES = ("queued", "running", *ENDED)
CANCEL_WAIT_S = (
    30.0  # after Ctrl-C, how long `safetwin run` waits for the engine to say the run was cancelled
)
SUBMIT_WAIT_S = 10.0  # after Ctrl-C during the request that submits a run, how long its answer is waited for
FOLLOW_TIMEOUT_S = 1.0
DEFAULT_RUNS_LISTED = 20  # what `safetwin runs list` shows without --limit (the engine's default too)


def _engine_for_runs() -> "ConnectionInfo":
    """The running engine, or the message that says how to start one, and exit status 1."""
    from safetwin.api.client import EngineError, get_status
    from safetwin.api.connection import (
        ConnectionFileError,
        connection_path,
        pid_alive,
        read_connection_file,
    )

    try:
        info = read_connection_file(connection_path())
    except ConnectionFileError as err:
        _fail(str(err))
    if info is None or not pid_alive(info.pid):
        typer.echo(ENGINE_NEEDED, err=True)
        raise typer.Exit(1)
    try:
        get_status(info)
    except EngineError:
        typer.echo(ENGINE_NEEDED, err=True)
        raise typer.Exit(1) from None
    return info


@app.command("run", hidden=True)
def run(
    file: Annotated[Path, typer.Argument(exists=True, readable=False, help="The pipeline YAML file.")],
    socket: Annotated[
        list[str] | None,
        typer.Option(
            "--socket", metavar="ALIAS=FOLDER", help="The folder of a socket. Once for each socket."
        ),
    ] = None,
    path: Annotated[
        Literal["fused", "batch", "hybrid"] | None,
        typer.Option("--path", help="Run every stage this way instead of the way the planner chooses."),
    ] = None,
    memory_limit: Annotated[
        str | None,
        typer.Option(
            "--memory-limit",
            metavar="SIZE",
            help="The memory a stage may use, such as 512MB. It can only lower the share each stage gets "
            "from the engine's limit.",
        ),
    ] = None,
) -> None:
    """Run a batch pipeline in the engine, with folders as its sockets, and follow it.

    For example: safetwin run pipeline.yaml --socket inbox=./in --socket outbox=./out

    It needs a running engine (safetwin engine start --background). It prints progress while the run goes and,
    at the end, the same report as safetwin run-local. Exits with 1 if the run fails (one ERROR line, which
    never shows data), and with 130 on Ctrl-C, after asking the engine to cancel the run.
    """
    from safetwin.memory import parse_size

    folders = {alias: os.path.abspath(folder) for alias, folder in _parse_sockets(socket or []).items()}
    if memory_limit is not None:
        try:
            parse_size(memory_limit)
        except ValueError as err:
            raise typer.BadParameter(str(err), param_hint="--memory-limit") from None
    info = _engine_for_runs()
    request: dict[str, Any] = {"pipeline_path": os.path.abspath(file), "sockets": folders}
    if memory_limit is not None:
        request["memory_limit"] = memory_limit
    if path is not None:
        request["path"] = path
    events = _EventStream(info)  # before the run is submitted, so that none of its events is missed
    try:
        status, answer = _submit(info, request)
        if status != 202 or not isinstance(answer, dict):
            _refused(status, answer)
        run_id = str(answer["run_id"])
        try:
            record = events.follow(run_id)
        except KeyboardInterrupt:
            _cancel_and_exit(info, run_id)
    finally:
        events.close()
    _report_run(record)


def _submit(info: "ConnectionInfo", request: dict[str, Any]) -> tuple[int, Any]:
    """`POST /v1/runs`, on a thread of its own, so that a Ctrl-C while it is under way can still cancel the
    run if the engine accepted it. Exits with 1 if the request fails.

    After a Ctrl-C the answer is waited for, for `SUBMIT_WAIT_S` at most (more Ctrl-C do not cut that short:
    a run that the engine accepted must not be left running), and then:

    - the engine accepted the run: it is cancelled (`_cancel_and_exit`);
    - it refused it, or nothing was listening: "no run was started", exit 130;
    - no answer came, or the request failed otherwise: the engine may have accepted it, so say where to
      look, exit 130.
    """
    from safetwin.api.client import EngineError, EngineNotRunning, call_json

    outcome: list[tuple[int, Any] | Exception] = []
    done = threading.Event()  # not Thread.join: a join cut short by Ctrl-C may not wait properly again

    def post() -> None:
        try:
            outcome.append(call_json(info, "POST", "/v1/runs", request))
        except Exception as err:  # said by its type below: its text is not shown
            outcome.append(err)
        finally:
            done.set()

    threading.Thread(target=post, name="safetwin-submit", daemon=True).start()
    try:
        while not done.wait(0.1):
            pass
    except KeyboardInterrupt:
        deadline = time.monotonic() + SUBMIT_WAIT_S
        while not done.is_set() and time.monotonic() < deadline:
            with suppress(KeyboardInterrupt):  # a second Ctrl-C: keep waiting, the run may need cancelling
                done.wait(max(0.0, deadline - time.monotonic()))
        answer = outcome[0] if outcome else None
        if isinstance(answer, tuple) and answer[0] == 202 and _run_id(answer[1]) is not None:
            _cancel_and_exit(info, str(_run_id(answer[1])))
        refused = isinstance(answer, tuple) and answer[0] != 202
        if refused or isinstance(answer, EngineNotRunning):  # refused, or nothing was listening
            typer.echo("ERROR interrupted before the engine accepted the run: no run was started", err=True)
        else:
            typer.echo(
                "ERROR interrupted before the engine answered: the engine may have accepted the run: check "
                "`safetwin runs show` or `GET /v1/runs`",
                err=True,
            )
        raise typer.Exit(130) from None
    result = outcome[0] if outcome else None
    if isinstance(result, EngineError):
        _fail(str(result))
    if not isinstance(result, tuple):
        _fail(f"the request to the engine failed ({type(result).__name__})")
    if result[0] == 202 and _run_id(result[1]) is None:
        _fail("the engine accepted the run but did not say its id")
    return result


def _run_id(answer: Any) -> str | None:
    """The run id of an answer to `POST /v1/runs`, if it has one."""
    run_id = answer.get("run_id") if isinstance(answer, dict) else None
    return run_id if isinstance(run_id, str) else None


def _refused(status: int, answer: Any) -> NoReturn:
    """Say why the engine did not accept a run, and exit with 1."""
    error = answer.get("error") if isinstance(answer, dict) else None
    if status == 422 and error == "invalid_pipeline":
        for problem in answer.get("problems", []):
            level = "ERROR" if problem.get("severity") == "error" else "WARN"
            where = str(problem.get("path") or "")
            node = where[len("spec.nodes[") : -1] + ": " if where.startswith("spec.nodes[") else ""
            typer.echo(f"{level} [{problem.get('code')}] {node}{problem.get('message')}")
        raise typer.Exit(1)
    reasons = {
        "pipeline_not_found": "the engine can't find the pipeline file",
        "pipeline_unreadable": "the engine can't read the pipeline file",
        "pipeline_too_large": "the pipeline file is too large",
        "shutting_down": "the engine is stopping",
    }
    if error in reasons:
        _fail(reasons[str(error)])
    if status == 422 and isinstance(answer, dict):
        where = ", ".join(
            ".".join(str(part) for part in item.get("loc", [])[1:]) for item in answer["problems"]
        )
        _fail(f"the engine refused the request ({where or 'invalid'})")
    _fail(f"the engine answered {status} to the run request")


class _EventStream:
    """The engine's events, for one run. If the stream closes (the engine is busy: 1013, or it was too far
    behind), the state of the run is polled instead."""

    def __init__(self, info: "ConnectionInfo") -> None:
        from websockets.sync.client import connect

        self._info = info
        self._progress = _Progress()
        self._stack = ExitStack()
        self._socket: Any = None
        try:
            self._socket = self._stack.enter_context(
                connect(
                    f"ws://127.0.0.1:{info.port}/v1/events", open_timeout=5, close_timeout=1, max_size=1 << 20
                )
            )
            self._socket.send(info.token)
            hello = json.loads(self._socket.recv(timeout=5))
            if hello.get("type") != "hello":
                self.close()
        except Exception:  # no events: the run is polled instead
            self.close()

    def close(self) -> None:
        self._socket = None
        with suppress(Exception):
            self._stack.close()

    def follow(self, run_id: str) -> dict[str, Any]:
        """Print the run's progress until it ends; then its record, from the engine."""
        from safetwin.api.client import EngineError, get_run

        ending = {"run.finished", "run.failed", "run.cancelled"}
        while self._socket is not None:
            try:
                raw = self._socket.recv(timeout=FOLLOW_TIMEOUT_S)
            except TimeoutError:
                continue
            except Exception:  # closed: poll from here on
                self.close()
                break
            event = json.loads(raw)
            data = event.get("data") or {}
            if data.get("run_id") != run_id:
                continue
            if event.get("type") == "stage.progress":
                self._progress.show(
                    int(data["stage"]),
                    str(data["path"]),
                    float(data["elapsed_s"]),
                    dict(data["rows_per_node"]),
                    int(data["bytes_written"]),
                    data.get("memory_bytes"),
                )
            elif event.get("type") in ending:
                break
        while True:
            try:
                record = get_run(self._info, run_id)
            except EngineError as err:
                _fail(str(err))
            if record is None:
                _fail("the engine has forgotten the run")
            if record["state"] in ENDED:
                return record
            time.sleep(0.25)


def _cancel_and_exit(info: "ConnectionInfo", run_id: str) -> NoReturn:
    """After Ctrl-C: ask the engine to cancel the run, wait for it to end, and report how it really ended.

    Cancelled: the cancelled line, exit 130. It may have ended otherwise before the cancel arrived (409, or
    its last stage was done): succeeded, the usual report and exit 0; failed, its ERROR line and exit 1. If
    the end can't be seen (the engine can't be reached, it no longer knows the run, or it takes too long),
    say so and exit 1.
    """
    from safetwin.api.client import EngineError, cancel_run, get_run

    record: dict[str, Any] | None = None
    try:
        status, _ = cancel_run(info, run_id)
        if status in (202, 409):
            deadline = time.monotonic() + CANCEL_WAIT_S
            while time.monotonic() < deadline:
                found = get_run(info, run_id)
                if found is None:
                    break
                if found["state"] in ENDED:
                    record = found
                    break
                time.sleep(0.1)
    except (EngineError, KeyboardInterrupt):
        record = None
    if record is None:
        _fail(f"the cancel could not be confirmed: check `safetwin runs show {run_id}`")
    if record["state"] == "cancelled":
        typer.echo("ERROR the run was cancelled: the stage that was running wrote nothing", err=True)
        raise typer.Exit(130)
    _report_run(record)
    raise typer.Exit(0)


def _run_error(record: dict[str, Any]) -> str:
    """The one line that says why a run failed, from the engine's safe error."""
    if record.get("state") == "interrupted":
        return "the run was interrupted: the engine stopped before the run ended"
    if record.get("error"):
        return str(record["error"])
    if record.get("error_class"):
        return f"the run failed with {record['error_class']} (its message can quote data, so it is not shown)"
    return "the run failed"


def _remote_summary(record: dict[str, Any], *, with_state: bool = False) -> list[str]:
    """The report of a run from the engine: as `safetwin run-local` prints it, or (`with_state`, for a run
    that did not succeed) with the state of the run and of each stage."""
    stages = record["stages"]
    operators = {
        node_id: operator
        for stage in stages
        for node_id, operator in zip(stage["node_ids"], stage["operators"], strict=True)
    }
    views = [
        _StageView(
            None if stage.get("path") is None else str(stage["path"]),
            None if stage.get("duration_s") is None else float(stage["duration_s"]),
            dict(stage["rows_per_node"]),
            [(str(f["path"]), int(f["bytes"]), str(f["sha256"])) for f in stage["files"]],
            None if stage.get("manifest") is None else str(stage["manifest"]),
            str(stage["state"]) if with_state else None,
        )
        for stage in stages
    ]
    state = str(record["state"]) if with_state else None
    return _summary_lines(str(record["run_id"]), str(record["pipeline"]), operators, views, state)


def _report_run(record: dict[str, Any]) -> None:
    """The end of `safetwin run`: the summary (exit 0), or one ERROR line (exit 1, or 130 if cancelled)."""
    if record["state"] == "succeeded":
        for line in _remote_summary(record):
            typer.echo(line)
        return
    if record["state"] == "cancelled":
        typer.echo("ERROR the run was cancelled", err=True)
        raise typer.Exit(130)
    _fail(_run_error(record))


@runs_app.command("show")
def runs_show(run_id: Annotated[str, typer.Argument(help="The id of the run, such as r1a2b3c4d.")]) -> None:
    """Show a run from the engine's history: the report of `safetwin run` if it succeeded, else the same with
    the state of the run and of each stage, and its error class.

    The engine's own message for an error is shown while the run is in its memory (it is never written to the
    history). It needs a running engine.
    """
    from safetwin.api.client import EngineError, get_run

    info = _engine_for_runs()
    try:
        record = get_run(info, run_id)
    except EngineError as err:
        _fail(str(err))
    if record is None:
        _fail("the engine has no run with that id")
    for line in _show_lines(record):
        typer.echo(line)


def _show_lines(record: dict[str, Any]) -> Iterable[str]:
    if record["state"] == "succeeded":
        yield from _remote_summary(record)
        return
    yield from _remote_summary(record, with_state=True)
    if record.get("error_class"):
        yield f"error_class: {record['error_class']}"
    if record["state"] in ("failed", "interrupted"):
        yield f"error: {_run_error(record)}"


@runs_app.command("list")
def runs_list(
    limit: Annotated[
        int, typer.Option("--limit", min=1, max=100, help="How many runs to show (1 to 100).")
    ] = DEFAULT_RUNS_LISTED,
    pipeline: Annotated[
        str | None, typer.Option("--pipeline", metavar="ID", help="Only the runs of this pipeline.")
    ] = None,
    state: Annotated[
        str | None,
        typer.Option(
            "--state", metavar="STATE", help=f"Only the runs in this state: {', '.join(RUN_STATES)}."
        ),
    ] = None,
    before: Annotated[
        str | None,
        typer.Option(
            "--before",
            metavar="RUN_ID",
            help="Only the runs older than this one: the next page, as the hint under a full page says.",
        ),
    ] = None,
) -> None:
    """List the runs in the engine's history, newest first: id, pipeline, state, start (UTC), duration, and
    the rows and bytes they wrote. When the page is full, a last line says how to get the next one
    (`--before`). It needs a running engine."""
    from safetwin.api.client import EngineError, list_runs

    if state is not None and state not in RUN_STATES:
        raise typer.BadParameter(f"one of {', '.join(RUN_STATES)}", param_hint="--state")
    info = _engine_for_runs()
    try:
        status, answer = list_runs(info, limit=limit, before=before, pipeline=pipeline, state=state)
    except EngineError as err:
        _fail(str(err))
    if status == 422 and isinstance(answer, dict):
        problems = answer.get("problems", [])
        if any(item.get("type") == "unknown_run" for item in problems):
            _fail("the engine has no run with the id given to --before")
        where = ", ".join(".".join(str(part) for part in item.get("loc", [])[1:]) for item in problems)
        _fail(f"the engine refused the request ({where or 'invalid'})")
    if status != 200 or not isinstance(answer, dict):
        _fail(f"the engine answered {status} to the request for its runs")
    for line in _run_table(answer["runs"]):
        typer.echo(line)
    next_before = answer.get("next_before")
    if isinstance(next_before, str) and next_before:
        typer.echo(f"more: {_next_page(next_before, limit, pipeline, state)}")


def _next_page(next_before: str, limit: int, pipeline: str | None, state: str | None) -> str:
    """The command that lists the next page: the same filters, older than `next_before`."""
    words = ["safetwin", "runs", "list", "--before", next_before]
    if limit != DEFAULT_RUNS_LISTED:
        words += ["--limit", str(limit)]
    if pipeline is not None:
        words += ["--pipeline", pipeline]
    if state is not None:
        words += ["--state", state]
    return " ".join(shlex.quote(word) for word in words)


def _run_table(runs: list[dict[str, Any]]) -> list[str]:
    """The runs as a table with a header, its columns as wide as their widest cell."""
    if not runs:
        return ["no runs"]
    rows = [("RUN", "PIPELINE", "STATE", "STARTED (UTC)", "DURATION", "ROWS", "BYTES")]
    for run in runs:
        totals = run.get("totals") or {}
        rows.append(
            (
                str(run["run_id"]),
                str(run["pipeline"]),
                str(run["state"]),
                _when(run.get("started_at")),
                _took(run.get("started_at"), run.get("finished_at")),
                f"{int(totals.get('rows', 0)):,}",
                f"{int(totals.get('bytes', 0)):,}",
            )
        )
    widths = [max(len(row[column]) for row in rows) for column in range(len(rows[0]))]
    right = {4, 5, 6}  # the numbers are aligned to the right
    return [
        "  ".join(
            cell.rjust(widths[column]) if column in right else cell.ljust(widths[column])
            for column, cell in enumerate(row)
        ).rstrip()
        for row in rows
    ]


def _when(moment: str | None) -> str:
    """`2026-10-02T09:30:00.123Z` as `2026-10-02 09:30:00`; `-` if there is none."""
    return "-" if not moment else moment[:19].replace("T", " ")


def _took(started: str | None, finished: str | None) -> str:
    """How long a run took (`0.6s`, `5m 09s`), `-` if it has not started or ended."""
    from datetime import datetime

    if not started or not finished:
        return "-"
    seconds = (datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds()
    return f"{seconds:.1f}s" if seconds < 60 else _duration(seconds)


@runs_app.command("cancel")
def runs_cancel(run_id: Annotated[str, typer.Argument(help="The id of the run, such as r1a2b3c4d.")]) -> None:
    """Cancel a run of the running engine. Exits with 1 if it has ended already or there is no such run."""
    from safetwin.api.client import EngineError, cancel_run

    info = _engine_for_runs()
    try:
        status, answer = cancel_run(info, run_id)
    except EngineError as err:
        _fail(str(err))
    if status == 404:
        _fail("the engine has no run with that id")
    if status == 409:
        _fail("the run has ended already")
    if status != 202 or not isinstance(answer, dict):
        _fail(f"the engine answered {status} to the cancel request")
    typer.echo(f"run {answer['run_id']}: {answer['state']}")
