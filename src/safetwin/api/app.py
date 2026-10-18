"""The control API app (docs/internals.md): FastAPI behind one guard that makes every security check.

`create_app` returns a `Guard`, a plain ASGI app that wraps the FastAPI app. The guard is the only middleware,
so the order of the checks is the order of the code in `Guard.__call__`:

HTTP requests:

1. **Host** must be exactly `127.0.0.1:<port>` or `localhost:<port>` (one header), else 400. This blocks DNS
   rebinding: a page of evil.com that has made its name point at 127.0.0.1 still sends `Host: evil.com`.
2. **CORS preflight** (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) carries no token. It is
   answered here, never by a route: 204 with the CORS headers and no body for an allowed origin that asks for
   an allowed method and headers, 403 for any other.
3. **Origin**, when there is one, must be an allowed origin, else 403. A request with no Origin (the CLI)
   goes on: the token decides.
4. **Token**: `Authorization: Bearer <token>`, compared with `hmac.compare_digest`, else 401. Never from a
   cookie or the query string.
5. **Body**: at most `MAX_BODY_BYTES` (1 MiB), else 413, and within `BODY_TIMEOUT_S`, else 408. It is read
   here, whole, before a route sees it.
6. The FastAPI app. Responses to an allowed origin get `Access-Control-Allow-Origin` (credentials stay off).
   An error that escapes a route is answered with 500 `{"error": "internal"}` (an `Exception` handler of the
   app; the guard answers the same if a response was not started) and logged once, by the guard, as its type
   only (its message could quote data). FastAPI's own telemetry is off (`TELEMETRY_OFF`).

WebSocket connections (`/v1/events`): Host and Origin are checked here before the socket is accepted (a
failure closes it unaccepted, which the server answers with 403). A missing Origin is allowed, because clients
outside a browser send none. The route then accepts the socket, takes the token as the first message (within
`TOKEN_TIMEOUT_S`) and closes with 1008, saying nothing more, if it is wrong, late or not text. The close
codes a client sees, and what it should do:

- **1008** (policy violation): the token was wrong, late or not text. A token problem: retrying with the same
  token will not help; read the connection file again.
- **1013** (try again later): the engine is busy, not refusing the client: its pending socket was evicted by
  newer connections before it sent the token (`events.Hub`), every authenticated slot is taken, or it fell
  too far behind the events. Retry with backoff.
- **1001** (going away): the engine is stopping.

Runs (`/v1/runs`, T5b and T5c): `POST /v1/runs` queues a run of a pipeline (a file the engine reads itself,
or its text) with folders as its sockets, and answers 202 with the run's id; `POST /v1/runs/{run_id}/cancel`
cancels one (409 if it has ended). The executor (`safetwin.executor`) runs them in stage workers, and their
events go to the WebSocket clients. The history is the metadata database (`executor.history`):

- `GET /v1/runs` lists runs, newest first, with what each wrote. Query: `limit` (1 to 100, default 20),
  `before` (a run id: the page after that run; `next_before` in an answer that may have more), `pipeline` (a
  pipeline id) and `state`. Any other parameter, or one given twice, is a 422 too.
- `GET /v1/runs/{run_id}` shows one, with its stages, the rows of each node, the bytes, the files with their
  size and SHA-256, and its `error_class`; and the engine's safe message (`error`) while the run is in its
  memory (messages are never written to the database).

Both read the database and add the latest progress of a run that is going. Errors stay fixed: an unknown run,
or a pipeline file that is not there, is a 404 that does not repeat the id or the path.

Every error is a fixed JSON object such as `{"error": "unauthorized"}`: no header, body or value the client
sent is ever repeated, and FastAPI's 422 (which repeats the input) is replaced by field locations and error
types only. `/docs` and `/redoc` are off, and `/openapi.json` needs the token like any route.
"""

import asyncio
import hmac
import json
import logging
import os
import stat
import time
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Annotated, Any, Final, Literal, Self

from fastapi import BackgroundTasks, FastAPI, Query, Request, WebSocket
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.telemetry import TelemetryConfig
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocketDisconnect

from safetwin.executor.executor import Executor, ExecutorClosed, QueueFull, RunEnded, RunNotFound
from safetwin.executor.store import (
    PIPELINE_ID_PATTERN,
    RUN_ID_PATTERN,
    RunRecord,
    RunState,
    RunSummary,
    UnknownCursor,
)
from safetwin.memory import memory_sampler, parse_size
from safetwin.spec import Problem, SpecError, find_secrets, load_pipeline_text, redacted
from safetwin.spec import validate_pipeline as validate_spec

from . import events
from .events import Event, Hub, Pending, Subscriber
from .settings import BODY_TIMEOUT_S, HEARTBEAT_S, MAX_BODY_BYTES, MAX_WS_MESSAGE_BYTES, TOKEN_TIMEOUT_S

_log = logging.getLogger(__name__)

ALLOWED_METHODS: Final = ("GET", "POST")
ALLOWED_HEADERS: Final = ("Authorization", "Content-Type")
PREFLIGHT_MAX_AGE_S: Final = 600
WS_POLICY_VIOLATION: Final = 1008
WS_GOING_AWAY: Final = 1001
WS_TRY_AGAIN_LATER: Final = 1013

_ERRORS: Final = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    408: "request_timeout",
    409: "conflict",
    413: "body_too_large",
    422: "invalid_request",
    500: "internal",
    503: "unavailable",
}
MAX_RUNS_LISTED: Final = 100
DEFAULT_RUNS_LISTED: Final = 20
RUNS_QUERY: Final = frozenset({"limit", "before", "pipeline", "state"})
_SECURITY_HEADERS: Final = [(b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff")]
_REPEATED: Final = object()  # a header that was sent more than once


def engine_version() -> str:
    """The version of the installed engine package."""
    try:
        return version("safetwin")
    except PackageNotFoundError:
        return "unknown"


def create_app(
    token: str,
    port: int,
    allowed_origins: Iterable[str],
    *,
    on_shutdown: Callable[[], object] | None = None,
    heartbeat_s: float = HEARTBEAT_S,
    hub: Hub | None = None,
    executor: Executor | None = None,
) -> "Guard":
    """The control API, guarded as the module docs say.

    `token` is the session token, `port` the port the engine listens on (for the Host check), and
    `allowed_origins` the browser origins it answers (`settings.allowed_origins`). `on_shutdown` is called
    after the response to `POST /v1/shutdown` has been sent. `heartbeat_s` is how often each WebSocket gets a
    heartbeat (tests pass a short one). `hub` is the hub of the WebSocket clients (a new one if None).
    `executor` runs the runs of `/v1/runs` (without one, those routes answer 503); its events go to the hub.
    """
    hub = Hub() if hub is None else hub
    bridge = EventBridge(hub)
    if executor is not None:
        executor.set_event_sink(bridge)
    state = _State(
        token=token.encode(),
        version=engine_version(),
        pid=os.getpid(),
        started=time.monotonic(),
        started_at=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        heartbeat_s=heartbeat_s,
        hub=hub,
        on_shutdown=on_shutdown,
        executor=executor,
    )
    return Guard(
        _build_api(state), token=token, port=port, allowed_origins=allowed_origins, hub=hub, bridge=bridge
    )


class EventBridge:
    """Hands events from any thread (the executor's) to the hub, on the event loop of the server.

    The hub runs on the loop alone, so an event goes over with `loop.call_soon_threadsafe`, which keeps the
    order in which they were sent. The loop is the one the guard runs on (`bind`, at every request). Until
    there is one, or once it is closed, events are dropped: nobody could receive them.
    """

    def __init__(self, hub: Hub) -> None:
        self._hub = hub
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def __call__(self, kind: str, data: dict[str, Any]) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        with suppress(RuntimeError):  # the loop closed in between
            loop.call_soon_threadsafe(self._hub.publish, Event(kind, data))


@dataclass(frozen=True)
class _State:
    token: bytes = field(repr=False)
    version: str
    pid: int
    started: float  # time.monotonic()
    started_at: str
    heartbeat_s: float
    hub: Hub
    on_shutdown: Callable[[], object] | None
    executor: Executor | None = None

    def uptime(self) -> float:
        return time.monotonic() - self.started


# --- the guard ---------------------------------------------------------------------------------------------


class Guard:
    """The ASGI app the server runs: every check of the module docs, in order, then the FastAPI app."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        token: str,
        port: int,
        allowed_origins: Iterable[str],
        hub: Hub,
        bridge: EventBridge | None = None,
    ) -> None:
        self.app = app
        self.hub = hub
        self._bridge = bridge
        self._token = token.encode()
        self._hosts = frozenset({f"127.0.0.1:{port}".encode(), f"localhost:{port}".encode()})
        self._origins = frozenset(origin.encode() for origin in allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self._bridge is not None:
            self._bridge.bind(asyncio.get_running_loop())
        if scope["type"] == "http":
            await self._http(scope, receive, send)
        elif scope["type"] == "websocket":
            await self._websocket(scope, receive, send)
        elif scope["type"] == "lifespan":
            await self.app(scope, receive, send)

    async def _http(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = scope["headers"]
        # 1. Host
        if _single(headers, b"host") not in self._hosts:
            await _error(send, 400, "bad_host")
            return
        origin = _single(headers, b"origin")
        cors = (
            [(b"access-control-allow-origin", origin), (b"vary", b"Origin")] if self._allowed(origin) else []
        )
        # 2. CORS preflight: answered here, it never reaches a route
        if (
            scope["method"] == "OPTIONS"
            and origin is not None
            and _has(headers, b"access-control-request-method")
        ):
            if cors and _preflight_asks_for_allowed(headers):
                await _preflight_ok(send, cors)
            else:
                await _error(send, 403, "forbidden_origin")
            return
        # 3. Origin
        if origin is not None and not cors:
            await _error(send, 403, "forbidden_origin")
            return
        # 4. Token
        if not self._token_ok(_single(headers, b"authorization")):
            await _error(send, 401, "unauthorized", cors)
            return
        # 5. Body
        body = await _read_body(scope, receive)
        if isinstance(body, int):
            if body:
                await _error(send, body, _ERRORS[body], cors)
            return  # 0: the client went away
        # 6. The app
        await self._call_app(scope, _replay(body, receive), send, cors)

    async def _websocket(self, scope: Scope, receive: Receive, send: Send) -> None:
        headers = scope["headers"]
        origin = _single(headers, b"origin")
        if _single(headers, b"host") not in self._hosts or (origin is not None and not self._allowed(origin)):
            message = await receive()  # websocket.connect
            if message["type"] == "websocket.connect":
                await send({"type": "websocket.close", "code": WS_POLICY_VIOLATION})
            return
        await self._call_app(scope, receive, send, [])

    def _allowed(self, origin: Any) -> bool:
        return isinstance(origin, bytes) and origin in self._origins

    def _token_ok(self, authorization: Any) -> bool:
        if not isinstance(authorization, bytes) or authorization[:7].lower() != b"bearer ":
            return False
        return hmac.compare_digest(authorization[7:].strip(), self._token)

    async def _call_app(
        self, scope: Scope, receive: Receive, send: Send, cors: list[tuple[Any, bytes]]
    ) -> None:
        started = False

        async def send_with_headers(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message = {**message, "headers": [*message.get("headers", []), *_SECURITY_HEADERS, *cors]}
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception as err:  # the message could quote data: only the type is logged
            _log.error("a request failed with %s", type(err).__name__)
            if scope["type"] == "http" and not started:
                await _error(send, 500, "internal", cors)


def _single(headers: Iterable[tuple[bytes, bytes]], name: bytes) -> Any:
    """The value of header `name`: None if it is missing, `_REPEATED` if it was sent more than once."""
    found = [value for key, value in headers if key == name]
    if not found:
        return None
    return found[0] if len(found) == 1 else _REPEATED


def _has(headers: Iterable[tuple[bytes, bytes]], name: bytes) -> bool:
    return any(key == name for key, _ in headers)


def _preflight_asks_for_allowed(headers: Iterable[tuple[bytes, bytes]]) -> bool:
    method = _single(headers, b"access-control-request-method")
    wanted = _single(headers, b"access-control-request-headers")
    if not isinstance(method, bytes) or method.decode("latin-1") not in ALLOWED_METHODS:
        return False
    if wanted is None:
        return True
    if not isinstance(wanted, bytes):
        return False
    allowed = {name.lower() for name in ALLOWED_HEADERS}
    asked = {name.strip().lower() for name in wanted.decode("latin-1").split(",") if name.strip()}
    return asked <= allowed


async def _preflight_ok(send: Send, cors: list[tuple[Any, bytes]]) -> None:
    headers = [
        *cors,
        (b"access-control-allow-methods", ", ".join(ALLOWED_METHODS).encode()),
        (b"access-control-allow-headers", ", ".join(ALLOWED_HEADERS).encode()),
        (b"access-control-max-age", str(PREFLIGHT_MAX_AGE_S).encode()),
        (b"content-length", b"0"),
        *_SECURITY_HEADERS,
    ]
    await send({"type": "http.response.start", "status": 204, "headers": headers})
    await send({"type": "http.response.body", "body": b""})


async def _error(send: Send, status: int, error: str, extra: list[tuple[Any, bytes]] | None = None) -> None:
    """A fixed error response: `{"error": error}`."""
    body = json.dumps({"error": error}).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        *_SECURITY_HEADERS,
        *(extra or []),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _read_body(scope: Scope, receive: Receive) -> bytes | int:
    """The whole body, or a status: 413 if it is over the cap, 400 for a bad Content-Length, 408 if it takes
    longer than `BODY_TIMEOUT_S` to arrive, 0 if the client went away."""
    length = _single(scope["headers"], b"content-length")
    if length is not None:
        if not isinstance(length, bytes) or not length.isdigit():
            return 400
        if int(length) > MAX_BODY_BYTES:
            return 413
    try:
        async with asyncio.timeout(BODY_TIMEOUT_S):
            return await _receive_body(receive)
    except TimeoutError:
        return 408


async def _receive_body(receive: Receive) -> bytes | int:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return 0
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            return 413
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)


def _replay(body: bytes, receive: Receive) -> Receive:
    """A `receive` that gives the body that was read, then whatever the client sends next (a disconnect)."""
    sent = False

    async def replayed() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return replayed


# --- the routes --------------------------------------------------------------------------------------------


class RunsStatusOut(BaseModel):
    """The runs and the stage workers of the engine, now."""

    active: int
    queued: int
    workers_running: int
    workers_idle: int
    memory_limit_bytes: int  # the engine's global limit, split between the stage workers that may run


class StatusOut(BaseModel):
    version: str
    pid: int
    started_at: str
    uptime_s: float
    memory_bytes: int
    memory_kind: Literal["phys_footprint", "rss"]
    runs: RunsStatusOut | None  # None without an executor


class RunIn(BaseModel):
    """`POST /v1/runs`: a pipeline (a file or its text: exactly one), the folders of its sockets, options."""

    model_config = ConfigDict(extra="forbid")

    pipeline_path: str | None = None  # absolute; the engine reads it itself
    pipeline_yaml: str | None = None
    sockets: dict[str, str] = Field(default_factory=dict)  # alias or socket URI -> absolute folder
    memory_limit: str | None = None  # such as 512MB: can make a stage's share smaller, never larger
    path: Literal["fused", "batch", "hybrid"] | None = None

    @model_validator(mode="after")
    def _one_pipeline(self) -> Self:
        if (self.pipeline_path is None) == (self.pipeline_yaml is None):
            raise ValueError("give exactly one of pipeline_path and pipeline_yaml")
        return self


class RunAccepted(BaseModel):
    run_id: str
    state: str


class RunsOut(BaseModel):
    runs: list[RunSummary]
    next_before: str | None = None  # the `before` of the next page, when this one is full


class ShutdownOut(BaseModel):
    status: Literal["shutting_down"]


class ProblemOut(BaseModel):
    severity: Literal["error", "warning"]
    code: str
    message: str
    path: str | None  # the node, as spec.nodes[<id>], when the problem is about one


class ValidateOut(BaseModel):
    valid: bool
    nodes: int | None  # how many nodes, when the text is a pipeline
    problems: list[ProblemOut]


_VALIDATE_BODY: Final = {
    "requestBody": {
        "required": True,
        "content": {
            "text/plain": {"schema": {"type": "string"}},
            "application/yaml": {"schema": {"type": "string"}},
        },
    }
}


# FastAPI's own OpenTelemetry support, all of it off: no spans, no metrics, no exporters set up from the
# environment, and no logs (which would record exception messages, stack traces and failed request bodies).
# `exclude` skips every request as well, in case a later FastAPI adds a kind that is on by default.
TELEMETRY_OFF: Final[TelemetryConfig] = {
    "tracing": False,
    "metrics": False,
    "logs": False,
    "operation_spans": False,
    "auto_configure": False,
    "exclude": lambda scope: True,
}


def _build_api(state: _State) -> FastAPI:
    api = FastAPI(
        title="safetwin engine",
        version=state.version,
        docs_url=None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=None,
        openapi_url="/openapi.json",
        telemetry=TELEMETRY_OFF,
    )
    api.add_exception_handler(RequestValidationError, _validation_error)  # type: ignore[arg-type]
    api.add_exception_handler(StarletteHTTPException, _http_error)  # type: ignore[arg-type]
    api.add_exception_handler(Exception, _internal_error)
    sample_memory, memory_kind = memory_sampler()

    @api.get("/v1/status")
    async def status() -> StatusOut:
        """The engine: its version, pid, when it started, the memory it holds now, and its runs."""
        executor = state.executor
        runs = None
        if executor is not None:
            counts = await run_in_threadpool(executor.counts)
            runs = RunsStatusOut(
                active=counts["runs_active"],
                queued=counts["runs_queued"],
                workers_running=counts["workers_running"],
                workers_idle=counts["workers_idle"],
                memory_limit_bytes=executor.settings.memory_limit_bytes,
            )
        return StatusOut(
            version=state.version,
            pid=state.pid,
            started_at=state.started_at,
            uptime_s=round(state.uptime(), 3),
            memory_bytes=sample_memory(),
            memory_kind=memory_kind,
            runs=runs,
        )

    @api.post("/v1/shutdown", status_code=202)
    async def shutdown(after: BackgroundTasks) -> ShutdownOut:
        """Stop the engine gracefully: it answers 202, then stops."""
        if state.on_shutdown is not None:
            after.add_task(state.on_shutdown)  # once the answer has been sent
        return ShutdownOut(status="shutting_down")

    @api.post("/v1/validate", openapi_extra=_VALIDATE_BODY)
    async def validate(request: Request) -> ValidateOut:
        """Check pipeline YAML text (the body) as `safetwin validate` does. Problems never quote a value."""
        body = await request.body()
        return await run_in_threadpool(validate_text, body)

    @api.post("/v1/runs", status_code=202, response_model=RunAccepted)
    async def submit_run(body: RunIn) -> Any:
        """Queue a run. 422 with the problems if the pipeline or the request is not valid, 404 if the file is
        not there, 503 `queue_full` if too many runs wait already; 202 with the run's id once it is queued."""
        executor = state.executor
        if executor is None:
            return _fixed(503, "runs_unavailable")
        checked = await run_in_threadpool(check_run_request, body)
        if isinstance(checked, JSONResponse):
            return checked
        text, name, memory_limit_bytes = checked
        try:
            record = await run_in_threadpool(  # the executor's lock is never taken on the event loop
                executor.submit,
                pipeline=name,
                pipeline_yaml=text,
                sockets=body.sockets,
                memory_limit_bytes=memory_limit_bytes,
                path=body.path,
            )
        except ExecutorClosed:
            return _fixed(503, "shutting_down")
        except QueueFull:
            return _fixed(503, "queue_full")
        return RunAccepted(run_id=record.run_id, state=record.state)

    @api.get("/v1/runs", response_model=RunsOut)
    async def list_runs(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=MAX_RUNS_LISTED)] = DEFAULT_RUNS_LISTED,
        before: Annotated[str | None, Query(pattern=RUN_ID_PATTERN)] = None,
        pipeline: Annotated[str | None, Query(pattern=PIPELINE_ID_PATTERN, max_length=256)] = None,
        run_state: Annotated[RunState | None, Query(alias="state")] = None,
    ) -> Any:
        """The runs, newest first, from the history (see the module docs for the query). A 422 says where and
        what kind of problem, never the value."""
        problems = _query_problems(request, RUNS_QUERY)
        if problems:
            return _invalid(*problems)
        executor = state.executor
        if executor is None:
            return RunsOut(runs=[])
        try:
            runs = await run_in_threadpool(  # the database is read on the thread pool
                executor.recent, limit, before=before, pipeline=pipeline, state=run_state
            )
        except UnknownCursor:
            return _invalid((["query", "before"], "unknown_run"))
        return RunsOut(runs=runs, next_before=runs[-1].run_id if len(runs) == limit else None)

    @api.get("/v1/runs/{run_id}", response_model=RunRecord)
    async def show_run(run_id: str) -> Any:
        """One run, with its stages and totals. An unknown id is a fixed 404."""
        record = await run_in_threadpool(state.executor.get, run_id) if state.executor is not None else None
        return _fixed(404, "run_not_found") if record is None else record

    @api.post("/v1/runs/{run_id}/cancel", status_code=202, response_model=RunAccepted)
    async def cancel_run(run_id: str) -> Any:
        """Cancel a run: 202, or 409 if it has ended already. A queued run is cancelled at once."""
        executor = state.executor
        if executor is None:
            return _fixed(404, "run_not_found")
        try:
            record = await run_in_threadpool(executor.cancel, run_id)
        except RunNotFound:
            return _fixed(404, "run_not_found")
        except RunEnded:
            return _fixed(409, "run_ended")
        return RunAccepted(run_id=record.run_id, state="cancelled" if record.ended else "cancelling")

    @api.websocket("/v1/events")
    async def event_stream(websocket: WebSocket) -> None:
        await _serve_events(websocket, state)

    return api


def _fixed(status: int, error: str) -> JSONResponse:
    return JSONResponse({"error": error}, status_code=status)


def _invalid(*problems: tuple[list[str], str]) -> JSONResponse:
    """422 in the shape of FastAPI's own (as `_validation_error` makes it): where, and the kind of error."""
    return JSONResponse(
        {"error": "invalid_request", "problems": [{"loc": loc, "type": kind} for loc, kind in problems]},
        status_code=422,
    )


def _query_problems(request: Request, allowed: frozenset[str]) -> list[tuple[list[str], str]]:
    """A parameter of the query that the route does not take (not named: it is input), or one given twice."""
    query = request.query_params
    problems: list[tuple[list[str], str]] = []
    if any(key not in allowed for key in query):
        problems.append((["query"], "unknown_parameter"))
    problems.extend((["query", key], "repeated") for key in sorted(allowed) if len(query.getlist(key)) > 1)
    return problems


def check_run_request(body: RunIn) -> tuple[str, str, int | None] | JSONResponse:
    """The pipeline text, its name and the memory limit of a run request, or the answer that refuses it.

    Paths must be absolute. The engine reads the pipeline file itself (it runs as the user); a file that is
    not there is a 404 that does not repeat the path. The pipeline is validated as `/v1/validate` does: a
    pipeline with errors is a 422 with its problems, in the same shape.
    """
    bad: list[tuple[list[str], str]] = []
    if body.pipeline_path is not None and not os.path.isabs(body.pipeline_path):
        bad.append((["body", "pipeline_path"], "not_absolute"))
    if any(not os.path.isabs(folder) for folder in body.sockets.values()):
        bad.append((["body", "sockets"], "not_absolute"))
    memory_limit_bytes = None
    if body.memory_limit is not None:
        try:
            memory_limit_bytes = parse_size(body.memory_limit)
        except ValueError:
            bad.append((["body", "memory_limit"], "invalid_size"))
    if bad:
        return _invalid(*bad)
    if body.pipeline_path is not None:
        data = _read_pipeline_file(body.pipeline_path)
        if isinstance(data, JSONResponse):
            return data
    else:
        assert body.pipeline_yaml is not None
        data = body.pipeline_yaml.encode("utf-8")
    answer, name = _validated(data)
    if not answer.valid or name is None:
        return JSONResponse({"error": "invalid_pipeline", **answer.model_dump()}, status_code=422)
    return data.decode("utf-8"), name, memory_limit_bytes


def _read_pipeline_file(path: str) -> bytes | JSONResponse:
    """The bytes of the pipeline file at `path` (at most `MAX_BODY_BYTES`). A FIFO or a device can't hang it:
    it is opened without blocking, and only a regular file is read."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except (FileNotFoundError, NotADirectoryError):
        return _fixed(404, "pipeline_not_found")
    except OSError:
        return _fixed(422, "pipeline_unreadable")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return _fixed(422, "pipeline_unreadable")
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(fd, 65536):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BODY_BYTES:
                return _fixed(413, "pipeline_too_large")
    except OSError:
        return _fixed(422, "pipeline_unreadable")
    finally:
        os.close(fd)
    return b"".join(chunks)


async def _validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
    """422 with where each error is and its type, never the input (FastAPI's own handler repeats it)."""
    problems = [
        {
            "loc": [
                part if isinstance(part, int) else redacted(str(part))[:64] for part in item.get("loc", ())
            ],
            "type": str(item.get("type", "invalid")),
        }
        for item in error.errors()
    ]
    return JSONResponse({"error": "invalid_request", "problems": problems}, status_code=422)


async def _http_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
    allow = {"allow": error.headers["allow"]} if error.headers and "allow" in error.headers else None
    return JSONResponse(
        {"error": _ERRORS.get(error.status_code, f"http_{error.status_code}")},
        status_code=error.status_code,
        headers=allow,
    )


async def _internal_error(request: Request, error: Exception) -> JSONResponse:
    """500 with a fixed body. Starlette raises the error again after this, and the guard logs its type."""
    return JSONResponse({"error": "internal"}, status_code=500)


def validate_text(body: bytes) -> ValidateOut:
    """What `POST /v1/validate` answers for `body`: the problems, as `safetwin validate` reports them.

    The messages are the spec package's, which name nodes, operators, sockets and keys but never repeat a
    value of the file (not even one that pydantic quotes), and redact anything
    that looks like a secret. As a last check, a message in which `find_secrets` still sees a secret is
    replaced by one that says only what kind of problem it was.
    """
    return _validated(body)[0]


def _validated(body: bytes) -> tuple[ValidateOut, str | None]:
    """`validate_text`'s answer, and the name of the pipeline when it is valid."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return _answer(None, [Problem("error", "encoding_error", "the pipeline is not UTF-8 text")]), None
    try:
        pipeline = load_pipeline_text(text)
    except SpecError as err:
        return _answer(None, err.problems), None
    problems = validate_spec(pipeline)
    valid = not any(problem.severity == "error" for problem in problems)
    return _answer(len(pipeline.spec.nodes), problems), pipeline.metadata.name if valid else None


def _answer(nodes: int | None, problems: list[Problem]) -> ValidateOut:
    return ValidateOut(
        valid=not any(problem.severity == "error" for problem in problems),
        nodes=nodes,
        problems=[_problem_out(problem) for problem in problems],
    )


def _problem_out(problem: Problem) -> ProblemOut:
    message = problem.message
    if any(find_secrets(message, "")):
        message = f"a problem of kind {problem.code} (its message is not shown: it may quote a secret)"
    path = f"spec.nodes[{redacted(problem.node_id)}]" if problem.node_id else None
    return ProblemOut(severity=problem.severity, code=problem.code, message=message, path=path)


# --- the WebSocket -----------------------------------------------------------------------------------------


async def _serve_events(websocket: WebSocket, state: _State) -> None:
    """One client of `/v1/events`: the token first, then hello, then events until one side ends."""
    hub = state.hub
    slot = hub.join()
    if slot is None:  # stopping: closed unaccepted
        await websocket.close(code=WS_GOING_AWAY)
        return
    subscriber: Subscriber | None = None
    try:
        await websocket.accept()
        if not await _token_received(websocket, state.token, slot):
            # Evicted by newer connections: the engine is busy, and the client may try again (1013). Any
            # other failure is about the token (1008).
            await websocket.close(code=WS_TRY_AGAIN_LATER if slot.evicted.is_set() else WS_POLICY_VIOLATION)
            return
        subscriber = hub.subscribe(slot)
        if subscriber is None:
            await websocket.close(code=WS_GOING_AWAY if hub.closing else WS_TRY_AGAIN_LATER)
            return
        await websocket.send_text(events.hello(state.version, state.pid, state.heartbeat_s).to_json())
        code = await _pump(websocket, subscriber, state)
        if code is not None:
            await websocket.close(code=code)
    except WebSocketDisconnect:
        pass
    finally:
        hub.leave(slot, subscriber)


async def _token_received(websocket: WebSocket, token: bytes, slot: Pending) -> bool:
    """Whether the first message is the token, as text, within `TOKEN_TIMEOUT_S` and before a newer
    connection evicts this one from its pending slot."""
    receiving = asyncio.ensure_future(websocket.receive())
    evicted = asyncio.ensure_future(slot.evicted.wait())
    try:
        done, _ = await asyncio.wait(
            {receiving, evicted}, timeout=TOKEN_TIMEOUT_S, return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        evicted.cancel()
    if receiving not in done or slot.evicted.is_set():
        if receiving.done() and not receiving.cancelled():
            receiving.exception()  # retrieved, so that asyncio does not log it
        receiving.cancel()
        return False
    message = receiving.result()
    text = message.get("text") if message["type"] == "websocket.receive" else None
    if not isinstance(text, str) or len(text) > MAX_WS_MESSAGE_BYTES:
        return False
    return hmac.compare_digest(text.encode(), token)


async def _pump(websocket: WebSocket, subscriber: Subscriber, state: _State) -> int | None:
    """Send the client its events, and a heartbeat whenever none came for `heartbeat_s`, until it goes away
    (None) or the hub ends it (the close code). What the client sends is read and dropped."""
    reader = asyncio.ensure_future(_drain(websocket))
    try:
        while True:
            getter = asyncio.ensure_future(subscriber.queue.get())
            done, _ = await asyncio.wait(
                {getter, reader}, timeout=state.heartbeat_s, return_when=asyncio.FIRST_COMPLETED
            )
            if reader in done:
                getter.cancel()
                return None
            if getter not in done:
                getter.cancel()
                await websocket.send_text(events.heartbeat(state.uptime()).to_json())
                continue
            item = getter.result()
            if item == events.CLOSE:
                return WS_GOING_AWAY
            if item == events.OVERFLOW:
                return WS_TRY_AGAIN_LATER
            assert isinstance(item, events.Event)
            await websocket.send_text(item.to_json())
    finally:
        reader.cancel()


async def _drain(websocket: WebSocket) -> None:
    """Read what the client sends, and drop it, until it disconnects (or the socket fails)."""
    try:
        while (await websocket.receive())["type"] != "websocket.disconnect":
            pass
    except Exception:  # the socket is gone either way
        return
