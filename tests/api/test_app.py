"""The control API at the ASGI level: every security check of `safetwin.api.app`, and its routes.

HTTP goes through Starlette's TestClient (httpx), except where a request must be one that httpx can't send
(no Host, a header twice, a body in chunks): those drive the ASGI app by hand (`asgi`).
"""

import asyncio
import json
import logging
import os
import secrets
import time
import warnings
from collections.abc import Iterator
from importlib.metadata import version
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.websockets import WebSocketDisconnect

from safetwin.api import events

with warnings.catch_warnings():  # Starlette 1.7 would like httpx2; httpx is what the project allows
    warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient` is deprecated")
    from starlette.testclient import TestClient
from safetwin.api.app import Guard, create_app, validate_text
from safetwin.api.events import Event, Hub
from safetwin.api.server import new_token
from safetwin.api.settings import (
    MAX_BODY_BYTES,
    TOKEN_TIMEOUT_S,
    VITE_DEV_ORIGIN,
    allowed_origins,
)

REPO = Path(__file__).resolve().parents[2]
PORT = 48123
APP_ORIGIN = "http://localhost:8765"  # an origin the engine was told to allow, as the browser UI's will be
TOKEN = new_token()
AUTH = {"Authorization": f"Bearer {TOKEN}"}
BASE = f"http://127.0.0.1:{PORT}"
WS_URL = f"ws://127.0.0.1:{PORT}/v1/events"  # websocket_connect does not use base_url
CSV_CLEAN = (REPO / "tests" / "fixtures" / "csv-clean.yaml").read_bytes()


class Spy:
    """Counts the calls of the shutdown hook and of a test route."""

    def __init__(self) -> None:
        self.shutdowns = 0
        self.route_calls = 0

    def shutdown(self) -> None:
        self.shutdowns += 1


@pytest.fixture
def spy() -> Spy:
    return Spy()


def make_app(spy: Spy | None = None, *, heartbeat_s: float = 5.0, hub: Hub | None = None) -> Guard:
    guard = create_app(
        TOKEN,
        PORT,
        (APP_ORIGIN, VITE_DEV_ORIGIN),
        on_shutdown=spy.shutdown if spy is not None else None,
        heartbeat_s=heartbeat_s,
        hub=hub,
    )
    api = cast(FastAPI, guard.app)

    class Item(BaseModel):
        count: int
        name: str

    @api.post("/v1/test/item", include_in_schema=False)
    async def item(body: Item) -> dict[str, int]:
        if spy is not None:
            spy.route_calls += 1
        return {"count": body.count}

    @api.api_route("/v1/test/spy", methods=["GET", "POST", "OPTIONS"], include_in_schema=False)
    async def spied() -> dict[str, bool]:
        if spy is not None:
            spy.route_calls += 1
        return {"ok": True}

    @api.get("/v1/test/fail", include_in_schema=False)
    async def fail() -> None:
        raise ValueError(f"a library said: {CANARY}")

    return guard


CANARY = f"CANARY-{secrets.token_hex(8)}"


@pytest.fixture
def client(spy: Spy) -> Iterator[TestClient]:
    with TestClient(make_app(spy), base_url=BASE) as made:
        yield made


def error_of(response: Any) -> str:
    body = response.json()
    assert set(body) == {"error"}
    return cast(str, body["error"])


# --- driving the ASGI app by hand --------------------------------------------------------------------------


def asgi(
    app: Guard, method: str, path: str, headers: list[tuple[bytes, bytes]], chunks: list[bytes] | None = None
) -> tuple[int, dict[bytes, bytes], bytes]:
    """Send one HTTP request to `app` and collect the answer: (status, headers, body)."""
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", PORT),
    }
    parts = chunks or [b""]
    incoming = [
        {"type": "http.request", "body": chunk, "more_body": index < len(parts) - 1}
        for index, chunk in enumerate(parts)
    ]
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return incoming.pop(0) if incoming else {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))  # type: ignore[arg-type]
    start = sent[0]
    return start["status"], dict(start["headers"]), b"".join(m.get("body", b"") for m in sent[1:])


def good_headers(**more: str) -> list[tuple[bytes, bytes]]:
    headers = [(b"host", f"127.0.0.1:{PORT}".encode()), (b"authorization", f"Bearer {TOKEN}".encode())]
    return headers + [(name.replace("_", "-").encode(), value.encode()) for name, value in more.items()]


# --- Host ---------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("host", [f"127.0.0.1:{PORT}", f"localhost:{PORT}"])
def test_the_two_loopback_hosts_with_the_port_are_accepted(client: TestClient, host: str) -> None:
    response = client.get("/v1/status", headers={**AUTH, "Host": host})
    assert response.status_code == 200


@pytest.mark.parametrize(
    "host",
    [
        f"127.0.0.1:{PORT + 1}",
        f"localhost:{PORT + 1}",
        "127.0.0.1",
        "localhost",
        "evil.com",
        f"evil.com:{PORT}",
        f"{CANARY}.example:{PORT}",
        f"[::1]:{PORT}",
        f"0.0.0.0:{PORT}",
        f"127.0.0.1:{PORT}.evil.com",
    ],
)
def test_any_other_host_gets_400_with_a_fixed_body(client: TestClient, spy: Spy, host: str) -> None:
    response = client.get("/v1/test/spy", headers={**AUTH, "Host": host})
    assert response.status_code == 400
    assert response.json() == {"error": "bad_host"}
    assert host.encode() not in response.content
    assert spy.route_calls == 0


def test_a_missing_or_repeated_host_gets_400(spy: Spy) -> None:
    app = make_app(spy)
    auth = (b"authorization", f"Bearer {TOKEN}".encode())
    host = (b"host", f"127.0.0.1:{PORT}".encode())
    assert asgi(app, "GET", "/v1/test/spy", [auth])[0] == 400
    assert asgi(app, "GET", "/v1/test/spy", [host, host, auth])[0] == 400
    assert asgi(app, "GET", "/v1/test/spy", [host, auth])[0] == 200
    assert spy.route_calls == 1


def test_the_host_is_checked_before_the_token(client: TestClient) -> None:
    response = client.get("/v1/status", headers={"Host": "evil.com"})
    assert response.status_code == 400


# --- the token ----------------------------------------------------------------------------------------------


def test_the_right_token_is_accepted_and_the_scheme_is_case_insensitive(client: TestClient) -> None:
    assert client.get("/v1/status", headers=AUTH).status_code == 200
    assert client.get("/v1/status", headers={"Authorization": f"bearer {TOKEN}"}).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer "},
        {"Authorization": f"Bearer {new_token()}"},
        {"Authorization": f"Bearer {TOKEN[:-1]}"},
        {"Authorization": f"Bearer {TOKEN}x"},
        {"Authorization": f"Basic {TOKEN}"},
        {"Authorization": TOKEN},
        {"Cookie": f"token={TOKEN}"},
        {"Cookie": f"Authorization=Bearer {TOKEN}"},
        {"X-Token": TOKEN},
    ],
    ids=[
        "none",
        "empty",
        "another",
        "shorter",
        "longer",
        "basic",
        "no-scheme",
        "cookie",
        "cookie-auth",
        "header",
    ],
)
def test_a_missing_or_wrong_token_gets_401_with_a_fixed_body(
    client: TestClient, spy: Spy, headers: dict[str, str]
) -> None:
    response = client.get("/v1/test/spy", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"error": "unauthorized"}
    assert TOKEN.encode() not in response.content
    assert spy.route_calls == 0


def test_a_token_in_the_query_string_is_refused(client: TestClient, spy: Spy) -> None:
    for query in (f"?token={TOKEN}", f"?access_token={TOKEN}", f"?authorization=Bearer%20{TOKEN}"):
        response = client.get(f"/v1/test/spy{query}")
        assert response.status_code == 401
    assert spy.route_calls == 0


def test_a_repeated_authorization_header_is_refused(spy: Spy) -> None:
    app = make_app(spy)
    headers = good_headers(authorization=f"Bearer {TOKEN}")  # twice
    assert asgi(app, "GET", "/v1/test/spy", headers)[0] == 401


# --- Origin and CORS ----------------------------------------------------------------------------------------


def test_a_request_from_an_allowed_origin_gets_the_cors_headers(client: TestClient) -> None:
    for origin in (APP_ORIGIN, VITE_DEV_ORIGIN):
        response = client.get("/v1/status", headers={**AUTH, "Origin": origin})
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin
        assert response.headers["vary"] == "Origin"
        assert "access-control-allow-credentials" not in response.headers


def test_a_request_with_no_origin_needs_only_the_token_and_gets_no_cors_headers(client: TestClient) -> None:
    response = client.get("/v1/status", headers=AUTH)
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(
    "origin", ["https://evil.com", "null", "http://localhost:5174", "http://127.0.0.1:8765", "file://"]
)
def test_a_request_from_another_origin_gets_403_even_with_the_token(
    client: TestClient, spy: Spy, origin: str
) -> None:
    response = client.get("/v1/test/spy", headers={**AUTH, "Origin": origin})
    assert response.status_code == 403
    assert response.json() == {"error": "forbidden_origin"}
    assert "access-control-allow-origin" not in response.headers
    assert spy.route_calls == 0


def test_a_401_to_an_allowed_origin_carries_the_cors_header_so_the_app_can_read_it(
    client: TestClient,
) -> None:
    response = client.get("/v1/status", headers={"Origin": APP_ORIGIN})
    assert response.status_code == 401
    assert response.headers["access-control-allow-origin"] == APP_ORIGIN


def preflight(origin: str, method: str = "POST", headers: str | None = "authorization, content-type") -> dict:
    asked = {"Origin": origin, "Access-Control-Request-Method": method}
    if headers is not None:
        asked["Access-Control-Request-Headers"] = headers
    return asked


@pytest.mark.parametrize("path", ["/v1/test/spy", "/v1/shutdown", "/v1/status", "/nowhere"])
def test_an_allowed_preflight_gets_only_cors_headers_and_never_reaches_a_route(
    client: TestClient, spy: Spy, path: str
) -> None:
    response = client.options(path, headers=preflight(APP_ORIGIN))  # no token: a preflight never has one
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["access-control-allow-origin"] == APP_ORIGIN
    assert response.headers["access-control-allow-methods"] == "GET, POST"
    assert response.headers["access-control-allow-headers"] == "Authorization, Content-Type"
    assert "access-control-allow-credentials" not in response.headers
    assert "content-type" not in response.headers
    assert spy.route_calls == 0
    assert spy.shutdowns == 0


@pytest.mark.parametrize(
    "asked",
    [
        preflight("https://evil.com"),
        preflight("null"),
        preflight(APP_ORIGIN, method="DELETE"),
        preflight(APP_ORIGIN, headers="authorization, x-evil"),
        preflight(APP_ORIGIN, headers="cookie"),
    ],
    ids=["other-origin", "null-origin", "method", "header", "cookie"],
)
def test_any_other_preflight_gets_403_and_never_reaches_a_route(
    client: TestClient, spy: Spy, asked: dict[str, str]
) -> None:
    response = client.options("/v1/test/spy", headers={**asked, **AUTH})
    assert response.status_code == 403
    assert "access-control-allow-origin" not in response.headers
    assert spy.route_calls == 0


def test_a_preflight_without_a_method_is_an_ordinary_options_request(client: TestClient, spy: Spy) -> None:
    assert client.options("/v1/test/spy", headers={"Origin": APP_ORIGIN}).status_code == 401
    assert spy.route_calls == 0
    assert client.options("/v1/test/spy", headers={**AUTH, "Origin": APP_ORIGIN}).status_code == 200
    assert spy.route_calls == 1


def test_no_origin_is_allowed_by_default_and_dev_origins_are_checked() -> None:
    assert allowed_origins() == ()
    assert allowed_origins(("http://localhost:5173",)) == ("http://localhost:5173",)
    assert allowed_origins(("http://localhost:5173", "http://localhost:5173")) == ("http://localhost:5173",)
    for bad in ("localhost:5173", "http://localhost:5173/", "file://x", "http://", "*", "http://a b"):
        with pytest.raises(ValueError, match="an origin is"):
            allowed_origins((bad,))


def test_an_app_with_the_default_origins_refuses_every_browser_origin() -> None:
    app = create_app(TOKEN, PORT, allowed_origins())
    with TestClient(app, base_url=BASE) as default_client:
        assert default_client.get("/v1/status", headers=AUTH).status_code == 200  # no Origin: the CLI
        for origin in (APP_ORIGIN, VITE_DEV_ORIGIN, "null", BASE):
            response = default_client.get("/v1/status", headers={**AUTH, "Origin": origin})
            assert (response.status_code, response.json()) == (403, {"error": "forbidden_origin"})


# --- bodies and errors --------------------------------------------------------------------------------------


def test_a_body_over_1_mib_gets_413_before_a_route_sees_it(client: TestClient, spy: Spy) -> None:
    response = client.post("/v1/test/spy", headers=AUTH, content=b"x" * (MAX_BODY_BYTES + 1))
    assert response.status_code == 413
    assert response.json() == {"error": "body_too_large"}
    assert spy.route_calls == 0


def test_a_body_of_exactly_1_mib_is_read() -> None:
    body = b"# " + b"x" * (MAX_BODY_BYTES - 3) + b"\n"
    assert len(body) == MAX_BODY_BYTES
    with TestClient(make_app(), base_url=BASE) as client:
        response = client.post("/v1/validate", headers=AUTH, content=body)
    assert response.status_code == 200
    assert response.json()["valid"] is False


def test_a_body_in_chunks_without_a_length_is_capped_too(spy: Spy) -> None:
    app = make_app(spy)
    chunk = b"x" * (256 * 1024)
    status, _, body = asgi(app, "POST", "/v1/test/spy", good_headers(), [chunk] * 4 + [b"x"])
    assert status == 413
    assert json.loads(body) == {"error": "body_too_large"}
    assert asgi(app, "POST", "/v1/test/spy", good_headers(), [chunk] * 4)[0] == 200
    assert spy.route_calls == 1


def test_a_body_that_takes_too_long_gets_408(spy: Spy, monkeypatch: pytest.MonkeyPatch) -> None:
    from safetwin.api import app as app_module

    monkeypatch.setattr(app_module, "BODY_TIMEOUT_S", 0.2)
    guard = make_app(spy)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/test/spy",
        "raw_path": b"/v1/test/spy",
        "query_string": b"",
        "root_path": "",
        "headers": [*good_headers(), (b"content-length", b"100")],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", PORT),
    }
    sent: list[dict[str, Any]] = []
    first = True

    async def receive() -> dict[str, Any]:
        nonlocal first
        if first:
            first = False
            return {"type": "http.request", "body": b"x", "more_body": True}
        await asyncio.sleep(3600)  # the rest never comes
        raise AssertionError("unreachable")

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    started = time.monotonic()
    asyncio.run(guard(scope, receive, send))  # type: ignore[arg-type]
    assert time.monotonic() - started < 2
    assert sent[0]["status"] == 408
    assert json.loads(sent[1]["body"]) == {"error": "request_timeout"}
    assert spy.route_calls == 0


def test_a_bad_content_length_gets_400(spy: Spy) -> None:
    app = make_app(spy)
    for length in (b"-1", b"abc", b"1e3"):
        assert asgi(app, "POST", "/v1/test/spy", [*good_headers(), (b"content-length", length)])[0] == 400
    assert spy.route_calls == 0


def test_the_422_answer_says_where_and_what_but_never_repeats_the_input(client: TestClient, spy: Spy) -> None:
    response = client.post("/v1/test/item", headers=AUTH, json={"count": CANARY, "name": 12, CANARY: CANARY})
    assert response.status_code == 422
    assert CANARY.encode() not in response.content
    body = response.json()
    assert body["error"] == "invalid_request"
    assert {"loc": ["body", "count"], "type": "int_parsing"} in body["problems"]
    assert {"loc": ["body", "name"], "type": "string_type"} in body["problems"]
    assert all(set(problem) == {"loc", "type"} for problem in body["problems"])
    broken = client.post(
        "/v1/test/item", headers={**AUTH, "Content-Type": "application/json"}, content=f'{{"count": "{CANARY}'
    )
    assert broken.status_code == 422
    assert CANARY.encode() not in broken.content
    assert spy.route_calls == 0


def test_not_found_and_wrong_method_are_fixed_json(client: TestClient) -> None:
    missing = client.get(f"/v1/{CANARY}", headers=AUTH)
    assert missing.status_code == 404
    assert missing.json() == {"error": "not_found"}
    wrong = client.get("/v1/shutdown", headers=AUTH)
    assert wrong.status_code == 405
    assert wrong.json() == {"error": "method_not_allowed"}


def test_an_error_in_a_route_is_a_fixed_500_and_is_logged_by_its_type_only(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    response = client.get("/v1/test/fail", headers=AUTH)
    assert response.status_code == 500
    assert response.json() == {"error": "internal"}
    assert CANARY.encode() not in response.content
    assert CANARY not in caplog.text
    assert caplog.text.count("a request failed with ValueError") == 1
    assert "Traceback" not in caplog.text


def test_docs_are_off_and_the_openapi_description_needs_the_token(client: TestClient) -> None:
    for path in ("/docs", "/redoc", "/docs/oauth2-redirect"):
        assert client.get(path, headers=AUTH).status_code == 404
    assert client.get("/openapi.json").status_code == 401
    described = client.get("/openapi.json", headers=AUTH)
    assert described.status_code == 200
    paths = described.json()["paths"]
    assert {"/v1/status", "/v1/shutdown", "/v1/validate"} <= set(paths)


def test_responses_are_not_cached(client: TestClient) -> None:
    for response in (client.get("/v1/status", headers=AUTH), client.get("/v1/status")):
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"


# --- the routes ---------------------------------------------------------------------------------------------


def test_status_says_what_the_engine_is(client: TestClient) -> None:
    body = client.get("/v1/status", headers=AUTH).json()
    assert set(body) == {"version", "pid", "started_at", "uptime_s", "memory_bytes", "memory_kind", "runs"}
    assert body["runs"] is None  # no executor in this app
    assert body["pid"] == os.getpid()
    assert body["version"] == version("safetwin")
    assert body["started_at"].endswith("Z")
    assert body["uptime_s"] >= 0
    assert body["memory_bytes"] > 10_000_000
    assert body["memory_kind"] == ("phys_footprint" if os.uname().sysname == "Darwin" else "rss")


def test_shutdown_answers_202_and_then_calls_the_hook(client: TestClient, spy: Spy) -> None:
    response = client.post("/v1/shutdown", headers=AUTH)
    assert response.status_code == 202
    assert response.json() == {"status": "shutting_down"}
    assert spy.shutdowns == 1


def test_validate_answers_a_valid_pipeline_as_safetwin_validate_does(client: TestClient) -> None:
    response = client.post(
        "/v1/validate", headers={**AUTH, "Content-Type": "application/yaml"}, content=CSV_CLEAN
    )
    assert response.status_code == 200
    assert response.json() == {
        "valid": True,
        "nodes": 4,
        "problems": [],
    }


def test_validate_lists_the_problems_with_code_severity_message_and_path(client: TestClient) -> None:
    cyclic = CSV_CLEAN.replace(b"inputs: [read_csv]", b"inputs: [write_parquet]")
    body = client.post("/v1/validate", headers=AUTH, content=cyclic).json()
    assert body["valid"] is False
    assert "effective_delivery" not in body
    assert body["problems"] == [
        {
            "severity": "error",
            "code": "cycle",
            "message": "steps form a loop: drop_incomplete → trim_text → write_parquet → drop_incomplete. "
            "Remove one of these connections",
            "path": "spec.nodes[drop_incomplete]",
        }
    ]


def test_validate_reports_text_that_is_not_utf8(client: TestClient) -> None:
    body = client.post("/v1/validate", headers=AUTH, content=b"\xff\xfe" + CANARY.encode()).json()
    assert body["problems"] == [
        {
            "severity": "error",
            "code": "encoding_error",
            "message": "the pipeline is not UTF-8 text",
            "path": None,
        }
    ]


def pipelines_with_a_canary() -> list[str]:
    """Pipelines that hold the canary in values, broken in many ways."""
    text = CSV_CLEAN.decode()
    return [
        text.replace('path: "*.csv"', f'path: "{CANARY}"'),  # valid
        text.replace('path: "*.csv"', f'path: "{CANARY}"').replace("transform.filter", "transform.nope"),
        text.replace('expr: "id IS NOT NULL"', f"expr: {CANARY}\n        expr: {CANARY}"),  # a key twice
        text.replace("  sockets:", f"  mode: {CANARY}\n  sockets:"),  # a key that is not in the format
        text.replace("kind: Pipeline", f"kind: {CANARY}"),
        text.replace("owner: me", f"owner: !{CANARY} me"),  # an unknown tag
        text.replace("owner: me", f"owner: &{CANARY} me\n  extra: &{CANARY} x"),  # an anchor used twice
        text.replace("socket: inbox", f"socket: {{nested: {CANARY}}}"),
        text.replace("header: true", f"header: [{CANARY}"),  # broken flow sequence
        text.replace('path: "clean/"', f'path: "{CANARY}'),  # an unclosed quote
        text.replace('path: "clean/"', f"path: *{CANARY}"),  # an alias
        text.replace('path: "clean/"', f'path: "{CANARY}\\q"'),  # a bad escape
        text.replace('path: "clean/"', f"path: {CANARY}\n\tcompression: x"),  # a tab
        text.replace("owner: me", f"owner: {{{CANARY}: {CANARY}}}"),
        text.replace("owner: me", f"owner: ghp_{'a1B2' * 9}"),  # an inline secret
        text.replace("tags: [csv, clean]", f"tags: {CANARY}"),
        text.replace("columns: [name, city]", f"columns: {CANARY}: {CANARY}"),
        f"{CANARY}",
        f"- {CANARY}",
        f"apiVersion: {CANARY}\nkind: Pipeline\n",
        text + f"\n{CANARY}: [\n",
        text.replace("    - id: read_csv\n", f"    - {CANARY}\n    - id: read_csv\n"),
        text.replace("kind: Pipeline", f"kind: \"a' found using '{CANARY}\""),
        text.replace("kind: Pipeline", f"kind: \"'{CANARY}'\""),
        text.replace("apiVersion: safetwin/v1", f"apiVersion: \"'{CANARY}'\""),
    ]


@pytest.mark.parametrize("kind", [CANARY, "a' found using 'LEAKED", f"x' found using '{CANARY}' z"])
def test_a_wrong_kind_is_not_repeated(client: TestClient, kind: str) -> None:
    text = CSV_CLEAN.replace(b"kind: Pipeline", f"kind: {json.dumps(kind)}".encode())
    response = client.post("/v1/validate", headers=AUTH, content=text)
    assert kind.encode() not in response.content
    assert b"LEAKED" not in response.content
    assert CANARY.encode() not in response.content
    (problem,) = response.json()["problems"]
    assert problem["code"] == "literal_error"
    assert problem["message"] == "kind: Input should be 'Pipeline'"


def test_validate_never_repeats_a_value_of_the_pipeline(client: TestClient) -> None:
    for text in pipelines_with_a_canary():
        response = client.post("/v1/validate", headers=AUTH, content=text.encode())
        assert response.status_code == 200, text
        assert CANARY.encode() not in response.content, text
        assert b"a1B2a1B2" not in response.content, text


def test_validate_answers_a_pipeline_nested_too_deeply() -> None:
    answer = validate_text(b"a: " + b"[" * 5000 + b"]" * 5000)
    assert answer.valid is False
    assert [problem.code for problem in answer.problems] == ["too_deep"]


def test_a_message_that_still_looks_like_a_secret_is_withheld() -> None:
    from safetwin.api.app import _problem_out
    from safetwin.spec import Problem

    shown = _problem_out(Problem("error", "unknown_reference", f"lists 'ghp_{'a1B2' * 9}'", node_id="n"))
    assert (
        shown.message
        == "a problem of kind unknown_reference (its message is not shown: it may quote a secret)"
    )
    assert shown.path == "spec.nodes[n]"


# --- the WebSocket ------------------------------------------------------------------------------------------


def test_the_right_token_within_2_s_gets_hello_then_heartbeats() -> None:
    with (
        TestClient(make_app(heartbeat_s=0.1), base_url=BASE) as client,
        client.websocket_connect(WS_URL) as ws,
    ):
        ws.send_text(TOKEN)
        hello = ws.receive_json()
        assert hello["type"] == "hello"
        expected = {"version": version("safetwin"), "pid": os.getpid(), "api": "v1", "heartbeat_s": 0.1}
        assert hello["data"] == expected
        assert hello["ts"].endswith("Z")
        beat = ws.receive_json()
        assert beat["type"] == "heartbeat"
        assert set(beat["data"]) == {"uptime_s"}
        assert ws.receive_json()["data"]["uptime_s"] >= beat["data"]["uptime_s"]


def test_an_allowed_origin_may_open_the_event_stream() -> None:
    with (
        TestClient(make_app(), base_url=BASE) as client,
        client.websocket_connect(WS_URL, headers={"Origin": APP_ORIGIN}) as ws,
    ):
        ws.send_text(TOKEN)
        assert ws.receive_json()["type"] == "hello"


def closed_with(ws: Any) -> int:
    """The close code of a socket that the server closes now (or has closed)."""
    message = ws.receive()
    assert message["type"] == "websocket.close", message
    return cast(int, message["code"])


@pytest.mark.parametrize(
    "first",
    [new_token(), TOKEN + "x", TOKEN[:-1], f"Bearer {TOKEN}", "", "x" * 10_000],
    ids=lambda v: str(len(v)),
)
def test_a_wrong_token_closes_the_socket_with_1008(first: str) -> None:
    with TestClient(make_app(), base_url=BASE) as client, client.websocket_connect(WS_URL) as ws:
        ws.send_text(first)
        assert closed_with(ws) == 1008


def test_a_first_message_that_is_not_text_closes_the_socket_with_1008() -> None:
    with TestClient(make_app(), base_url=BASE) as client, client.websocket_connect(WS_URL) as ws:
        ws.send_bytes(TOKEN.encode())
        assert closed_with(ws) == 1008


def test_no_token_within_2_s_closes_the_socket_with_1008_and_a_late_one_is_too_late() -> None:
    with TestClient(make_app(), base_url=BASE) as client, client.websocket_connect(WS_URL) as ws:
        started = time.monotonic()
        assert closed_with(ws) == 1008
        waited = time.monotonic() - started
    assert TOKEN_TIMEOUT_S - 0.3 <= waited <= TOKEN_TIMEOUT_S + 1.5


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://evil.com"},
        {"Origin": "null"},
        {"Host": "evil.com"},
        {"Host": f"127.0.0.1:{PORT + 1}"},
    ],
    ids=["evil-origin", "null-origin", "evil-host", "other-port"],
)
def test_a_bad_origin_or_host_is_closed_before_the_socket_is_accepted(headers: dict[str, str]) -> None:
    with TestClient(make_app(), base_url=BASE) as client:
        with (
            pytest.raises(WebSocketDisconnect) as closed,
            client.websocket_connect(WS_URL, headers=headers),
        ):
            pass
        assert closed.value.code == 1008


def test_only_so_many_authenticated_websocket_clients_at_once() -> None:
    app = make_app(hub=Hub(max_clients=2))
    with (
        TestClient(app, base_url=BASE) as client,
        client.websocket_connect(WS_URL) as first,
        client.websocket_connect(WS_URL) as second,
    ):
        first.send_text(TOKEN)
        second.send_text(TOKEN)
        assert first.receive_json()["type"] == second.receive_json()["type"] == "hello"
        with client.websocket_connect(WS_URL) as third:
            third.send_text(TOKEN)
            assert closed_with(third) == 1013


def test_sockets_that_never_send_the_token_can_not_keep_the_app_out() -> None:
    from collections import deque

    hub = Hub(max_clients=16, max_pending=4)
    with (
        TestClient(make_app(hub=hub, heartbeat_s=0.1), base_url=BASE) as client,
        client.websocket_connect(WS_URL) as app_socket,
    ):
        app_socket.send_text(TOKEN)
        assert app_socket.receive_json()["type"] == "hello"
        idle: deque[Any] = deque()
        try:
            for _ in range(4):  # every pending slot taken by a socket that never sends the token
                idle.append(client.websocket_connect(WS_URL).__enter__())
            for _round in range(5):
                # The attacker opens 4 more (each one evicts the oldest idle socket, with 1013: try again
                # later, not 1008, which would say its token was bad)...
                for _ in range(4):
                    idle.append(client.websocket_connect(WS_URL).__enter__())
                    oldest = idle.popleft()
                    assert closed_with(oldest) == 1013
                    oldest.__exit__(None, None, None)
                # ...and a client that sends its token at once still gets in.
                with client.websocket_connect(WS_URL) as newcomer:
                    newcomer.send_text(TOKEN)
                    assert newcomer.receive_json()["type"] == "hello"
                    idle.popleft().__exit__(None, None, None)  # the newcomer evicted the oldest idle one
                idle.append(client.websocket_connect(WS_URL).__enter__())
            assert app_socket.receive_json()["type"] == "heartbeat"  # the app's client was never disturbed
        finally:
            for session in idle:
                session.__exit__(None, None, None)


def test_fastapi_telemetry_is_off() -> None:
    from safetwin.api.app import TELEMETRY_OFF

    api = cast(FastAPI, make_app().app)
    # FastAPI 0.142 keeps its settings in private attributes: there is no public accessor yet.
    config = api._telemetry
    for key in ("tracing", "metrics", "logs", "operation_spans", "auto_configure"):
        assert config[key] is False, key  # type: ignore[literal-required]
    assert TELEMETRY_OFF["exclude"] is not None
    assert TELEMETRY_OFF["exclude"]({"type": "http"}) is True
    assert not api._native_telemetry.enabled()


def test_the_state_of_the_app_does_not_show_the_token() -> None:
    from safetwin.api.app import _State

    state = _State(TOKEN.encode(), "0.0.1", 1, 0.0, "2026-10-02T00:00:00Z", 5.0, Hub(), None)
    assert TOKEN not in repr(state)


def test_the_engine_stopping_sends_shutting_down_then_closes_with_1001() -> None:
    hub = Hub()
    with TestClient(make_app(hub=hub), base_url=BASE) as client, client.websocket_connect(WS_URL) as ws:
        ws.send_text(TOKEN)
        assert ws.receive_json()["type"] == "hello"
        assert client.portal is not None
        client.portal.call(hub.publish, Event("test.event", {"n": 1}))
        assert ws.receive_json()["type"] == "test.event"
        client.portal.call(hub.close_all)
        last = ws.receive_json()
        assert last["type"] == "shutting_down"
        assert last["data"] == {}
        assert closed_with(ws) == 1001
        with pytest.raises(WebSocketDisconnect), client.websocket_connect(WS_URL):
            pass  # no new client once the engine is stopping


def test_a_client_that_falls_behind_is_dropped_and_publish_never_waits() -> None:
    async def scenario() -> None:
        hub = Hub(queue_events=3)
        slot = hub.join()
        assert slot is not None
        subscriber = hub.subscribe(slot)
        assert subscriber is not None
        for n in range(5):
            hub.publish(Event("test.event", {"n": n}))
        assert subscriber.queue.qsize() == 1
        assert subscriber.queue.get_nowait() == events.OVERFLOW

    asyncio.run(scenario())


def test_the_event_envelope_has_type_ts_and_data() -> None:
    event = Event("run.started", {"run_id": "r1"}, ts="2026-10-02T09:30:00.123Z")
    assert json.loads(event.to_json()) == {
        "type": "run.started",
        "ts": "2026-10-02T09:30:00.123Z",
        "data": {"run_id": "r1"},
    }
    assert events.utc_now().endswith("Z")
    assert json.loads(events.heartbeat(1.23456).to_json())["data"] == {"uptime_s": 1.235}
