"""A small client of the control API, for the `safetwin` command and the single-instance check of the engine.

Standard library only (`http.client`), so that `safetwin engine status` and `safetwin engine stop` stay light.
The token goes in the Authorization header and nowhere else, and no error message repeats it or what the
engine sent.
"""

import http.client
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from .connection import ConnectionInfo

DEFAULT_TIMEOUT_S = 5.0
_MAX_RESPONSE_BYTES = 1 << 20


class EngineError(Exception):
    """The engine could not be reached or did not answer as it should. The message is one safe line."""


class EngineNotRunning(EngineError):
    """Nothing answers on the port of the connection file."""


class EngineTimeout(EngineError):
    """The engine did not answer in time."""


class EngineRefusedToken(EngineError):
    """The engine answered 401: the token of the connection file is not its token."""


@dataclass(frozen=True)
class EngineStatus:
    """What `GET /v1/status` answers."""

    version: str
    pid: int
    started_at: str
    uptime_s: float
    memory_bytes: int
    memory_kind: str

    @classmethod
    def from_json(cls, raw: Any) -> "EngineStatus":
        try:
            return cls(
                version=str(raw["version"]),
                pid=int(raw["pid"]),
                started_at=str(raw["started_at"]),
                uptime_s=float(raw["uptime_s"]),
                memory_bytes=int(raw["memory_bytes"]),
                memory_kind=str(raw["memory_kind"]),
            )
        except (KeyError, TypeError, ValueError):
            raise EngineError("the engine sent a status that this safetwin can't read") from None


def call(
    info: ConnectionInfo,
    method: str,
    path: str,
    body: bytes | None = None,
    *,
    content_type: str = "text/plain; charset=utf-8",
    timeout: float = DEFAULT_TIMEOUT_S,
) -> tuple[int, Any]:
    """Send one request to the engine of `info`; the status and the JSON it answered (None if not JSON).

    Raises `EngineNotRunning`, `EngineTimeout`, `EngineRefusedToken` (for a 401) or `EngineError`.
    """
    address = f"127.0.0.1:{info.port}"
    headers = {"Authorization": f"Bearer {info.token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = content_type
    connection = http.client.HTTPConnection("127.0.0.1", info.port, timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(_MAX_RESPONSE_BYTES + 1)
        status = response.status
    except ConnectionRefusedError:
        raise EngineNotRunning(f"nothing answers on {address}") from None
    except TimeoutError:  # socket.timeout is TimeoutError
        raise EngineTimeout(f"the engine on {address} did not answer within {timeout:g} s") from None
    except (OSError, http.client.HTTPException) as err:
        reason = err.strerror if isinstance(err, OSError) and err.strerror else type(err).__name__
        raise EngineError(f"could not talk to the engine on {address}: {reason}") from None
    finally:
        connection.close()
    if status == 401:
        raise EngineRefusedToken(
            f"the engine on {address} refused the token of the connection file (is another program on that "
            "port?)"
        )
    try:
        parsed = json.loads(data) if len(data) <= _MAX_RESPONSE_BYTES else None
    except ValueError:
        parsed = None
    return status, parsed


def get_status(info: ConnectionInfo, *, timeout: float = DEFAULT_TIMEOUT_S) -> EngineStatus:
    """`GET /v1/status`."""
    status, body = call(info, "GET", "/v1/status", timeout=timeout)
    if status != 200:
        raise EngineError(f"the engine answered {status} to a status request")
    return EngineStatus.from_json(body)


def request_shutdown(info: ConnectionInfo, *, timeout: float = DEFAULT_TIMEOUT_S) -> None:
    """`POST /v1/shutdown`: the engine answers 202 and then stops."""
    status, _ = call(info, "POST", "/v1/shutdown", b"", timeout=timeout)
    if status != 202:
        raise EngineError(f"the engine answered {status} to a shutdown request")


def call_json(
    info: ConnectionInfo, method: str, path: str, body: Any = None, *, timeout: float = DEFAULT_TIMEOUT_S
) -> tuple[int, Any]:
    """`call` with a JSON body (when `body` is not None)."""
    data = None if body is None else json.dumps(body).encode("utf-8")
    return call(info, method, path, data, content_type="application/json", timeout=timeout)


def get_run(
    info: ConnectionInfo, run_id: str, *, timeout: float = DEFAULT_TIMEOUT_S
) -> dict[str, Any] | None:
    """`GET /v1/runs/{run_id}`: the run, or None if the engine has no run with that id."""
    status, body = call(info, "GET", f"/v1/runs/{quote(run_id, safe='')}", timeout=timeout)
    if status == 404:
        return None
    if status != 200 or not isinstance(body, dict):
        raise EngineError(f"the engine answered {status} to a request for a run")
    return body


def list_runs(
    info: ConnectionInfo,
    *,
    limit: int | None = None,
    before: str | None = None,
    pipeline: str | None = None,
    state: str | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> tuple[int, Any]:
    """`GET /v1/runs` with the parameters that are given: the status (200, or 422 for a bad one) and the
    answer."""
    given = {"limit": limit, "before": before, "pipeline": pipeline, "state": state}
    query = urlencode({key: value for key, value in given.items() if value is not None})
    return call(info, "GET", f"/v1/runs?{query}" if query else "/v1/runs", timeout=timeout)


def cancel_run(info: ConnectionInfo, run_id: str, *, timeout: float = DEFAULT_TIMEOUT_S) -> tuple[int, Any]:
    """`POST /v1/runs/{run_id}/cancel`: 202, 404 (no such run) or 409 (it has ended), and the answer."""
    return call(info, "POST", f"/v1/runs/{quote(run_id, safe='')}/cancel", b"", timeout=timeout)
