"""The settings of the control API: which app origins it allows and its limits. Standard library only."""

from typing import Final

# No browser origin is allowed by default: a request that carries an `Origin` header is refused unless
# `safetwin engine start --dev-origin` names that origin. Clients outside a browser (the CLI) send none. The
# browser UI (M5) adds its own origin when it is built.
DEFAULT_ORIGINS: Final[tuple[str, ...]] = ()
# A Vite dev server, for `safetwin engine start --dev-origin` (an example, not a default).
VITE_DEV_ORIGIN: Final = "http://localhost:5173"

MAX_BODY_BYTES: Final = 1 << 20  # 1 MiB: a bigger request body gets 413
BODY_TIMEOUT_S: Final = 10.0  # a request body that takes longer to arrive gets 408
TOKEN_TIMEOUT_S: Final = 2.0  # a WebSocket client must send the token within this time
HEARTBEAT_S: Final = 5.0  # a heartbeat event this often on every WebSocket
MAX_WS_CLIENTS: Final = 16  # authenticated WebSocket clients at once
# WebSocket connections at once that have not sent the token yet. A new one evicts the oldest when they are
# all taken (`events.Hub`), so the app (which sends its token within milliseconds) could only be evicted by
# this many new connections arriving inside that window: more slots make that harder, and each costs little.
MAX_WS_PENDING: Final = 16
MAX_WS_MESSAGE_BYTES: Final = 4096  # what a client may send in one message (it only sends the token)
WS_QUEUE_EVENTS: Final = 256  # events waiting for one client; a client that falls this far behind is dropped
# Connections at once, HTTP and WebSocket, idle or not: uvicorn counts every open connection and answers 503
# above this. It is far above what the UI and the CLI use (a handful), so that connections a local process
# opens and leaves idle (each is closed after 5 s without a request head: `server.EngineH11Protocol`) don't
# push the app's requests over it. It stays a limit, below the file descriptors the engine keeps for itself
# (`FD_SOFT_LIMIT`), so that too many connections get 503 instead of starving the engine of descriptors.
MAX_CONNECTIONS: Final = 1024
FD_SOFT_LIMIT: Final = 4096  # the engine raises its soft RLIMIT_NOFILE to this (or the hard limit, if lower)


def allowed_origins(dev_origins: tuple[str, ...] = ()) -> tuple[str, ...]:
    """The default origins (none) and the dev origins, without repeats. Each dev origin is checked by
    `check_origin`."""
    origins = [*DEFAULT_ORIGINS, *(check_origin(origin) for origin in dev_origins)]
    return tuple(dict.fromkeys(origins))


def check_origin(origin: str) -> str:
    """`origin` if it is a plain http(s) origin (scheme, host and port, nothing else); else ValueError."""
    scheme, sep, rest = origin.partition("://")
    if not sep or scheme not in ("http", "https") or not rest or any(c in rest for c in "/?#@ "):
        raise ValueError("an origin is a scheme, a host and an optional port, like http://localhost:5173")
    return origin
