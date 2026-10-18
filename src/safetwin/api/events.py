"""The events of the WebSocket `/v1/events`: their envelope, and the hub that sends them to every client.

Every message the engine sends is one JSON object, an envelope:

    {"type": "heartbeat", "ts": "2026-10-02T09:30:00.123Z", "data": {"uptime_s": 12.5}}

- `type`: what happened. A dotted name for families of events (`run.started`, `stage.progress`, ...).
  Clients ignore types they don't know.
- `ts`: when, in UTC, ISO 8601 with milliseconds.
- `data`: an object whose fields depend on `type`. It holds metadata only, never a data value
  (docs/security.md).

The types today:

- `hello`, first after the token is accepted: {version, pid, api: "v1", heartbeat_s}.
- `heartbeat`, every `heartbeat_s` seconds: {uptime_s}.
- `shutting_down`, last, when the engine stops: {}. The engine then closes the socket with 1001 (going away).

The events of runs (`safetwin.executor`; `stage` is the index of a stage, from 0). Each has the `run_id`:

- `run.queued`: {run_id, pipeline, position}: the run waits for a free stage worker.
- `run.started`: {run_id, pipeline}.
- `stage.started`: {run_id, stage, node_ids, path, attempt, worker_id, worker_pid, worker_start ("warm" or
  "cold"), worker_wait_s}.
- `stage.progress`, at most four a second for each stage: {run_id, stage, path, rows_per_node,
  bytes_written, memory_bytes, elapsed_s}.
- `stage.finished`: {run_id, stage, state, path, rows_per_node, bytes_written, files: [{path, bytes, sha256}],
  duration_s, error_class, error}, whether the stage succeeded, failed or was cancelled.
- `run.finished` {run_id, pipeline, state: "succeeded", totals: {rows, bytes, files}}, `run.failed` {run_id,
  pipeline, stage, error_class, error} or `run.cancelled` {run_id, pipeline, stage}: the last event of a run.

Errors are safe: a class name, and a message only where the engine writes its own (never a library's).

The close codes of the socket: 1008 means the token was wrong, late or not text (a token problem: read the
connection file again rather than retrying); 1013 (try again later) means the engine is busy: a pending socket
that newer connections evicted before it sent its token, no free authenticated slot, or a client that fell
too far behind. Clients retry 1013 with backoff. 1001 means the engine is stopping.

The hub keeps a bounded queue for each client. `publish` never waits: a client that has fallen
`queue_events` events behind is closed with 1013 (try again later) instead of holding memory for it.
Everything here runs on the event loop of the server; a worker thread that publishes (T5b) must hand the event
over with `loop.call_soon_threadsafe(hub.publish, event)`.
"""

import asyncio
import json
import time
from collections import deque
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal

from .settings import MAX_WS_CLIENTS, MAX_WS_PENDING, WS_QUEUE_EVENTS


def utc_now() -> str:
    """Now, as the `ts` of an event: `2026-10-02T09:30:00.123Z`."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    """One event: the envelope of the module docs."""

    type: str
    data: Mapping[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=utc_now)

    def to_json(self) -> str:
        return json.dumps({"type": self.type, "ts": self.ts, "data": dict(self.data)}, separators=(",", ":"))


def hello(version: str, pid: int, heartbeat_s: float) -> Event:
    return Event("hello", {"version": version, "pid": pid, "api": "v1", "heartbeat_s": heartbeat_s})


def heartbeat(uptime_s: float) -> Event:
    return Event("heartbeat", {"uptime_s": round(uptime_s, 3)})


def shutting_down() -> Event:
    return Event("shutting_down")


Signal = Literal["close", "overflow"]
CLOSE: Final[Signal] = "close"  # the engine stops: send nothing more, close with 1001
OVERFLOW: Final[Signal] = "overflow"  # the client fell too far behind: close with 1013


class Subscriber:
    """The queue of one authenticated client. Room is kept for the signals that end it."""

    def __init__(self, queue_events: int) -> None:
        self.queue: asyncio.Queue[Event | Signal] = asyncio.Queue(maxsize=queue_events + 2)
        self._limit = queue_events

    def offer(self, event: Event) -> bool:
        """Queue `event`; False (and an `OVERFLOW` signal instead) if the client is too far behind."""
        if self.queue.qsize() >= self._limit:
            self._end(OVERFLOW)
            return False
        self.queue.put_nowait(event)
        return True

    def close(self, last: Event) -> None:
        """Queue `last`, then `CLOSE`, ahead of nothing: what is still queued is dropped first if need be."""
        while self.queue.qsize() > self._limit:
            self.queue.get_nowait()
        self.queue.put_nowait(last)
        self.queue.put_nowait(CLOSE)

    def _end(self, signal: Signal) -> None:
        while not self.queue.empty():
            self.queue.get_nowait()
        self.queue.put_nowait(signal)


class Pending:
    """The slot of a connection that has not sent its token yet. `evicted` is set when a newer connection
    takes the slot: the connection then closes with 1013 (try again later), not 1008, which would say its
    token was bad."""

    def __init__(self) -> None:
        self.evicted = asyncio.Event()


class Hub:
    """The WebSocket clients of the engine and the events that go to them.

    A connection takes one of `max_pending` slots for clients that have not sent the token yet (`join`), and
    `subscribe` moves it to one of `max_clients` slots for authenticated clients, with its queue. `leave`
    gives back whichever slot the connection had.

    When every pending slot is taken, a new connection is not refused: the oldest pending one is evicted
    (closed with 1013, try again later) and the newcomer takes its slot. The app sends its token within
    milliseconds of connecting, so sockets that never send one (each is closed after 2 s anyway) can't keep it
    out, however often a local process reopens them; at worst they evict one another. They never reach the
    authenticated slots, which only a client with the token gets.
    """

    def __init__(
        self,
        max_clients: int = MAX_WS_CLIENTS,
        queue_events: int = WS_QUEUE_EVENTS,
        max_pending: int = MAX_WS_PENDING,
    ) -> None:
        self.started = time.monotonic()
        self._max_clients = max_clients
        self._max_pending = max_pending
        self._queue_events = queue_events
        self._pending: deque[Pending] = deque()  # oldest first
        self._subscribers: set[Subscriber] = set()
        self._authenticated = 0  # subscribers, and those that were ended by the hub but have not left yet
        self._closing = False
        self._idle = asyncio.Event()
        self._idle.set()

    @property
    def closing(self) -> bool:
        return self._closing

    def join(self) -> Pending | None:
        """A pending slot for a new connection (the oldest pending connection is evicted if none is free);
        None if the engine is stopping."""
        if self._closing:
            return None
        while len(self._pending) >= self._max_pending:
            self._pending.popleft().evicted.set()
        slot = Pending()
        self._pending.append(slot)
        self._idle.clear()
        return slot

    def subscribe(self, slot: Pending) -> Subscriber | None:
        """Move a connection whose token was accepted from its pending slot to an authenticated one, and give
        it its queue. None (and the connection keeps its pending slot) if the engine is stopping, the slot
        was evicted, or every authenticated slot is taken."""
        if self._closing or slot.evicted.is_set() or self._authenticated >= self._max_clients:
            return None
        self._drop_pending(slot)
        self._authenticated += 1
        subscriber = Subscriber(self._queue_events)
        self._subscribers.add(subscriber)
        return subscriber

    def leave(self, slot: Pending, subscriber: Subscriber | None) -> None:
        """A connection has ended: give back its slot (authenticated if it has a subscriber, else pending)."""
        if subscriber is None:
            self._drop_pending(slot)
        else:
            self._subscribers.discard(subscriber)
            self._authenticated = max(0, self._authenticated - 1)
        if not self._pending and self._authenticated == 0:
            self._idle.set()

    def _drop_pending(self, slot: Pending) -> None:
        with suppress(ValueError):  # evicted already
            self._pending.remove(slot)

    def publish(self, event: Event) -> None:
        """Send `event` to every authenticated client. Never waits."""
        if self._closing:
            return
        for subscriber in list(self._subscribers):
            if not subscriber.offer(event):
                self._subscribers.discard(subscriber)

    async def close_all(self, timeout: float = 1.0) -> None:
        """Send `shutting_down` to every client and close them; wait up to `timeout` for them to go.

        No connection is let in after this.
        """
        self._closing = True
        last = shutting_down()
        for subscriber in list(self._subscribers):
            subscriber.close(last)
        self._subscribers.clear()
        with suppress(TimeoutError):
            await asyncio.wait_for(self._idle.wait(), timeout)
