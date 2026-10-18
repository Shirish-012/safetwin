"""The hash-chained audit log of the metadata database (docs/internals.md): who did what, in a form that
shows if it was changed.

Each event stores the hash of the event before it, so editing or deleting an event breaks the chain from
there on. The hash of an event is

    sha256(prev_hash + canonical(fields))

where `fields` is the JSON object {"action", "details", "outcome", "principal", "resource", "ts"} and
`canonical` is JSON with sorted keys and no spaces:
`json.dumps(fields, sort_keys=True, separators=(",", ":"))`.
`ts` is UTC in ISO 8601 with microseconds, like `2026-09-30T12:00:00.000000+00:00`. The first event has a
`prev_hash` of 64 zeros. Anyone can check an exported log with this recipe.

The ids count up by one (AUTOINCREMENT never reuses one), so a gap in the ids is a deleted event too.

A chain can't show two things. If the newest events are deleted, what is left is a shorter, valid chain. And
someone who can write to the database can rewrite an event and every hash after it. Both would need signed
checkpoints kept elsewhere, which this log does not have.
"""

import hashlib
import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import chain
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from safetwin.spec.validate import find_secrets

from .models import AUDIT_DETAILS_MAX_BYTES, AuditEvent

GENESIS_HASH = "0" * 64  # the prev_hash of the first event


@dataclass(frozen=True)
class ChainCheck:
    """The result of `verify_audit_chain`.

    `checked` counts the events, from the oldest, that are fine: all of them when `ok`, otherwise the ones
    before `first_bad_id`, the first event that is not.
    """

    ok: bool
    checked: int
    first_bad_id: int | None
    reason: str | None


def append_audit_event(
    session: Session, *, principal: str, action: str, resource: str, outcome: str, details: Mapping[str, Any]
) -> AuditEvent:
    """Add an event to the end of the chain, as part of the session's transaction: the caller commits.

    The database's write lock is taken before the last hash is read, so two appenders (threads, or processes)
    can never chain to the same event: the second one waits for the first to commit. `details` must be
    JSON, and metadata only: no data values. Audit rows are permanent, so `details` is refused with a
    `ValueError` when it is longer than 4 KiB as JSON, or when a string in it (a value or a key, at any
    depth) looks like a secret, by the test the pipeline validator uses for inline secrets. The message
    names the place and never repeats the string.
    """
    details_json = _canonical(details)  # before the lock: bad details must not hold it up
    canonical_details = json.loads(details_json)  # what is stored is what is checked: a tuple is a list
    _refuse_unfit_details(details_json, canonical_details)
    _take_write_lock(session)
    last_hash = session.scalar(select(AuditEvent.hash).order_by(AuditEvent.id.desc()).limit(1))
    prev_hash = last_hash or GENESIS_HASH
    ts = datetime.now(UTC)
    event = AuditEvent(
        ts=ts,
        principal=principal,
        action=action,
        resource=resource,
        outcome=outcome,
        details_json=details_json,
        prev_hash=prev_hash,
        hash=_event_hash(prev_hash, ts, principal, action, resource, outcome, canonical_details),
    )
    session.add(event)
    session.flush()
    return event


def verify_audit_chain(session: Session) -> ChainCheck:
    """Check the events from the oldest to the newest and report the first one that is wrong.

    Each event must name the hash of the one before it as its `prev_hash` and have the next id, and its own
    hash must be that of its contents. An edited event fails the second test. A deleted, added or moved event
    makes the event after it fail the first.

    The events are read from the database, not from objects this session may hold: it can be used to check
    a chain that someone has just changed.
    """
    previous: _StoredEvent | None = None
    checked = 0
    for row in session.execute(select(*_COLUMNS).order_by(AuditEvent.id).execution_options(yield_per=500)):
        event = _StoredEvent(*row)
        reason = _link_problem(event, previous) or _content_problem(event)
        if reason is not None:
            return ChainCheck(ok=False, checked=checked, first_bad_id=event.id, reason=reason)
        previous = event
        checked += 1
    return ChainCheck(ok=True, checked=checked, first_bad_id=None, reason=None)


def _refuse_unfit_details(details_json: str, details: object) -> None:
    """Raise `ValueError` if the details are too long for an audit row or have a secret in them.

    `details` is `details_json` parsed again, so it is what is stored: a number used as a key is text.
    """
    size = len(details_json.encode())
    if size > AUDIT_DETAILS_MAX_BYTES:
        raise ValueError(
            f"the details are {size} bytes as JSON; an audit event holds at most {AUDIT_DETAILS_MAX_BYTES}"
        )
    in_keys = (found for key in _keys(details) for found in find_secrets(key, "a key in details"))
    secret = next(chain(find_secrets(details, "details"), in_keys), None)
    if secret is not None:
        where, kind = secret
        raise ValueError(
            f"{where} looks like a secret ({kind}): audit events are permanent, so they hold neither "
            "secrets nor data values"
        )


def _keys(value: object) -> Iterator[str]:
    """The keys of the mappings inside parsed JSON, at any depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _keys(item)


def _take_write_lock(session: Session) -> None:
    """Start SQLite's write transaction now, so that what is read next is still true when it is written.

    Left to itself the driver only starts a transaction at the first INSERT, after the last hash was read.
    A session that has already written holds the lock and needs nothing.
    """
    connection = session.connection()
    driver_connection = connection.connection.driver_connection
    if driver_connection is not None and not driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN IMMEDIATE")


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _event_hash(
    prev_hash: str, ts: datetime, principal: str, action: str, resource: str, outcome: str, details: object
) -> str:
    fields = {
        "ts": ts.isoformat(timespec="microseconds"),
        "principal": principal,
        "action": action,
        "resource": resource,
        "outcome": outcome,
        "details": details,
    }
    return hashlib.sha256((prev_hash + _canonical(fields)).encode()).hexdigest()


@dataclass(frozen=True)
class _StoredEvent:
    """An event as `verify_audit_chain` reads it: the columns of the row, in the order of `_COLUMNS`."""

    id: int
    ts: datetime
    principal: str
    action: str
    resource: str
    outcome: str
    details_json: str
    prev_hash: str
    hash: str


_COLUMNS = (
    AuditEvent.id,
    AuditEvent.ts,
    AuditEvent.principal,
    AuditEvent.action,
    AuditEvent.resource,
    AuditEvent.outcome,
    AuditEvent.details_json,
    AuditEvent.prev_hash,
    AuditEvent.hash,
)


def _link_problem(event: _StoredEvent, previous: _StoredEvent | None) -> str | None:
    if previous is None:
        if event.prev_hash != GENESIS_HASH:
            return "the chain does not start here: earlier events were removed, or this one was changed"
    elif event.prev_hash != previous.hash or event.id != previous.id + 1:
        return (
            "this event does not follow the one before it: "
            "an event was removed, added or moved, or this one was changed"
        )
    return None


def _content_problem(event: _StoredEvent) -> str | None:
    try:
        details = json.loads(event.details_json)
    except ValueError:
        return "this event was edited: its details are not valid JSON"
    hash_of_contents = _event_hash(
        event.prev_hash, event.ts, event.principal, event.action, event.resource, event.outcome, details
    )
    # The details are also compared as written: another spelling of the same JSON is still an edit.
    if event.hash != hash_of_contents or event.details_json != _canonical(details):
        return "this event was edited: its contents do not match its hash"
    return None
