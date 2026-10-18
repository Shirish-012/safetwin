"""The audit log: appending, checking, and what the check finds when someone has been at the file."""

import hashlib
import json
import re
import sqlite3
import subprocess
import sys
import threading
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from safetwin.metadata import ChainCheck, append_audit_event, session_factory, verify_audit_chain
from safetwin.metadata.audit import GENESIS_HASH
from safetwin.metadata.models import AUDIT_DETAILS_MAX_BYTES, AuditEvent, Setting


def append(session: Session, count: int = 1, **overrides: Any) -> list[AuditEvent]:
    fields: dict[str, Any] = {
        "principal": "me",
        "action": "pipeline.run",
        "outcome": "success",
        "details": {"attempt": 1},
    }
    events = []
    for number in range(count):
        events.append(append_audit_event(session, resource=f"pipeline/p{number}", **{**fields, **overrides}))
    return events


def check(engine: Engine) -> ChainCheck:
    """Verifies from a session of its own, so nothing that another session holds gets in the way."""
    with session_factory(engine)() as session:
        return verify_audit_chain(session)


def run_sql(engine: Engine, statement: str, **parameters: Any) -> None:
    """What someone with access to the file could do: change it under the app's feet."""
    with engine.begin() as connection:
        connection.execute(text(statement), parameters)


@pytest.fixture
def chain(engine: Engine) -> Engine:
    """A database with five events in it, ids 1 to 5."""
    with session_factory(engine)() as session:
        append(session, 5)
        session.commit()
    return engine


# --- appending -----------------------------------------------------------------------------------


def test_the_first_event_starts_the_chain_and_each_one_names_the_hash_of_the_one_before(
    session: Session,
) -> None:
    events = append(session, 4)
    session.commit()
    assert [event.id for event in events] == [1, 2, 3, 4]
    assert events[0].prev_hash == GENESIS_HASH == "0" * 64
    for before, event in pairwise(events):
        assert event.prev_hash == before.hash
    hashes = [event.hash for event in events]
    assert len(set(hashes)) == 4
    assert all(re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes)


def test_the_event_keeps_what_it_was_given_and_the_time_of_the_append(session: Session) -> None:
    before = datetime.now(UTC)
    event = append_audit_event(
        session,
        principal="user:me",
        action="key.rotate",
        resource="key/k1",
        outcome="denied",
        details={"why": "no"},
    )
    session.commit()
    session.expire_all()
    stored = session.get_one(AuditEvent, event.id)
    assert (stored.principal, stored.action, stored.resource, stored.outcome) == (
        "user:me",
        "key.rotate",
        "key/k1",
        "denied",
    )
    assert before <= stored.ts <= datetime.now(UTC)
    assert stored.ts.utcoffset().total_seconds() == 0  # type: ignore[union-attr]


def recipe(prev_hash: str, event: AuditEvent) -> str:
    """The hash as the module docs describe it, written out again so that it is not the code under test."""
    fields = {
        "ts": event.ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"),
        "principal": event.principal,
        "action": event.action,
        "resource": event.resource,
        "outcome": event.outcome,
        "details": json.loads(event.details_json),
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def test_an_events_hash_follows_the_recipe_in_the_module_docs(session: Session) -> None:
    details = {"z": 1, "a": {"y": [1, 2, {"c": None, "b": True}], "x": "é ✓"}, "m": 1.5}
    events = append(session, 3, details=details)
    session.commit()
    previous = GENESIS_HASH
    for event in events:
        assert event.hash == recipe(previous, event)
        previous = event.hash


def test_details_are_stored_as_canonical_json(session: Session) -> None:
    (event,) = append(session, details={"z": 1, "a": {"y": [1, 2], "x": "é"}})
    assert event.details_json == '{"a":{"x":"\\u00e9","y":[1,2]},"z":1}'
    (empty,) = append(session, details={})
    assert empty.details_json == "{}"


def test_events_are_part_of_the_callers_transaction(session: Session) -> None:
    append(session)
    session.rollback()
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0
    append(session)
    session.commit()
    session.rollback()
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_two_events_of_one_transaction_chain_to_each_other(session: Session) -> None:
    first, second = append(session, 2)
    session.commit()
    assert second.prev_hash == first.hash
    assert verify_audit_chain(session) == ChainCheck(ok=True, checked=2, first_bad_id=None, reason=None)


def test_an_event_can_follow_other_writes_of_the_same_transaction(session: Session) -> None:
    session.add(Setting(key="theme", value_json='"dark"'))
    session.flush()  # the transaction has written: it already holds the database's write lock
    append(session, 2)
    session.commit()
    assert verify_audit_chain(session).ok


def test_an_event_can_follow_reads_of_the_same_session(session: Session) -> None:
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0
    append(session)
    session.commit()
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_details_that_are_not_json_are_refused_and_do_not_hold_the_lock(
    session: Session, db_path: Path
) -> None:
    with pytest.raises(TypeError):
        append(session, details={"when": datetime.now(UTC)})
    with pytest.raises(ValueError, match="Out of range float values"):
        append(session, details={"ratio": float("nan")})
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0
    with sqlite3.connect(db_path, timeout=0) as other:  # would fail at once if this session held the lock
        other.execute("BEGIN IMMEDIATE")
        other.execute("ROLLBACK")


def test_ids_are_not_used_again_after_an_event_is_deleted(chain: Engine) -> None:
    run_sql(chain, "DELETE FROM audit_events WHERE id = 5")
    with session_factory(chain)() as session:
        (event,) = append(session)
        session.commit()
    assert event.id == 6


# --- what may not go into the details ----------------------------------------------------------------

GITHUB_TOKEN = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
HEX_KEY = "3c82458822067a8405b54f1594dd5af84be10246"
BASE64_TOKEN = "q3Jk8sT0vXw2YzA5bC7dE9fG1hI4jK6lM8nO0pQ2rS4="
SECRETS = (GITHUB_TOKEN, AWS_KEY_ID, HEX_KEY, BASE64_TOKEN)

DETAILS_WITH_A_SECRET = {
    "a value": {"token": GITHUB_TOKEN},
    "a value in an object in an object": {"a": {"b": {"c": AWS_KEY_ID}}},
    "a value in a list": {"items": ["fine", HEX_KEY]},
    "a value in a tuple": {"items": ("fine", GITHUB_TOKEN)},
    "a value in a list of objects": {"items": [{"n": 1}, {"n": BASE64_TOKEN}]},
    "a value among other words": {"note": f"Bearer {BASE64_TOKEN} was used"},
    "a key": {AWS_KEY_ID: 1},
    "a key in an object in a list": {"a": [{GITHUB_TOKEN: "fine"}]},
}


@pytest.mark.parametrize("details", DETAILS_WITH_A_SECRET.values(), ids=DETAILS_WITH_A_SECRET.keys())
def test_details_with_a_secret_in_them_are_refused_and_nothing_is_written(
    session: Session, db_path: Path, details: dict[str, Any]
) -> None:
    with pytest.raises(ValueError, match="looks like a secret") as refused:
        append(session, details=details)
    assert not any(secret in str(refused.value) for secret in SECRETS)  # the message never repeats it
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 0
    with sqlite3.connect(db_path, timeout=0) as other:  # the refusal comes before the write lock is taken
        other.execute("BEGIN IMMEDIATE")
        other.execute("ROLLBACK")


def test_the_message_names_the_place_and_the_kind_but_not_the_secret(session: Session) -> None:
    with pytest.raises(ValueError, match=r"details\.token looks like a secret \(a GitHub token\)"):
        append(session, details={"token": GITHUB_TOKEN})
    with pytest.raises(ValueError, match=r"details\.a\.<redacted> looks like a secret"):
        append(session, details={"a": {AWS_KEY_ID: GITHUB_TOKEN}})  # the key is named by its place, redacted
    with pytest.raises(ValueError, match=r"a key in details looks like a secret \(an AWS access key ID\)"):
        append(session, details={"a": {AWS_KEY_ID: 1}})


def test_the_same_test_that_the_pipeline_validator_uses_decides(session: Session) -> None:
    digest = hashlib.sha256(b"x").hexdigest()
    with pytest.raises(ValueError, match="random-looking token"):
        append(session, details={"file": digest})  # on its own a 64-digit hex number looks like a key
    event, *_ = append(
        session, 3, details={"sha256": digest, "file": f"sha256:{digest}", "url": "socket://a"}
    )
    assert (
        json.loads(event.details_json)["sha256"] == digest
    )  # under a digest key, or with its prefix, it is fine


DIGEST = hashlib.sha256(b"x").hexdigest()  # 64 hex digits that are random-looking on their own


@pytest.mark.parametrize(
    "value",
    [
        f"sha256:{BASE64_TOKEN}",
        f"sha1:{DIGEST}",
        f"md5:{DIGEST[:40]}",
        f"sha256:{DIGEST[:63]}",
        f"sha256:{DIGEST}0",
        f"x sha256:{DIGEST}",
    ],
    ids=[
        "a token after the prefix",
        "sha1 with 64 digits",
        "md5 with 40 digits",
        "sha256 with 63 digits",
        "sha256 with 65 digits",
        "something in front of the prefix",
    ],
)
def test_a_prefix_does_not_make_anything_else_a_digest(session: Session, value: str) -> None:
    with pytest.raises(ValueError, match="looks like a secret"):
        append(session, details={"file": value})


def test_ordinary_details_still_go_in(session: Session) -> None:
    details = {"runs": 3, "pipeline": "csv-clean", "files": ["a.csv", "b.csv"], "ok": True, "note": None}
    (event,) = append(session, details=details)
    assert json.loads(event.details_json) == details


def details_of_size(size: int, filler: str = "x") -> dict[str, str]:
    """Details that are `size` bytes of JSON: {"k":"xxx..."}. The filler is one ASCII character."""
    overhead = len('{"k":""}')
    return {"k": filler * (size - overhead)}


def test_details_may_be_4_kib_as_json_and_not_a_byte_more(session: Session) -> None:
    assert AUDIT_DETAILS_MAX_BYTES == 4096
    (event,) = append(session, details=details_of_size(4096))
    assert len(event.details_json.encode()) == 4096
    session.commit()
    with pytest.raises(ValueError, match="4097 bytes as JSON; an audit event holds at most 4096"):
        append(session, details=details_of_size(4097))
    assert session.scalar(select(func.count()).select_from(AuditEvent)) == 1


def test_the_size_is_that_of_the_stored_json_where_a_letter_with_an_accent_takes_six_bytes(
    session: Session,
) -> None:
    with pytest.raises(ValueError, match="bytes as JSON"):
        append(session, details={"k": "é" * 700})  # 700 characters, but "\\u00e9" each once stored
    append(session, details={"k": "é" * 680})  # 4080 bytes + 8 bytes of JSON around it


def test_the_database_holds_the_same_limit_whoever_writes(engine: Engine) -> None:
    statement = (
        "INSERT INTO audit_events (ts, principal, action, resource, outcome, details_json, prev_hash, hash) "
        "VALUES ('2026-09-30 12:00:00.000000', 'x', 'y', 'z', 'success', :details, :prev, :hash)"
    )
    with pytest.raises(IntegrityError, match="ck_audit_events_details_json_size"):
        run_sql(engine, statement, details="x" * 4097, prev="0" * 64, hash="a" * 64)
    run_sql(engine, statement, details="x" * 4096, prev="0" * 64, hash="a" * 64)


# --- checking ------------------------------------------------------------------------------------


def test_a_chain_that_nobody_touched_is_fine(chain: Engine) -> None:
    assert check(chain) == ChainCheck(ok=True, checked=5, first_bad_id=None, reason=None)


def test_a_log_without_events_is_fine(engine: Engine) -> None:
    assert check(engine) == ChainCheck(ok=True, checked=0, first_bad_id=None, reason=None)


def test_a_long_chain_is_checked_all_the_way_through(engine: Engine) -> None:
    with session_factory(engine)() as session:
        append(session, 1100)  # more than one batch of rows
        session.commit()
    assert check(engine) == ChainCheck(ok=True, checked=1100, first_bad_id=None, reason=None)
    run_sql(engine, "UPDATE audit_events SET outcome = 'denied' WHERE id = 1000")
    result = check(engine)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 999, 1000)


def test_the_check_reads_the_database_and_not_the_objects_a_session_holds(engine: Engine) -> None:
    with session_factory(engine)() as session:
        events = append(session, 5)
        session.commit()
        assert verify_audit_chain(session).ok
        run_sql(engine, "UPDATE audit_events SET outcome = 'denied' WHERE id = 3")
        assert events[2].outcome == "success"  # the session still has the old object
        assert verify_audit_chain(session).first_bad_id == 3


EDITS = {
    "the principal": "UPDATE audit_events SET principal = 'someone else' WHERE id = 3",
    "the action": "UPDATE audit_events SET action = 'pipeline.delete' WHERE id = 3",
    "the resource": "UPDATE audit_events SET resource = 'pipeline/other' WHERE id = 3",
    "the outcome": "UPDATE audit_events SET outcome = 'denied' WHERE id = 3",
    # (text() takes a backslash before a colon to mean the colon itself, not a parameter)
    "the details": """UPDATE audit_events SET details_json = '{"attempt"\\:99}' WHERE id = 3""",
    "the time": "UPDATE audit_events SET ts = '2001-01-01 00:00:00.000000' WHERE id = 3",
    "the hash": f"UPDATE audit_events SET hash = '{'f' * 64}' WHERE id = 3",
    "the spelling of the details": (
        "UPDATE audit_events SET details_json = replace(details_json, ':', ': ') WHERE id = 3"
    ),
    "the details, to something that is not JSON": (
        "UPDATE audit_events SET details_json = 'not json' WHERE id = 3"
    ),
}


@pytest.mark.parametrize("edit", EDITS.values(), ids=EDITS.keys())
def test_an_edited_event_is_found(chain: Engine, edit: str) -> None:
    run_sql(chain, edit)
    result = check(chain)
    assert result.ok is False
    assert (result.checked, result.first_bad_id) == (2, 3)
    assert result.reason is not None
    assert "edited" in result.reason


def test_an_event_that_names_another_hash_than_its_predecessors_is_found(chain: Engine) -> None:
    run_sql(chain, f"UPDATE audit_events SET prev_hash = '{'a' * 64}' WHERE id = 3")
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 2, 3)
    assert result.reason is not None
    assert "does not follow" in result.reason


def test_a_deleted_event_in_the_middle_is_found_at_the_event_after_it(chain: Engine) -> None:
    run_sql(chain, "DELETE FROM audit_events WHERE id = 3")
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 2, 4)
    assert result.reason is not None
    assert "does not follow" in result.reason


def test_a_deleted_first_event_is_found_because_the_chain_no_longer_starts(chain: Engine) -> None:
    run_sql(chain, "DELETE FROM audit_events WHERE id = 1")
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 0, 2)
    assert result.reason is not None
    assert "does not start here" in result.reason


def swap_ids(engine: Engine, first: int, second: int) -> None:
    with engine.begin() as connection:  # a primary key can only be swapped through a spare value
        connection.execute(text("UPDATE audit_events SET id = -1 WHERE id = :a"), {"a": first})
        connection.execute(text("UPDATE audit_events SET id = :a WHERE id = :b"), {"a": first, "b": second})
        connection.execute(text("UPDATE audit_events SET id = :b WHERE id = -1"), {"b": second})


@pytest.mark.parametrize(
    ("first", "second", "first_bad_id"),
    [(2, 3, 2), (3, 4, 3), (2, 5, 2), (1, 5, 1), (1, 2, 1)],
    ids=["two neighbours", "two others", "far apart", "the ends", "the first two"],
)
def test_events_that_swapped_places_are_found_at_the_first_of_them(
    chain: Engine, first: int, second: int, first_bad_id: int
) -> None:
    swap_ids(chain, first, second)
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, first_bad_id - 1, first_bad_id)


def test_an_event_moved_to_the_front_is_found_there(chain: Engine) -> None:
    run_sql(chain, "UPDATE audit_events SET id = 0 WHERE id = 5")
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 0, 0)


def test_an_event_added_at_the_end_with_a_made_up_hash_is_found(chain: Engine) -> None:
    with session_factory(chain)() as session:
        last = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc())).first()
    assert last is not None
    run_sql(
        chain,
        "INSERT INTO audit_events (ts, principal, action, resource, outcome, details_json, prev_hash, hash) "
        "VALUES ('2026-09-30 12:00:00.000000', 'x', 'y', 'z', 'success', '{}', :prev, :hash)",
        prev=last.hash,
        hash="b" * 64,
    )
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 5, 6)


def test_a_deleted_newest_event_is_found_once_another_event_is_added(chain: Engine) -> None:
    run_sql(chain, "DELETE FROM audit_events WHERE id = 5")
    with session_factory(chain)() as session:
        append(session)  # chains to event 4, but takes the id 6, not the id 5 that was deleted
        session.commit()
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 4, 6)


def recompute_hashes(engine: Engine, first_id: int, last_id: int) -> None:
    """What someone who knows the recipe can do: write the hashes of these events again."""
    with session_factory(engine)() as session:
        rows = {e.id: e for e in session.scalars(select(AuditEvent).order_by(AuditEvent.id))}
        previous = rows[first_id - 1].hash if first_id > 1 else GENESIS_HASH
        for event_id in range(first_id, last_id + 1):
            event = rows[event_id]
            new_hash = recipe(previous, event)
            session.execute(
                text("UPDATE audit_events SET prev_hash = :prev, hash = :hash WHERE id = :id"),
                {"prev": previous, "hash": new_hash, "id": event_id},
            )
            event.hash = previous = new_hash
        session.commit()


def test_an_edit_whose_hash_was_recomputed_is_found_at_the_next_event(chain: Engine) -> None:
    run_sql(chain, "UPDATE audit_events SET outcome = 'denied' WHERE id = 3")
    recompute_hashes(chain, 3, 3)
    result = check(chain)
    assert (result.ok, result.checked, result.first_bad_id) == (False, 3, 4)


def test_what_the_chain_alone_cannot_show(chain: Engine) -> None:
    # The limits that the module docs state. Only signed checkpoints kept elsewhere could show these.
    run_sql(chain, "UPDATE audit_events SET outcome = 'denied' WHERE id = 3")
    recompute_hashes(chain, 3, 5)  # an edit, and every hash after it written again
    assert check(chain) == ChainCheck(ok=True, checked=5, first_bad_id=None, reason=None)

    run_sql(chain, "DELETE FROM audit_events WHERE id = 5")  # the newest event, deleted
    assert check(chain) == ChainCheck(ok=True, checked=4, first_bad_id=None, reason=None)


# --- appending from several places at once -----------------------------------------------------------


def test_two_threads_appending_at_the_same_time_keep_one_chain(engine: Engine) -> None:
    factory = session_factory(engine)
    each = 25
    barrier = threading.Barrier(2)
    errors: list[Exception] = []

    def worker(name: str) -> None:
        try:
            for number in range(each):
                barrier.wait(timeout=30)  # both start every append together
                with factory() as session:
                    append_audit_event(
                        session,
                        principal=name,
                        action="tick",
                        resource=f"n{number}",
                        outcome="success",
                        details={},
                    )
                    session.commit()
        except Exception as err:
            errors.append(err)  # reported below, from the main thread

    threads = [threading.Thread(target=worker, args=(name,)) for name in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert errors == []
    with factory() as session:
        assert verify_audit_chain(session) == ChainCheck(
            ok=True, checked=2 * each, first_bad_id=None, reason=None
        )
        assert (
            len(set(session.scalars(select(AuditEvent.prev_hash)))) == 2 * each
        )  # no two share a predecessor
        assert sorted(session.scalars(select(AuditEvent.id))) == list(range(1, 2 * each + 1))
        principals = list(session.scalars(select(AuditEvent.principal)))
        assert (principals.count("a"), principals.count("b")) == (each, each)


def test_an_append_waits_for_the_append_before_it_to_commit(engine: Engine) -> None:
    factory = session_factory(engine)
    holding, release, second_done = threading.Event(), threading.Event(), threading.Event()
    errors: list[Exception] = []

    def first() -> None:
        try:
            with factory() as session:
                append(session, principal="first")
                holding.set()
                assert release.wait(timeout=30)
                session.commit()
        except Exception as err:
            errors.append(err)

    def second() -> None:
        try:
            with factory() as session:
                append(session, principal="second")
                session.commit()
            second_done.set()
        except Exception as err:
            errors.append(err)

    first_thread = threading.Thread(target=first)
    first_thread.start()
    assert holding.wait(timeout=30)
    second_thread = threading.Thread(target=second)
    second_thread.start()
    assert not second_done.wait(timeout=0.3)  # it is waiting for the first to commit, not chaining to nothing
    release.set()
    first_thread.join(timeout=30)
    second_thread.join(timeout=30)
    assert errors == []
    with factory() as session:
        events = list(session.scalars(select(AuditEvent).order_by(AuditEvent.id)))
        assert [event.principal for event in events] == ["first", "second"]
        assert events[1].prev_hash == events[0].hash
        assert verify_audit_chain(session).ok


APPENDER = """
import sys, time
from pathlib import Path
from safetwin.metadata import append_audit_event, open_metadata_db, session_factory

path, name, sync = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
factory = session_factory(open_metadata_db(path))
(sync / f"{name}.ready").touch()
while not (sync / "go").exists():
    time.sleep(0.002)
for number in range(30):
    with factory() as session:
        append_audit_event(
            session, principal=name, action="tick", resource=f"n{number}", outcome="success", details={}
        )
        session.commit()
"""


def test_two_processes_appending_at_the_same_time_keep_one_chain(
    engine: Engine, db_path: Path, tmp_path: Path
) -> None:
    sync = tmp_path / "sync"
    sync.mkdir()
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", APPENDER, str(db_path), name, str(sync)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for name in ("a", "b")
    ]
    try:
        for _ in range(3000):  # up to 30 s for both to start and open the database
            if all((sync / f"{name}.ready").exists() for name in ("a", "b")):
                break
            threading.Event().wait(0.01)
        (sync / "go").touch()
        outputs = [process.communicate(timeout=60) for process in processes]
    finally:
        for process in processes:
            process.kill()
    assert [process.returncode for process in processes] == [0, 0], outputs
    with session_factory(engine)() as session:
        assert verify_audit_chain(session) == ChainCheck(ok=True, checked=60, first_bad_id=None, reason=None)
        assert len(set(session.scalars(select(AuditEvent.prev_hash)))) == 60
