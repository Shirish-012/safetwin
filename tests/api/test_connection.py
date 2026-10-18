"""The connection file, the instance lock, the token and the client's errors."""

import http.server
import json
import os
import re
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import psutil
import pytest

from safetwin.api.client import EngineNotRunning, EngineRefusedToken, EngineTimeout, get_status
from safetwin.api.connection import (
    ConnectionFileError,
    ConnectionInfo,
    InstanceLock,
    connection_path,
    ensure_home,
    pid_alive,
    read_connection_file,
    remove_connection_file,
    write_connection_file,
)
from safetwin.api.server import new_token


def info(**changes: object) -> ConnectionInfo:
    fields: dict[str, object] = {
        "version": "0.0.1",
        "pid": os.getpid(),
        "port": 50123,
        "token": new_token(),
        "started_at": "2026-10-02T09:30:00Z",
    }
    fields.update(changes)
    return ConnectionInfo(**fields)  # type: ignore[arg-type]


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_the_token_is_256_random_bits_in_url_safe_base64() -> None:
    tokens = {new_token() for _ in range(100)}
    assert len(tokens) == 100
    for token in tokens:
        assert len(token) == 43
        assert set(token) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def test_the_connection_file_is_written_0600_in_a_folder_made_0700(safetwin_home: Path) -> None:
    assert not safetwin_home.exists()
    path = connection_path()
    assert path == safetwin_home / "engine.json"
    mine = info()
    write_connection_file(path, mine)
    assert mode(safetwin_home) == 0o700
    assert mode(path) == 0o600
    assert os.listdir(safetwin_home) == ["engine.json"]  # no temporary file is left
    assert json.loads(path.read_text()) == {
        "version": "0.0.1",
        "pid": os.getpid(),
        "port": 50123,
        "token": mine.token,
        "started_at": "2026-10-02T09:30:00Z",
    }
    assert read_connection_file(path) == mine


def test_writing_again_replaces_the_file(safetwin_home: Path) -> None:
    path = connection_path()
    write_connection_file(path, info(pid=1))
    second = info(pid=2)
    write_connection_file(path, second)
    assert read_connection_file(path) == second
    assert mode(path) == 0o600
    assert os.listdir(safetwin_home) == ["engine.json"]


@pytest.mark.parametrize("bits", [0o755, 0o777, 0o750, 0o701])
def test_a_default_folder_that_is_there_with_group_or_other_bits_is_set_to_0700(
    tmp_path: Path, bits: int
) -> None:
    """A folder that is not the one SAFETWIN_HOME names (as the default folder of the app is not) is
    tightened."""
    home = tmp_path / "home"
    home.mkdir()
    os.chmod(home, bits)
    ensure_home(home)
    assert mode(home) == 0o700
    os.chmod(home, bits)
    write_connection_file(home / "engine.json", info())
    assert mode(home) == 0o700
    os.chmod(home, bits)
    assert InstanceLock(home).acquire()
    assert mode(home) == 0o700


def test_a_safetwin_home_that_others_may_use_is_refused_and_left_as_it_is(safetwin_home: Path) -> None:
    safetwin_home.mkdir()
    os.chmod(safetwin_home, 0o755)  # SAFETWIN_HOME names it (the fixture): the user chose it
    message = (
        "(SAFETWIN_HOME) can be used by other users: run chmod 700 on it, "
        "or set SAFETWIN_HOME to another folder"
    )
    with pytest.raises(ConnectionFileError, match=re.escape(message)):
        ensure_home(safetwin_home)
    with pytest.raises(ConnectionFileError, match=re.escape(message)):
        write_connection_file(connection_path(), info())
    with pytest.raises(ConnectionFileError, match=re.escape(message)):
        InstanceLock(safetwin_home).acquire()
    assert mode(safetwin_home) == 0o755
    assert list(safetwin_home.iterdir()) == []
    ensure_home(safetwin_home, explicit=False)  # as the default folder, it would be tightened
    assert mode(safetwin_home) == 0o700


def test_a_safetwin_home_that_safetwin_makes_is_0700(safetwin_home: Path) -> None:
    old = os.umask(0o002)  # a loose umask must not loosen it
    try:
        ensure_home(safetwin_home)
    finally:
        os.umask(old)
    assert mode(safetwin_home) == 0o700


def test_a_folder_of_another_user_is_refused(safetwin_home: Path) -> None:
    ensure_home(safetwin_home)
    write_connection_file(connection_path(), info())
    someone_else = lambda: os.getuid() + 1  # noqa: E731
    with pytest.raises(ConnectionFileError, match="it must be a folder of yours"):
        ensure_home(safetwin_home, uid=someone_else)
    with pytest.raises(ConnectionFileError, match="it must be a folder of yours"):
        InstanceLock(safetwin_home, uid=someone_else).acquire()
    with pytest.raises(ConnectionFileError, match=r"folder of the connection file .* is not safe to use"):
        read_connection_file(connection_path(), uid=someone_else)


@pytest.mark.parametrize("kind", ["link", "file"])
def test_a_folder_that_is_a_link_or_a_file_is_refused(tmp_path: Path, kind: str) -> None:
    home = tmp_path / "home"
    if kind == "link":
        (tmp_path / "real").mkdir(mode=0o700)
        home.symlink_to(tmp_path / "real")
    else:
        home.write_text("")
    with pytest.raises(ConnectionFileError, match="not safe to use: it must be a folder of yours"):
        ensure_home(home)
    with pytest.raises(ConnectionFileError, match="not safe to use"):
        read_connection_file(home / "engine.json")


@pytest.mark.parametrize("bits", [0o770, 0o722, 0o702])
def test_a_connection_file_in_a_folder_others_may_write_is_refused(safetwin_home: Path, bits: int) -> None:
    write_connection_file(connection_path(), info())
    os.chmod(safetwin_home, bits)
    with pytest.raises(ConnectionFileError, match="a folder of yours that no one else may write"):
        read_connection_file(connection_path())
    os.chmod(safetwin_home, 0o755)  # others may read the folder, not write it: the file decides
    assert read_connection_file(connection_path()) is not None


def in_time(work: Callable[[], object], seconds: float = 5.0) -> object:
    """What `work` returns or raises, run on a thread; the test fails if it takes longer than `seconds`."""
    outcome: list[object] = []

    def run() -> None:
        try:
            outcome.append(work())
        except BaseException as err:
            outcome.append(err)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"it did not end within {seconds} s"
    return outcome[0]


def test_a_fifo_at_the_connection_file_is_refused_at_once(safetwin_home: Path) -> None:
    ensure_home(safetwin_home)
    os.mkfifo(connection_path(), 0o600)
    started = time.monotonic()
    outcome = in_time(lambda: read_connection_file(connection_path()))
    assert isinstance(outcome, ConnectionFileError)
    assert "is not safe to use" in str(outcome)
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize("kind", ["fifo", "link", "folder"])
def test_a_lock_file_that_is_not_a_regular_file_is_refused(
    tmp_path: Path, safetwin_home: Path, kind: str
) -> None:
    ensure_home(safetwin_home)
    lock = safetwin_home / "engine.lock"
    if kind == "fifo":
        os.mkfifo(lock, 0o600)
    elif kind == "link":
        target = tmp_path / "elsewhere.lock"
        target.write_text("")
        lock.symlink_to(target)
    else:
        lock.mkdir()
    outcome = in_time(lambda: InstanceLock(safetwin_home).acquire())
    assert isinstance(outcome, ConnectionFileError)
    assert "the lock file" in str(outcome)
    assert "must be a regular file of yours" in str(outcome)


def test_a_lock_file_of_another_user_is_refused(safetwin_home: Path) -> None:
    assert InstanceLock(safetwin_home).acquire()  # makes the file; held by this process from now on
    other = InstanceLock(safetwin_home, uid=lambda: os.getuid() + 1)
    with pytest.raises(ConnectionFileError):
        other.acquire()


def test_the_token_is_not_in_the_repr() -> None:
    mine = info()
    assert mine.token not in repr(mine)


def test_a_missing_file_is_none(safetwin_home: Path) -> None:
    assert read_connection_file(connection_path()) is None


@pytest.mark.parametrize("bits", [0o644, 0o640, 0o604, 0o660, 0o700, 0o606])
def test_a_file_that_others_may_read_or_write_is_refused(safetwin_home: Path, bits: int) -> None:
    path = connection_path()
    write_connection_file(path, info())
    os.chmod(path, bits)
    if bits & 0o077:
        with pytest.raises(ConnectionFileError, match="is not safe to use"):
            read_connection_file(path)
    else:
        assert read_connection_file(path) is not None


def test_a_file_of_another_user_is_refused(safetwin_home: Path) -> None:
    path = connection_path()
    mine = info()
    write_connection_file(path, mine)
    # The folder is checked first, with the same user: another user's file in it is refused either way.
    with pytest.raises(ConnectionFileError, match="is not safe to use") as caught:
        read_connection_file(path, uid=lambda: os.getuid() + 1)
    assert mine.token not in str(caught.value)


def test_a_link_is_refused(tmp_path: Path, safetwin_home: Path) -> None:
    target = tmp_path / "elsewhere.json"
    write_connection_file(target, info())
    safetwin_home.mkdir(mode=0o700)
    connection_path().symlink_to(target)
    with pytest.raises(ConnectionFileError, match="if it is a link, delete it"):
        read_connection_file(connection_path())


@pytest.mark.parametrize(
    "text",
    [
        "not json at all CANARY",
        "[]",
        '{"version": "1", "pid": 1, "port": 2}',
        '{"version": "1", "pid": true, "port": 2, "token": "abcdefghijklmnopqrstuvwxyz", "started_at": "x"}',
        '{"version": "1", "pid": 1, "port": 70000, "token": "abcdefghijklmnopqrstuvwxyz", "started_at": "x"}',
        '{"version": "1", "pid": 1, "port": 2, "token": "short", "started_at": "x"}',
        '{"version": "1", "pid": 1, "port": 2, "token": "abcdefghijklmnop CANARY", "started_at": "x"}',
    ],
)
def test_a_damaged_file_is_refused_without_repeating_it(safetwin_home: Path, text: str) -> None:
    path = connection_path()
    safetwin_home.mkdir(mode=0o700)
    path.write_text(text)
    os.chmod(path, 0o600)
    with pytest.raises(ConnectionFileError, match="is damaged: delete it") as caught:
        read_connection_file(path)
    assert "CANARY" not in str(caught.value)


def test_the_file_is_removed_only_while_it_holds_this_engine(safetwin_home: Path) -> None:
    path = connection_path()
    mine = info()
    write_connection_file(path, mine)
    assert not remove_connection_file(path, info(token=new_token()))  # another token
    assert not remove_connection_file(path, info(pid=mine.pid + 1, token=mine.token))  # another pid
    assert path.exists()
    assert remove_connection_file(path, mine)
    assert not path.exists()
    assert not remove_connection_file(path, mine)  # gone already


def test_only_one_holder_of_the_instance_lock(safetwin_home: Path) -> None:
    first, second = InstanceLock(safetwin_home), InstanceLock(safetwin_home)
    assert first.acquire()
    assert mode(safetwin_home) == 0o700
    assert mode(safetwin_home / "engine.lock") == 0o600
    assert not second.acquire()
    first.release()
    with second:
        assert second.acquire()
        assert not first.acquire()
    assert first.acquire()
    first.release()


def test_the_instance_lock_is_let_go_when_its_process_ends(safetwin_home: Path) -> None:
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys, time; from pathlib import Path; from safetwin.api.connection import InstanceLock;"
            f"assert InstanceLock(Path({str(safetwin_home)!r})).acquire();"
            "print('held', flush=True); time.sleep(60)",
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "held"
        assert not InstanceLock(safetwin_home).acquire()
    finally:
        holder.kill()
        holder.wait()
    assert InstanceLock(safetwin_home).acquire()


def test_a_process_that_has_ended_is_not_alive() -> None:
    assert pid_alive(os.getpid())
    ended = subprocess.Popen([sys.executable, "-c", "pass"])
    ended.wait()
    assert not pid_alive(ended.pid)
    zombie = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 10
        while psutil.Process(zombie.pid).status() != psutil.STATUS_ZOMBIE:  # ended, not waited for yet
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert not pid_alive(zombie.pid)
    finally:
        zombie.wait()


# --- the client's errors ------------------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_nothing_listening_is_engine_not_running() -> None:
    with pytest.raises(EngineNotRunning, match=r"nothing answers on 127\.0\.0\.1:\d+"):
        get_status(info(port=free_port()))


def test_an_engine_that_does_not_answer_is_a_timeout() -> None:
    with socket.socket() as silent:
        silent.bind(("127.0.0.1", 0))
        silent.listen()  # connections wait in the backlog and nobody answers
        port = int(silent.getsockname()[1])
        with pytest.raises(EngineTimeout, match=r"did not answer within 0\.3 s"):
            get_status(info(port=port), timeout=0.3)


@pytest.fixture
def refusing_server() -> Iterator[int]:
    """A server that answers 401 to everything, as an engine with another token would."""

    class Refuse(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Refuse)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()


def test_a_401_is_a_refused_token_and_the_message_does_not_hold_the_token(refusing_server: int) -> None:
    mine = info(port=refusing_server)
    with pytest.raises(EngineRefusedToken, match="refused the token of the connection file") as caught:
        get_status(mine)
    assert mine.token not in str(caught.value)
