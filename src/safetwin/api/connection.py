"""The connection file of the engine, and the lock that lets only one engine run (docs/internals.md).

`$SAFETWIN_HOME/engine.json` holds what a client needs to reach the running engine: {version, pid, port,
token, started_at}. The app and the `safetwin` command read it; the engine writes it once its socket is
listening and removes it when it stops cleanly, but only while it still holds this engine's pid and token.

- The folder must be a real folder (not a link) of the current user. It is made with mode 0700 if it is
  missing. The default folder, if it is there with group or other bits, is set back to 0700; a folder chosen
  with `$SAFETWIN_HOME` is refused instead, with a message that says to `chmod 700` it (`ensure_home`).
- The file is written with mode 0600 and replaced atomically (a new file opened with O_EXCL, fsync, then
  `os.replace`), so a reader never sees half a file.
- A reader trusts the file only if it is a regular file of the current user with no group or other permission
  bits, in a folder of the current user that nobody else may write (`read_connection_file`). Another user who
  could write either could point the CLI at an engine of theirs. Files are opened with O_NOFOLLOW and
  O_NONBLOCK, so neither a link nor a FIFO put in their place can redirect or hang a reader.
- `$SAFETWIN_HOME/engine.lock` is held with `fcntl.flock` for the whole life of the engine. Two starts can't
  both get it, and the system lets it go when the process ends, however it ends. The file itself stays, and
  must be a regular file of the current user.

The token is never put in an exception message, a log line or the repr of `ConnectionInfo`.

Standard library only: the `safetwin` command imports this without FastAPI. POSIX only for now (fcntl, uids).
"""

import fcntl
import hmac
import json
import os
import re
import secrets
import stat
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from safetwin.paths import safetwin_home, safetwin_home_is_explicit

CONNECTION_FILE = "engine.json"
LOCK_FILE = "engine.lock"
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{16,256}$")  # URL-safe base64, as `server.new_token` makes it
_MAX_FILE_BYTES = 64 * 1024


class ConnectionFileError(Exception):
    """The connection file can't be used. The message says why and what to do; it never holds the token."""


@dataclass(frozen=True)
class ConnectionInfo:
    """What the connection file holds. The token is left out of the repr."""

    version: str
    pid: int
    port: int
    token: str = field(repr=False)
    started_at: str  # ISO 8601, UTC

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2) + "\n"

    @classmethod
    def from_mapping(cls, raw: Any) -> Self:
        """The info in `raw` (the parsed file). Raises `ConnectionFileError` if a field is missing or bad."""
        if not isinstance(raw, dict):
            raise ConnectionFileError("the connection file is damaged")
        version, pid, port, token, started_at = (
            raw.get(name) for name in ("version", "pid", "port", "token", "started_at")
        )
        if (
            isinstance(version, str)
            and isinstance(pid, int)
            and isinstance(port, int)
            and not isinstance(pid, bool)
            and not isinstance(port, bool)
            and isinstance(token, str)
            and isinstance(started_at, str)
            and pid > 0
            and 0 < port < 65536
            and _TOKEN.match(token)
        ):
            return cls(version, pid, port, token, started_at)
        raise ConnectionFileError("the connection file is damaged")

    def holds(self, other: "ConnectionInfo") -> bool:
        """Whether this is the same engine as `other`: the same pid and token (compared in constant time)."""
        return self.pid == other.pid and hmac.compare_digest(self.token.encode(), other.token.encode())


def connection_path(home: Path | None = None) -> Path:
    """Where the connection file is: `engine.json` in `home` (the folder of the app if None)."""
    return (safetwin_home() if home is None else home) / CONNECTION_FILE


_OPEN_FLAGS = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)


def _current_uid(uid: Callable[[], int] | None) -> int:
    return os.getuid() if uid is None else uid()


def ensure_home(home: Path, *, explicit: bool | None = None, uid: Callable[[], int] | None = None) -> None:
    """Make the folder of the app if it is missing, and make sure it is safe to keep the token in.

    - Missing: it is made with mode 0700.
    - There: it must be a folder (not a link) of the user `uid()` (`os.getuid` if None).
    - There with group or other permission bits: the default folder of the app is set to 0700. A folder the
      user chose with `$SAFETWIN_HOME` (`explicit`; by default, whether `home` is the folder `$SAFETWIN_HOME`
      names) is not changed behind their back (it could be their home folder): it is refused.

    Raises `ConnectionFileError`, whose message says what to do. The checks and the chmod are made on one
    open descriptor of the folder (O_DIRECTORY, O_NOFOLLOW), so the folder can't be swapped in between.
    """
    if explicit is None:
        explicit = safetwin_home_is_explicit() and home == safetwin_home()
    created = False
    try:
        home.parent.mkdir(parents=True, exist_ok=True)
        home.mkdir(mode=0o700)
        created = True
    except FileExistsError:
        pass
    unsafe = ConnectionFileError(
        f"the folder of the app {home} is not safe to use: it must be a folder of yours (not a link). "
        "Fix it, or set SAFETWIN_HOME to another folder"
    )
    try:
        fd = os.open(home, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:  # a link (ELOOP), not a folder (ENOTDIR), not ours to open
        raise unsafe from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != _current_uid(uid):
            raise unsafe
        if stat.S_IMODE(info.st_mode) & 0o077:
            if explicit and not created:
                raise ConnectionFileError(
                    f"the folder of the app {home} (SAFETWIN_HOME) can be used by other users: run chmod 700 "
                    "on it, or set SAFETWIN_HOME to another folder"
                )
            os.fchmod(fd, 0o700)  # also what a new folder needs: mkdir's mode is cut down by the umask
    finally:
        os.close(fd)


def write_connection_file(path: Path, info: ConnectionInfo) -> None:
    """Write `info` to `path` atomically, with mode 0600 (its folder is made with `ensure_home` first)."""
    ensure_home(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        try:
            os.write(fd, info.to_json().encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    _fsync_folder(path.parent)


def _fsync_folder(folder: Path) -> None:
    """Make the rename in `folder` durable. Some file systems can't: that is not an error."""
    try:
        fd = os.open(folder, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def read_connection_file(path: Path, *, uid: Callable[[], int] | None = None) -> ConnectionInfo | None:
    """The info in the connection file, or None if there is none.

    The file is trusted only if it is a regular file (not a link, not a FIFO) that belongs to the user
    `uid()` and has no group or other permission bits, in a folder of that user that no one else may write;
    otherwise, or if it is damaged, this raises `ConnectionFileError`. `uid` gives the current user
    (`os.getuid` if None): tests play another user with it.
    """
    owner = _current_uid(uid)
    try:
        folder = os.lstat(path.parent)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(folder.st_mode) or folder.st_uid != owner or folder.st_mode & 0o022:
        raise ConnectionFileError(
            f"the folder of the connection file {path.parent} is not safe to use: it must be a folder of "
            "yours that no one else may write. Fix it, or set SAFETWIN_HOME to another folder"
        )
    try:
        fd = os.open(path, os.O_RDONLY | _OPEN_FLAGS)
    except FileNotFoundError:
        return None
    except OSError as err:
        raise ConnectionFileError(
            f"the connection file {path} can't be read ({os.strerror(err.errno) if err.errno else 'error'}): "
            "if it is a link, delete it"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
            raise ConnectionFileError(
                f"the connection file {path} is not safe to use: it must be a file of yours that only you "
                "can read and write (mode 0600). Delete it and start the engine again"
            )
        data = os.read(fd, _MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > _MAX_FILE_BYTES:
        raise ConnectionFileError(f"the connection file {path} is damaged: delete it")
    try:
        return ConnectionInfo.from_mapping(json.loads(data))
    except (ValueError, ConnectionFileError):  # a JSON error quotes the text: it is not repeated
        raise ConnectionFileError(f"the connection file {path} is damaged: delete it") from None


def remove_connection_file(path: Path, mine: ConnectionInfo) -> bool:
    """Delete the connection file if it still holds the engine `mine` (its pid and token). True if deleted."""
    try:
        found = read_connection_file(path)
    except ConnectionFileError:
        return False
    if found is None or not found.holds(mine):
        return False
    path.unlink(missing_ok=True)
    return True


def pid_alive(pid: int) -> bool:
    """Whether a process with this pid is running (a zombie, which has ended, is not)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # there, but another user's
        return True
    import psutil  # only here: the CLI does not load it otherwise

    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
    except psutil.Error:
        return True


class InstanceLock:
    """The lock that only one engine may hold: `flock` on `engine.lock` in the folder of the app.

    `acquire` returns False at once if another process holds it. It is held until `release` (or the end of
    the process). Use it as a context manager to release it however the block ends.
    """

    def __init__(self, home: Path, *, uid: Callable[[], int] | None = None) -> None:
        self.path = home / LOCK_FILE
        self._uid = uid
        self._fd: int | None = None

    def acquire(self) -> bool:
        """Take the lock: True, or False if another process holds it.

        Raises `ConnectionFileError` if the folder is not safe (`ensure_home`) or the lock file is not a
        regular file of the current user (a link, a FIFO, another user's file).
        """
        ensure_home(self.path.parent, uid=self._uid)
        unsafe = ConnectionFileError(
            f"the lock file {self.path} is not safe to use: it must be a regular file of yours (not a link). "
            "Delete it and start the engine again"
        )
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_RDWR | _OPEN_FLAGS, 0o600)
        except OSError:  # a link (ELOOP), a folder, no permission
            raise unsafe from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != _current_uid(self._uid):
                raise unsafe
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return True

    def release(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, kind: type[BaseException] | None, error: BaseException | None, trace: TracebackType | None
    ) -> None:
        self.release()
