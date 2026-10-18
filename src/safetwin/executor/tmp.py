"""The private temporary folder of each stage worker (docs/internals.md, docs/security.md).

Every worker gets `$SAFETWIN_HOME/tmp/<worker id>/`, a new, empty folder that only its user may open (0700),
and its TMPDIR and POLARS_TEMP_DIR point there from before Python starts, so `tempfile`, Polars and anything
else that honours them write nowhere else. The control plane deletes the folder when the worker ends, however
it ends. Next to the folder, `<worker id>.pid` (0600) records the worker's pid and the time its process
started, so that a pid used again by another process is not taken for the worker.

Folders that an engine which crashed (or was killed) left behind are deleted when the next engine starts
(`remove_stale`), which it does only once it holds the engine's lock, so it never touches the folders of an
engine that runs. A worker of the dead engine may still be running then: it ends by itself at most two of
the engine's cancel grace periods after its stdin closed (one, unless a commit was under way: `worker.py`),
but the next engine can start sooner. So a folder whose worker is still alive (its pid file names a running
process that started at that time) is kept, and the engine tries again later for those
(`remove_stale(..., only=kept)`).

Deleting never follows a link: a link (or a file) where a folder should be is removed itself, and the rest
is removed with `shutil.rmtree`, which on this system does not follow links inside the tree either (it works
on file descriptors: `shutil.rmtree.avoids_symlink_attacks`).

Whatever sits where a pid file should be is removed with the folder, the same way and without following a
link: a link, a file, or a folder named `<worker id>.pid` (with what is in it). The engine never makes such a
folder, so it is debris, and it is removed rather than kept for ever.

Standard library and psutil (the start time of a process) only.
"""

import os
import re
import shutil
import stat
from collections.abc import Collection
from contextlib import suppress
from pathlib import Path
from typing import Final

import psutil

TMP_DIR: Final = "tmp"
WORKER_ID = re.compile(r"^w[0-9a-f]{8,32}$")


class TmpFolderError(Exception):
    """The temporary folder of the engine can't be used safely. The message says why."""


def tmp_root(home: Path) -> Path:
    """`$SAFETWIN_HOME/tmp`: where the folders of the workers are."""
    return home / TMP_DIR


def ensure_tmp_root(home: Path) -> Path:
    """Make `tmp/` in the folder of the app if it is missing, and make sure it is a real folder of this user
    with mode 0700. A link or a file in its place is removed first. Raises `TmpFolderError`."""
    root = tmp_root(home)
    with suppress(FileNotFoundError):
        info = os.lstat(root)
        if not stat.S_ISDIR(info.st_mode):  # a link (to anywhere) or a file: not ours to follow
            os.unlink(root)
    with suppress(FileExistsError):
        os.mkdir(root, 0o700)
    _check_private_folder(root)
    return root


def make_worker_tmp(home: Path, worker_id: str) -> Path:
    """A new, empty folder for the worker `worker_id`, mode 0700. Raises `TmpFolderError` (or `OSError`)."""
    if not WORKER_ID.fullmatch(worker_id):
        raise ValueError("a worker id is w and 8 to 32 hex digits")
    folder = ensure_tmp_root(home) / worker_id
    os.mkdir(folder, 0o700)  # FileExistsError if it is there: the id is random, so that is never expected
    _check_private_folder(folder)
    return folder


def _check_private_folder(folder: Path) -> None:
    """The folder is a real folder of this user; set it to 0700 (mkdir's mode is cut down by the umask)."""
    fd = os.open(folder, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise TmpFolderError(f"{folder} is not a folder of yours: delete it")
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.fchmod(fd, 0o700)
    finally:
        os.close(fd)


def remove_tree(path: Path) -> bool:
    """Delete `path` and everything below it, without following any link. True if nothing is left.

    A link is removed, not followed; so is a file. Errors are not raised (this runs while a worker is being
    cleaned up, whatever went wrong): what could not be removed is left, and the result says so.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        with suppress(OSError):
            os.unlink(path)
    else:
        shutil.rmtree(path, ignore_errors=True)
    return not os.path.lexists(path)


def pid_file(home: Path, worker_id: str) -> Path:
    return tmp_root(home) / f"{worker_id}.pid"


def write_worker_pid(home: Path, worker_id: str, pid: int) -> None:
    """Record the pid of a worker, and when its process started, next to its folder (mode 0600)."""
    try:
        started = psutil.Process(pid).create_time()
    except psutil.Error:
        started = 0.0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(pid_file(home, worker_id), flags, 0o600)
    try:
        os.write(fd, f"{pid} {started!r}\n".encode())
    finally:
        os.close(fd)


def remove_worker_files(home: Path, worker_id: str) -> bool:
    """Delete the folder of a worker and its pid file (or whatever is in its place: `remove_tree` follows no
    link). True if nothing is left."""
    gone = remove_tree(tmp_root(home) / worker_id)
    return remove_tree(pid_file(home, worker_id)) and gone


def worker_alive(home: Path, worker_id: str) -> bool:
    """Whether the worker that the pid file names is still running (the same process: same start time)."""
    path = pid_file(home, worker_id)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        pid_text, _, started_text = os.read(fd, 100).decode("ascii", "replace").strip().partition(" ")
    finally:
        os.close(fd)
    try:
        pid, started = int(pid_text), float(started_text)
        process = psutil.Process(pid)
        return process.status() != psutil.STATUS_ZOMBIE and abs(process.create_time() - started) < 0.01
    except (ValueError, psutil.Error):
        return False


def remove_stale(home: Path, only: Collection[str] | None = None) -> tuple[list[str], list[str]]:
    """Delete what an engine that did not stop cleanly left in `$SAFETWIN_HOME/tmp/`: the names that were
    removed, and the folders that were kept because their worker still runs. With `only`, just those names.

    Call it only while holding the engine's lock, before this engine starts a worker (or with `only`).
    """
    root = tmp_root(home)
    try:
        info = os.lstat(root)
    except FileNotFoundError:
        return [], []
    if not stat.S_ISDIR(info.st_mode):
        remove_tree(root)
        return [], []
    try:
        with os.scandir(root) as entries:
            names = sorted(entry.name for entry in entries)
    except OSError:
        return [], []
    removed: list[str] = []
    kept: list[str] = []
    for name in names:
        if name.endswith(".pid") and WORKER_ID.fullmatch(name[:-4]):
            continue  # with its folder, below (or alone, if the folder is gone)
        if only is not None and name not in only:
            continue
        if WORKER_ID.fullmatch(name):
            if worker_alive(home, name):
                kept.append(name)
            elif remove_worker_files(home, name):
                removed.append(name)
        elif remove_tree(root / name):
            removed.append(name)
    for name in names:  # a pid file whose folder is gone
        worker_id = name[:-4]
        if (
            name.endswith(".pid")
            and WORKER_ID.fullmatch(worker_id)
            and (only is None or worker_id in only)
            and worker_id not in names  # (a folder that was there was handled above, with its pid file)
            and not worker_alive(home, worker_id)
            and remove_worker_files(home, worker_id)
        ):
            removed.append(name)
    return removed, kept
