"""A file writer that publishes its file only when told to (docs/guide.md, atomic writes).

The bytes go to a hidden temporary file next to the target. Only `commit()` gives them the real name, after
the file and its folder have been fsynced, so a reader never sees half a file, and a crash leaves at most a
hidden `.name.tmp-xxxx` file behind, never something with the real name.

A writer that is interrupted (Ctrl-C) at the wrong moment can leave its temporary file behind: in Python 3.12
a signal can raise `KeyboardInterrupt` just after `os.open` has made the file and before the writer knows
about it, or just after the writer is made and before its `with` block starts. So whoever runs a stage also
calls `remove_temporaries` when the stage fails, which finds them by name.

The syncs are `os.fsync`. On macOS that does not force the drive's own cache to its platters (`F_FULLFSYNC`
does, and is much slower); it is what docs/guide.md asks for, and the same as most software does.
"""

import errno
import hashlib
import io
import os
import re
import secrets
from collections.abc import Buffer, Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileCommit:
    """A committed file: its path, its size in bytes and the SHA-256 (hex) of its bytes."""

    path: Path
    bytes: int
    sha256: str


class CommitWriter(io.RawIOBase):
    """A binary file object that writes to `.<name>.tmp-<random>` and is published by `commit()`.

    It can be handed to anything that writes to a file object, such as Polars' `sink_parquet` or PyArrow's
    `ParquetWriter`. It counts the bytes and computes the SHA-256 as they arrive, and calls `on_progress`
    with the running number of bytes after every write (from whichever thread writes).

    - `commit()` flushes and fsyncs the file, renames it to `target` and fsyncs the folder, and returns a
      `FileCommit`. It refuses to replace an existing `target` unless `overwrite` is true. The missing
      folders of `target` are created (by the constructor).
    - `abort()` deletes the temporary file. So does `close()`, and so does leaving the `with` block, unless
      the file was committed: a writer that was never committed publishes nothing.

    Whoever holds the writer must not close it before `commit()`: that throws the file away.
    """

    def __init__(
        self, target: Path, *, overwrite: bool = False, on_progress: Callable[[int], None] | None = None
    ) -> None:
        super().__init__()
        self._fd: int | None = None  # set first: if the constructor fails, close() still works
        self._temp: Path | None = None
        self._commit: FileCommit | None = None
        self._target = target
        self._overwrite = overwrite
        self._on_progress = on_progress
        self._digest = hashlib.sha256()
        self._written = 0
        self._refuse_to_replace()
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_name(f".{target.name}.tmp-{secrets.token_hex(6)}")
        self._fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)  # 0o666 less the umask
        self._temp = temp

    def writable(self) -> bool:
        return True

    def write(self, data: Buffer) -> int:
        """Write all of `data` (bytes, bytearray or a memoryview) and return how many bytes that was."""
        if self._fd is None:
            raise ValueError("write to a file that was committed or aborted")
        view = memoryview(data).cast("B")
        done = 0
        while done < view.nbytes:
            done += os.write(self._fd, view[done:])
        self._digest.update(view)
        self._written += view.nbytes
        if self._on_progress is not None:
            self._on_progress(self._written)
        return view.nbytes

    def commit(self) -> FileCommit:
        """Publish the file under its real name. If this raises, nothing is published and nothing is left."""
        if self._commit is not None:
            raise ValueError("this file was committed already")
        if self._fd is None or self._temp is None:
            raise ValueError("this file was aborted")
        try:
            self.flush()
            os.fsync(self._fd)
            os.close(self._fd)
            self._fd = None
            if not self._overwrite:
                self._refuse_to_replace()  # again: somebody may have made the file while we were writing
            os.replace(self._temp, self._target)
        except BaseException:
            self.abort()
            raise
        try:
            _fsync_folder(self._target.parent)
        except BaseException:
            self._target.unlink(missing_ok=True)  # the rename is done, so take the real name away again
            raise
        self._temp = None
        self._commit = FileCommit(self._target, self._written, self._digest.hexdigest())
        super().close()
        return self._commit

    def abort(self) -> None:
        """Delete the temporary file. Does nothing for a file that was committed or aborted already."""
        fd, self._fd = self._fd, None
        temp, self._temp = self._temp, None
        if fd is not None:
            os.close(fd)
        if temp is not None:
            temp.unlink(missing_ok=True)
        super().close()

    def close(self) -> None:
        self.abort()

    def _refuse_to_replace(self) -> None:
        # lexists, not exists: a broken symlink with the name of the target is in the way too
        if not self._overwrite and os.path.lexists(self._target):
            raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), str(self._target))


def remove_temporaries(folder: Path, target: str) -> list[Path]:
    """Delete the temporary files that writers for a target in `folder` left behind, and return them.

    They are the hidden files `.<name>.tmp-<12 hex digits>` whose `<name>` fully matches the regular
    expression `target` (such as `re.escape("part-00000-r1.parquet")`). Only regular files are deleted, and
    what can't be deleted is left where it is: this runs while another error is on its way.
    """
    pattern = re.compile(rf"\.(?:{target})\.tmp-[0-9a-f]{{12}}")
    removed: list[Path] = []
    with suppress(OSError), os.scandir(folder) as entries:
        for entry in entries:
            if pattern.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                with suppress(OSError):
                    os.unlink(entry.path)
                    removed.append(Path(entry.path))
    return removed


def _fsync_folder(folder: Path) -> None:
    """Make the new name in `folder` durable. Some filesystems (FAT, network shares) can't sync a folder."""
    fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(fd)
    except OSError as err:
        if err.errno not in (errno.EINVAL, errno.ENOTSUP):
            raise
    finally:
        os.close(fd)
