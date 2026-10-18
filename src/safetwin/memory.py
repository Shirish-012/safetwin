"""How much memory a process holds: what the memory watchdog and the engine's status report.

On macOS this is `phys_footprint` (what Activity Monitor calls "Memory"), read with `proc_pid_rusage`
through ctypes because psutil does not expose it; elsewhere it is rss less the shared pages on Linux, and rss
on other systems. `dataplane/watchdog.py` explains why rss is the wrong measure on macOS: it counts the clean
pages of a mapped input file.

It also has the sizes of memory limits: `default_memory_limit` (a quarter of the physical memory), and
`parse_size` and `format_size` for what `--memory-limit` takes and what messages show.

This module needs only ctypes and psutil, so the control plane can use it without loading the data libraries.
"""

import ctypes
import ctypes.util
import os
import re
import sys
import threading
from collections.abc import Callable
from typing import Final, Literal

import psutil

Sampler = Callable[[], int]  # the memory of the process now, in bytes
MemoryKind = Literal["phys_footprint", "rss"]


class _RusageInfoV0(ctypes.Structure):
    """`struct rusage_info_v0` of macOS (sys/resource.h): the fields up to and with the footprint."""

    _fields_ = [
        ("ri_uuid", ctypes.c_uint8 * 16),
        ("ri_user_time", ctypes.c_uint64),
        ("ri_system_time", ctypes.c_uint64),
        ("ri_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_interrupt_wkups", ctypes.c_uint64),
        ("ri_pageins", ctypes.c_uint64),
        ("ri_wired_size", ctypes.c_uint64),
        ("ri_resident_size", ctypes.c_uint64),
        ("ri_phys_footprint", ctypes.c_uint64),
        ("ri_proc_start_abstime", ctypes.c_uint64),
        ("ri_proc_exit_abstime", ctypes.c_uint64),
    ]


def footprint_sampler(pid: int | None = None) -> Sampler | None:
    """The phys_footprint of process `pid` (this one if None) on macOS, or None if it can't be read here.

    Another process can be read only if it belongs to the same user.
    """
    if sys.platform != "darwin":
        return None
    try:
        libproc = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")
        rusage = libproc.proc_pid_rusage
    except (OSError, AttributeError):
        return None
    rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    rusage.restype = ctypes.c_int
    target = os.getpid() if pid is None else pid
    info = _RusageInfoV0()
    lock = threading.Lock()  # `info` is one buffer

    def footprint() -> int:
        with lock:
            if rusage(target, 0, ctypes.byref(info)) != 0:  # 0 is RUSAGE_INFO_V0
                raise OSError("proc_pid_rusage failed")
            return int(info.ri_phys_footprint)

    try:
        footprint()
    except OSError:
        return None
    return footprint


def resident_sampler(pid: int | None = None) -> Sampler:
    """The rss of process `pid` (this one if None), less the shared pages on Linux."""
    process = psutil.Process(pid)

    def resident() -> int:
        info = process.memory_info()
        return (
            int(info.rss - getattr(info, "shared", 0)) if sys.platform.startswith("linux") else int(info.rss)
        )

    return resident


def memory_sampler(pid: int | None = None) -> tuple[Sampler, MemoryKind]:
    """The best sampler for process `pid` (this one if None), and what it measures."""
    footprint = footprint_sampler(pid)
    if footprint is not None:
        return footprint, "phys_footprint"
    return resident_sampler(pid), "rss"


# --- sizes --------------------------------------------------------------------------------------------------

_UNITS: Final = {
    "B": 1,
    "KB": 1000,
    "MB": 1000**2,
    "GB": 1000**3,
    "TB": 1000**4,
    "KIB": 1024,
    "MIB": 1024**2,
    "GIB": 1024**3,
    "TIB": 1024**4,
}
_SIZE = re.compile(r"\s*(\d+(?:\.\d+)?)\s*([KMGT]i?B|B)\s*", re.IGNORECASE)


def default_memory_limit() -> int:
    """A quarter of the physical memory (the default memory limit of a run and of the engine)."""
    return psutil.virtual_memory().total // 4


def parse_size(text: str) -> int:
    """`512MB` or `2GiB` in bytes. MB and GB count in thousands and MiB and GiB in 1024s, as DuckDB's do.

    A unit is required, and the size must be more than 0 bytes. Raises `ValueError`, saying what to write.
    """
    match = _SIZE.fullmatch(text)
    if match is None:
        raise ValueError(f"'{text}' is not a size: write a number and a unit, such as 512MB or 2GB")
    size = int(float(match[1]) * _UNITS[match[2].upper()])
    if size < 1:
        raise ValueError(f"'{text}' is not a size: it must be more than 0 bytes")
    return size


def format_size(size: int) -> str:
    """`size` bytes as `400 MB` or `2.5 GB`."""
    if size >= 1000**3:
        return f"{size / 1000**3:.1f} GB"
    return f"{size / 1000**2:.0f} MB" if size >= 1000**2 else f"{size:,} bytes"
