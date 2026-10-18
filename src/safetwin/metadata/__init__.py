"""The metadata database: facts about pipelines and runs, never the data itself (docs/internals.md).

The tables are in ``safetwin.metadata.models``, imported explicitly when needed. The names below come from
``db`` and ``audit``, which need SQLAlchemy; they are imported when first used, so that the engine's control
plane can import ``safetwin.metadata.lite`` (sqlite3 only) without loading SQLAlchemy.
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .audit import ChainCheck, append_audit_event, verify_audit_chain
    from .db import PruneResult, open_metadata_db, prune, session_factory

_HOMES = {
    "ChainCheck": "audit",
    "append_audit_event": "audit",
    "verify_audit_chain": "audit",
    "PruneResult": "db",
    "open_metadata_db": "db",
    "prune": "db",
    "session_factory": "db",
}

__all__ = [
    "ChainCheck",
    "PruneResult",
    "append_audit_event",
    "open_metadata_db",
    "prune",
    "session_factory",
    "verify_audit_chain",
]


def __getattr__(name: str) -> Any:
    home = _HOMES.get(name)
    if home is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(f".{home}", __name__), name)
