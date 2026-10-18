"""Where the app keeps its own files. Standard library only, so that any part of the engine can import it."""

import os
import sys
from pathlib import Path


def safetwin_home() -> Path:
    """The folder of the app: `$SAFETWIN_HOME`, else `~/Library/Application Support/safetwin` on macOS and
    `~/.local/share/safetwin` elsewhere."""
    if configured := os.environ.get("SAFETWIN_HOME"):
        return Path(configured).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "safetwin"
    return Path.home() / ".local" / "share" / "safetwin"


def safetwin_home_is_explicit() -> bool:
    """Whether the folder of the app was chosen with `$SAFETWIN_HOME` (rather than being the default)."""
    return bool(os.environ.get("SAFETWIN_HOME"))
