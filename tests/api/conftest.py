"""Fixtures for the tests of the control API."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def safetwin_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The folder of the app is a folder of the test, so no test touches the real one (it is not made)."""
    home = tmp_path / "safetwin-home"
    monkeypatch.setenv("SAFETWIN_HOME", str(home))
    return home
