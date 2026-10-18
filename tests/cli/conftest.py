"""Fixtures for the tests of the safetwin command."""

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def safetwin_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The folder of the app is a folder of the test, so that no run touches the real one (it is not made)."""
    home = tmp_path / "safetwin-home"
    monkeypatch.setenv("SAFETWIN_HOME", str(home))
    return home
