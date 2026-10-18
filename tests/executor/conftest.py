"""Fixtures for the tests of the executor."""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def safetwin_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The folder of the app is a folder of the test, made with mode 0700, so no test touches the real one."""
    home = tmp_path / "safetwin-home"
    home.mkdir(mode=0o700)
    os.chmod(home, 0o700)
    monkeypatch.setenv("SAFETWIN_HOME", str(home))
    return home
