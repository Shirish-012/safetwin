"""A process that has run a stage with DuckDB in it can end, however the stage ended.

Measured with DuckDB 1.5.6 and PyArrow 25: a DuckDB query that reads a stream from Python and is dropped
while it is still running (the writer failed, or a `LIMIT` was reached) leaves work in the thread pool of
Arrow, and the process then waits for it for ever when it ends, after the last line of the program has run.
`hybrid.py` ends such a query on purpose. Each of these stages is run in a process of its own, which has to
end in time.
"""

import subprocess
import sys
from pathlib import Path

import polars as pl
import pytest

CHILD = Path(__file__).with_name("exit_scenarios.py")
ROWS = 1_000_000
SECONDS = 120  # a stage takes a few seconds: a process that is not done after this is waiting for ever

OUTCOMES = {
    "success": f"rows {ROWS}",
    "limit": "rows 10",
    "writer_fails": "failed in the writer",
    "two_steps_writer_fails": "failed in the writer",
    "polars_between_fails": "failed in the writer",
    "step_after_fails": "failed with InvalidOperationError",
    "step_before_fails": "failed with InvalidOperationError",
    "out_of_memory": "out of memory",
}


@pytest.fixture(scope="module")
def csv_folder(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("exit") / "in"
    folder.mkdir()
    pl.DataFrame(
        {
            "id": range(ROWS),
            "name": [f"name {i % 1000}" for i in range(ROWS)],
            "amount": [i % 977 for i in range(ROWS)],
        }
    ).write_csv(folder / "big.csv")
    return folder


@pytest.mark.parametrize("scenario", OUTCOMES)
def test_a_process_ends_after_a_stage_that_failed_or_gave_up_halfway(
    tmp_path: Path, csv_folder: Path, scenario: str
) -> None:
    folder = tmp_path / "run"
    (folder / "out").mkdir(parents=True)
    (folder / "in").symlink_to(csv_folder)
    try:
        done = subprocess.run(
            [sys.executable, "-W", "ignore", str(CHILD), scenario, str(folder)],
            capture_output=True,
            text=True,
            timeout=SECONDS,
            check=False,
            env={"PATH": "/usr/bin:/bin", "SAFETWIN_HOME": str(tmp_path / "home")},
        )
    except subprocess.TimeoutExpired as hung:
        output = (hung.stdout or b"").decode(errors="replace").strip().splitlines()
        pytest.fail(f"the process did not end in {SECONDS} s; it had printed {output[-1:]}")
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.strip().splitlines()[-1] == OUTCOMES[scenario]
    assert sorted(path.name for path in folder.iterdir()) == ["in", "out"]  # nothing else was written there
    assert not [path for path in (folder / "out").rglob("*") if path.is_file()] or scenario in (
        "success",
        "limit",
    )
