"""Postgres and Excel sources and targets, through the staging folder (masking/staging.py).

Postgres runs on an embedded server (the `pgserver` wheel, a dev requirement), or on the server of
`SAFETWIN_TEST_PG_URL` when it is set (an empty database the tests may fill: its schemas `public` and
`safe_copy` are dropped and made again). Without either, the Postgres tests are skipped.
"""

import json
import os
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import polars as pl
import pytest
import xlsxwriter
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.masking import staging
from safetwin.masking.scan import make_reversible, render
from safetwin.masking.scan import scan as run_scan
from safetwin.spec.policy import load_policy_text, validate_policy

from .test_export import policy_file
from .test_mask_run import KEY, _generator

cli = CliRunner()


@pytest.fixture(scope="module")
def shop(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert _generator().main([str(folder)]) == 0
    return folder


@pytest.fixture(autouse=True)
def private_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Staging folders go to a temporary folder of the test's own, so a test can count them."""
    folder = tmp_path / "system-temp"
    folder.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(folder))
    return folder


def staged(folder: Path) -> list[Path]:
    return [p for p in folder.iterdir() if p.name.startswith(staging.STAGE_PREFIX)]


# --- Postgres -----------------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url(shop: Path) -> Iterator[str]:
    server = None
    url = os.environ.get("SAFETWIN_TEST_PG_URL", "")
    if not url:
        pgserver = pytest.importorskip("pgserver")
        data = Path(tempfile.mkdtemp(prefix="st-pg-"))  # short: the server's socket path has a length limit
        server = pgserver.get_server(data, cleanup_mode="delete")
        url = server.get_uri()
    connection = staging.connect(url, read_only=False)
    with connection.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS safe_copy CASCADE")
        cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
        cur.execute("CREATE SCHEMA public")
        for table in ("customers", "orders"):
            cur.adbc_ingest(table, pl.read_parquet(shop / f"{table}.parquet").to_arrow(), mode="replace")
        cur.execute("ALTER TABLE customers ADD PRIMARY KEY (id)")
        cur.execute("ALTER TABLE orders ADD PRIMARY KEY (id)")
        cur.execute("ALTER TABLE orders ADD FOREIGN KEY (customer_id) REFERENCES customers (id)")
    connection.commit()
    connection.close()
    yield url
    if server is not None:
        server.cleanup()


def pg_policy(tmp_path: Path, url: str, target: str) -> Path:
    """The draft `scan --postgres` writes, with `target` as its target line."""
    path = tmp_path / "masking.yaml"
    done = cli.invoke(app, ["scan", "--postgres", "env://PGURL", "--output", str(path)], env={"PGURL": url})
    assert done.exit_code == 0, done.output
    text = path.read_text(encoding="utf-8")
    text, count = re.subn(r"(?m)^  target: .*$", f"  target: {target}", text)
    assert count == 1
    path.write_text(text, encoding="utf-8")
    return path


def mask(policy: Path, url: str, *options: str) -> Any:
    return cli.invoke(app, ["mask", str(policy), *options], env={"SAFETWIN_KEY": KEY, "PGURL": url})


def password_free(text: str, url: str) -> None:
    assert url not in text
    assert "postgresql://" not in text


def test_scan_drafts_a_policy_with_the_database_foreign_keys(pg_url: str, tmp_path: Path) -> None:
    path = tmp_path / "masking.yaml"
    done = cli.invoke(
        app, ["scan", "--postgres", "env://PGURL", "--output", str(path)], env={"PGURL": pg_url}
    )
    assert done.exit_code == 0, done.output
    password_free(done.output, pg_url)
    text = path.read_text(encoding="utf-8")
    assert "source: { postgres: env://PGURL, schema: public }" in text
    assert "- orders.customer_id -> customers.id" in text
    assert "customers:  # 1,000 rows" in text
    assert "orders:  # 3,000 rows" in text
    assert not staged(Path(tempfile.gettempdir()))

    refused = cli.invoke(app, ["scan", "--postgres", pg_url])
    assert refused.exit_code != 0
    assert "never the URL itself" in " ".join(refused.output.replace("│", " ").split())
    password_free(refused.output, pg_url)


def test_mask_to_files_reads_the_whole_table_and_names_the_source(pg_url: str, tmp_path: Path) -> None:
    policy = pg_policy(tmp_path, pg_url, '{ folder: "./safe" }')
    checked = cli.invoke(app, ["check", str(policy)], env={"SAFETWIN_KEY": KEY, "PGURL": pg_url})
    assert checked.exit_code == 0, checked.output
    done = mask(policy, pg_url)
    assert done.exit_code == 0, done.output
    password_free(done.output, pg_url)
    report = json.loads((tmp_path / "safe" / "report.json").read_text(encoding="utf-8"))
    assert report["source"].startswith("Postgres at ")
    assert report["source"].endswith(", schema public")
    password_free(json.dumps(report), pg_url)
    customers = pl.read_parquet(next((tmp_path / "safe" / "customers").glob("*.parquet")))
    assert customers.height == 1000
    assert "notes" not in customers.columns  # the draft drops it
    assert not staged(Path(tempfile.gettempdir()))


def test_mask_into_a_schema_adds_the_keys_back_and_needs_replace(pg_url: str, tmp_path: Path) -> None:
    policy = pg_policy(tmp_path, pg_url, '{ folder: "./report", postgres: env://PGURL, schema: safe_copy }')
    done = mask(policy, pg_url)
    assert done.exit_code == 0, done.output
    report = json.loads((tmp_path / "report" / "report.json").read_text(encoding="utf-8"))
    assert report["delivered"]["schema"] == "safe_copy"
    assert report["delivered"]["tables"] == {"customers": 1000, "orders": 3000}
    assert report["files"] == []
    assert "safe_copy" in (tmp_path / "report" / "report.html").read_text(encoding="utf-8")

    connection = staging.connect(pg_url, read_only=True)
    try:
        facts = staging.read_facts(connection, "safe_copy")
        assert facts.tables == ["customers", "orders"]
        assert facts.primary_keys == {"customers": ["id"], "orders": ["id"]}
        assert facts.foreign_keys == [("orders", "customer_id", "customers", "id")]
        assert staging.count_rows(connection, "safe_copy", "orders") == 3000
    finally:
        connection.close()

    again = mask(policy, pg_url)
    assert again.exit_code != 0
    assert "--replace" in again.output
    replaced = mask(policy, pg_url, "--replace")
    assert replaced.exit_code == 0, replaced.output
    assert not staged(Path(tempfile.gettempdir()))


def test_the_target_schema_must_not_be_the_source(pg_url: str, tmp_path: Path) -> None:
    policy = pg_policy(tmp_path, pg_url, '{ folder: "./report", postgres: env://PGURL, schema: public }')
    done = mask(policy, pg_url)
    assert done.exit_code != 0
    assert "must not be the source schema" in done.output


def test_a_wrong_url_is_named_by_host_never_by_password(pg_url: str, tmp_path: Path) -> None:
    policy = pg_policy(tmp_path, pg_url, '{ folder: "./safe" }')
    wrong = "postgresql://someone:hunter2-secret@127.0.0.1:1/nowhere"
    done = mask(policy, wrong)
    assert done.exit_code != 0
    assert "Postgres at 127.0.0.1:1/nowhere" in done.output
    assert "hunter2" not in done.output
    assert "someone" not in done.output
    assert not staged(Path(tempfile.gettempdir()))


def test_a_table_the_schema_lacks_is_named(pg_url: str, tmp_path: Path) -> None:
    policy = pg_policy(tmp_path, pg_url, '{ folder: "./safe" }')
    text = policy.read_text(encoding="utf-8").replace("    orders:", "    invoices:")
    text = text.replace("orders.customer_id", "invoices.customer_id")
    policy.write_text(text, encoding="utf-8")
    done = mask(policy, pg_url)
    assert done.exit_code != 0
    assert "table 'invoices' is not in the schema public" in done.output
    assert not staged(Path(tempfile.gettempdir()))


def test_export_refuses_a_postgres_policy(pg_url: str, tmp_path: Path) -> None:
    policy = pg_policy(tmp_path, pg_url, '{ folder: "./safe" }')
    done = cli.invoke(app, ["export", str(policy), "--to", "polars", "-o", str(tmp_path / "mask.py")])
    assert done.exit_code != 0
    assert "Postgres" in done.output
    assert not (tmp_path / "mask.py").exists()


def test_the_staging_folder_is_private_and_removed_on_failure(tmp_path: Path) -> None:
    root = Path(tempfile.gettempdir())
    seen: list[Path] = []

    def fail() -> None:
        with staging.staging_folder() as folder:
            seen.append(folder)
            assert folder.stat().st_mode & 0o777 == 0o700
            (folder / "t.parquet").write_bytes(b"x")
            raise RuntimeError

    with pytest.raises(RuntimeError):
        fail()
    assert seen
    assert not staged(root)


def test_a_policy_with_the_url_itself_is_refused_without_showing_it(tmp_path: Path) -> None:
    url = "postgresql://someone:hunter2-secret@db.example/app"
    text = f"""apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {{ name: inline }}
spec:
  source: {{ postgres: "{url}", schema: public }}
  target: {{ folder: ./safe, postgres: "{url}", schema: safe_copy }}
  key: env://SAFETWIN_KEY
  tables:
    t: {{ id: keep }}
"""
    problems = validate_policy(load_policy_text(text))
    assert [p.code for p in problems] == ["url_reference", "url_reference"]
    assert not any("hunter2" in p.message or "someone" in p.message for p in problems)
    done = cli.invoke(app, ["check", str(policy_file(tmp_path, text))], env={"SAFETWIN_KEY": KEY})
    assert done.exit_code == 1
    assert "hunter2" not in done.output


def test_where_never_shows_the_user_or_password() -> None:
    url = "postgresql://u:p@db.example:5433/app?sslmode=require"
    assert staging.where(url) == "Postgres at db.example:5433/app"
    assert staging.where("postgresql:///app") == "Postgres at localhost/app"


# --- Excel --------------------------------------------------------------------------------------------------


@pytest.fixture
def workbooks(shop: Path, tmp_path: Path) -> Path:
    """`in/shop.xlsx` with the sheets customers and orders, and `in/vip.xlsx` with one sheet."""
    folder = tmp_path / "in"
    folder.mkdir()
    with xlsxwriter.Workbook(folder / "shop.xlsx") as book:
        for table in ("customers", "orders"):
            frame = pl.read_parquet(shop / f"{table}.parquet")
            staging.for_excel(frame).write_excel(book, worksheet=table)
    pl.DataFrame({"code": [1, 2, 3], "big": [2**60, 5, 2**53 + 1], "label": ["a", "b", "c"]}).with_columns(
        pl.col("big").cast(pl.String)
    ).write_excel(folder / "vip.xlsx", worksheet="Sheet1")
    return folder


def excel_policy(folder: Path, tmp_path: Path, *, reversible: bool = False) -> Path:
    result = run_scan(folder, fmt="xlsx")
    if reversible:
        make_reversible(result)
    text = render(result, source=str(folder), name="xl", target=str(tmp_path / "safe"), target_format="xlsx")
    return policy_file(tmp_path, text)


def test_a_workbook_with_several_sheets_is_a_table_per_sheet(workbooks: Path) -> None:
    assert sorted(staging.excel_tables(workbooks)) == ["shop_customers", "shop_orders", "vip"]
    result = run_scan(workbooks, fmt="xlsx")
    assert result.tables["shop_customers"].rows == 1000
    assert result.tables["shop_orders"].rows == 3000
    assert not staged(Path(tempfile.gettempdir()))


def test_mask_to_excel_writes_a_workbook_per_table(workbooks: Path, tmp_path: Path) -> None:
    policy = excel_policy(workbooks, tmp_path)
    done = cli.invoke(app, ["mask", str(policy)], env={"SAFETWIN_KEY": KEY})
    assert done.exit_code == 0, done.output
    safe = tmp_path / "safe"
    books = ["shop_customers.xlsx", "shop_orders.xlsx", "vip.xlsx"]
    assert sorted(p.name for p in safe.glob("*.xlsx")) == books
    report = json.loads((safe / "report.json").read_text(encoding="utf-8"))
    assert report["delivered"]["tables"]["shop_orders"] == 3000
    assert sorted(f["path"] for f in report["files"]) == books
    orders = pl.read_excel(safe / "shop_orders.xlsx", engine="calamine")
    assert orders.height == 3000
    assert not staged(Path(tempfile.gettempdir()))

    again = cli.invoke(app, ["mask", str(policy)], env={"SAFETWIN_KEY": KEY})
    assert again.exit_code != 0
    assert "--replace" in again.output


def test_for_excel_writes_big_integers_as_text() -> None:
    frame = pl.DataFrame({"small": [1, 2], "big": [2**53, 1], "neg": [-(2**60), 0]})
    out = staging.for_excel(frame)
    assert out["small"].dtype == pl.Int64
    assert out["big"].to_list() == [str(2**53), "1"]
    assert out["neg"].dtype == pl.String


def test_a_reversible_excel_twin_reads_back_exactly(workbooks: Path, tmp_path: Path) -> None:
    policy = excel_policy(workbooks, tmp_path, reversible=True)
    done = cli.invoke(app, ["mask", str(policy)], env={"SAFETWIN_KEY": KEY})
    assert done.exit_code == 0, done.output
    back = cli.invoke(
        app,
        ["unmask", str(tmp_path / "safe"), "--policy", str(policy), "--out", str(tmp_path / "r")],
        env={"SAFETWIN_KEY": KEY},
    )
    assert back.exit_code == 0, back.output
    for table, (book, sheet) in staging.excel_tables(workbooks).items():
        original = pl.read_excel(book, sheet_name=sheet, engine="calamine")
        readable = pl.read_excel(tmp_path / "r" / f"{table}.xlsx", engine="calamine")
        assert readable.columns == original.columns, table
        for column in original.columns:
            assert readable[column].equals(original[column]), (table, column)
