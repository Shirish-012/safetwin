"""`safetwin ui`: its guard (host, token, cookie, header) and a mask → unmask round trip through its API."""

import io
import json
import os
import stat
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import polars as pl
import pytest
from fastapi.testclient import TestClient

from safetwin.demo import main as make_demo
from safetwin.ui.server import Workspace, create_app

PORT = 54321
TOKEN = "t" * 43
SAFE = {"X-Safetwin": "1"}


@pytest.fixture
def workspace() -> Iterator[Workspace]:
    space = Workspace()
    yield space
    space.close()


@pytest.fixture
def client(tmp_path: Path, workspace: Workspace) -> TestClient:
    app = create_app(TOKEN, PORT, tmp_path / "home" / "ui.key", workspace)
    return TestClient(app, base_url=f"http://127.0.0.1:{PORT}")


@pytest.fixture
def logged_in(client: TestClient) -> TestClient:
    assert client.post("/api/login", json={"token": TOKEN}).status_code == 200
    return client


@pytest.fixture(scope="module")
def shop_csv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert make_demo([str(folder / "demo"), "--csv"]) == 0
    return folder / "demo"


def test_the_guard(client: TestClient, tmp_path: Path) -> None:
    assert client.get("/").status_code == 200  # the page itself holds no data
    assert "script-src 'self'" in client.get("/").headers["content-security-policy"]
    assert client.get("/api/state").status_code == 401
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 421
    assert client.post("/api/login", json={"token": "wrong"}).status_code == 401
    assert client.post("/api/login", json={"token": TOKEN}).status_code == 200
    assert client.post("/api/jobs").status_code == 403  # no X-Safetwin header: another site can't send one
    state = client.get("/api/state").json()
    assert set(state) == {"key_file", "key"}
    assert state["key"]["source"] == "computer"
    key_file = tmp_path / "home" / "ui.key"
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert key_file.read_text().strip() not in str(state)


def test_mask_then_unmask(logged_in: TestClient, shop_csv: Path, workspace: Workspace) -> None:
    c = logged_in
    job = c.post("/api/jobs", headers=SAFE).json()["id"]
    for name in ("customers.csv", "orders.csv"):
        put = c.put(f"/api/jobs/{job}/files/{name}", content=(shop_csv / name).read_bytes(), headers=SAFE)
        assert put.status_code == 200
    assert c.put(f"/api/jobs/{job}/files/notes.txt", content=b"x", headers=SAFE).status_code == 400
    plan = c.post(f"/api/jobs/{job}/scan", headers=SAFE).json()
    assert [t["name"] for t in plan["tables"]] == ["customers", "orders"]
    assert plan["relationships"] == ["orders.customer_id -> customers.id"]

    missing = c.post(f"/api/jobs/{job}/mask", headers=SAFE, json={"choices": {"customers": "reversible"}})
    assert missing.status_code == 400
    assert "every file" in missing.json()["error"]

    choices = {"customers": "reversible", "orders": "one-way"}
    done = c.post(f"/api/jobs/{job}/mask", headers=SAFE, json={"choices": choices, "picked": {}})
    assert done.status_code == 200, done.text
    result = done.json()
    assert result["ok"]
    assert result["orphans"] == 0
    assert result["classes"]["customers"]["email"] == "encrypted"
    assert result["classes"]["customers"]["id"] == "pseudonymized"  # it links to the one-way orders
    assert "encrypted" not in result["classes"]["orders"].values()
    archive = zipfile.ZipFile(io.BytesIO(c.get(f"/api/jobs/{job}/download/masked.zip").content))
    assert sorted(archive.namelist()) == [
        "customers.csv",
        "masking.yaml",
        "orders.csv",
        "report.html",
        "report.json",
    ]
    report = c.get(f"/api/jobs/{job}/report")
    assert "sandbox" in report.headers["content-security-policy"]

    back = c.post("/api/jobs", headers=SAFE).json()["id"]
    for name in ("customers.csv", "orders.csv", "report.json"):  # the report names the ff1 columns
        c.put(f"/api/jobs/{back}/files/{name}", content=archive.read(name), headers=SAFE)
    access = c.get("/api/access-key").text.strip()
    read = c.post(f"/api/jobs/{back}/unmask", headers=SAFE, json={"access_key": access})
    assert read.status_code == 200, read.text
    tables = {t["name"]: t for t in read.json()["tables"]}
    found = {d["column"]: d["algorithm"] for d in tables["customers"]["decrypted"]}
    assert found["email"] == "aes-siv"  # detected from the value, nothing chosen by hand
    assert found["phone"] == "ff1"  # named by the report.json
    assert tables["orders"]["decrypted"] == []
    readable = zipfile.ZipFile(io.BytesIO(c.get(f"/api/jobs/{back}/download/readable.zip").content))
    original = pl.read_csv(shop_csv / "customers.csv", infer_schema=False)
    again = pl.read_csv(io.BytesIO(readable.read("customers.csv")), infer_schema=False)
    for column in ("full_name", "email", "phone", "notes"):
        assert again[column].equals(original[column]), column

    wrong = c.post(f"/api/jobs/{back}/unmask", headers=SAFE, json={"access_key": "ab" * 32})
    assert wrong.status_code == 400
    message = wrong.json()["error"]
    assert "masked with the access key" in message  # the report's fingerprint refuses it before decrypting
    assert not any(v in message for v in original["email"].drop_nulls().to_list())

    folder = workspace.jobs[job].folder
    assert c.delete(f"/api/jobs/{job}", headers=SAFE).json() == {"ok": True}
    assert not folder.exists()
    assert c.get(f"/api/jobs/{job}/report").status_code == 404


def _job(c: TestClient, folder: Path, names: tuple[str, ...]) -> str:
    job: str = c.post("/api/jobs", headers=SAFE).json()["id"]
    for name in names:
        put = c.put(f"/api/jobs/{job}/files/{name}", content=(folder / name).read_bytes(), headers=SAFE)
        assert put.status_code == 200, put.text
    return job


def _columns(plan: dict[str, Any], table: str) -> dict[str, dict[str, Any]]:
    (found,) = [t for t in plan["tables"] if t["name"] == table]
    return {c["name"]: c for c in found["columns"]}


def test_the_method_picker_preview_progress_and_history(
    logged_in: TestClient, shop_csv: Path, tmp_path: Path
) -> None:
    c = logged_in
    job = _job(c, shop_csv, ("customers.csv", "orders.csv"))
    plan = c.post(f"/api/jobs/{job}/scan", headers=SAFE).json()
    customers = _columns(plan, "customers")
    email = customers["email"]
    ids = [o["id"] for o in email["options"]]
    assert email["default"] == "fake_email"
    assert {"keep", "code", "fake_name", "last4", "hide", "null", "drop"} <= set(ids)
    assert [o["id"] for o in customers["id"]["options"]] == ["suggested", "keep"]  # it links the files

    choices = {"customers": "reversible", "orders": "one-way"}
    mismatch = {"customers": {"id": "keep"}}
    refused = c.post(f"/api/jobs/{job}/preview", headers=SAFE, json={"choices": choices, "picked": mismatch})
    assert refused.status_code == 400
    assert "mask both or keep both" in refused.json()["error"]
    bad = c.post(
        f"/api/jobs/{job}/preview", headers=SAFE, json={"choices": choices, "picked": {"orders": {"id": "x"}}}
    )
    assert bad.status_code == 400

    picked = {"customers": {"phone": "drop", "full_name": "keep"}, "orders": {"card_number": "hide"}}
    body = {"choices": choices, "picked": picked}
    preview = c.post(f"/api/jobs/{job}/preview", headers=SAFE, json=body)
    assert preview.status_code == 200, preview.text
    tables = {t["name"]: t for t in preview.json()["tables"]}
    assert "phone" not in tables["customers"]["columns"]  # dropped stays dropped in a reversible file
    original = pl.read_csv(shop_csv / "customers.csv", infer_schema=False).head(5)
    names = tables["customers"]["columns"]
    rows = tables["customers"]["rows"]
    assert len(rows) == 5
    assert [r[names.index("full_name")] for r in rows] == original["full_name"].to_list()  # kept
    assert all(r[names.index("email")].startswith("st1.") for r in rows)  # encrypted
    orders = tables["orders"]
    assert {r[orders["columns"].index("card_number")] for r in orders["rows"]} == {"REDACTED"}

    assert c.get(f"/api/jobs/{job}/progress").json() == {"phase": "idle"}
    done = c.post(f"/api/jobs/{job}/mask", headers=SAFE, json=body)
    assert done.status_code == 200, done.text
    result = done.json()
    assert result["ok"]
    assert result["classes"]["customers"]["email"] == "encrypted"
    assert (
        "phone" not in result["classes"]["customers"] or result["classes"]["customers"]["phone"] == "removed"
    )
    assert result["classes"]["orders"]["card_number"] == "removed"  # fixed text: nothing of the value
    progress = c.get(f"/api/jobs/{job}/progress").json()
    assert progress == {"phase": "done", "rows": 4000, "total": 4000}

    runs = c.get("/api/history").json()["runs"]
    assert len(runs) == 1
    run = runs[0]
    assert run["ok"]
    assert run["files"] == ["customers.csv", "orders.csv"]
    assert run["choices"] == choices
    assert run["tables"]["orders"] == {"rows_in": 3000, "rows_out": 3000}
    history = tmp_path / "home" / "ui-history"
    assert stat.S_IMODE(os.stat(history).st_mode) == 0o700
    saved = " ".join(p.read_text(encoding="utf-8") for p in history.rglob("*.json"))
    assert not any(v in saved for v in original["email"].to_list())  # reports only: no value
    old = c.get(f"/api/history/{run['id']}/report")
    assert old.status_code == 200
    assert "sandbox" in old.headers["content-security-policy"]
    assert c.get("/api/history/../ui.key/report").status_code == 404
    assert c.get("/api/history/20260101-000000-zzzzzzzzzzzz/report").status_code == 404
    assert c.delete(f"/api/history/{run['id']}", headers=SAFE).json() == {"ok": True}
    assert c.get("/api/history").json() == {"runs": []}


def test_excel_in_and_out(logged_in: TestClient, shop_csv: Path, tmp_path: Path) -> None:
    c = logged_in
    folder = tmp_path / "books"
    folder.mkdir()
    for table in ("customers", "orders"):
        pl.read_csv(shop_csv / f"{table}.csv", try_parse_dates=True).write_excel(
            folder / f"{table}.xlsx", worksheet=table
        )
    job = _job(c, folder, ("customers.xlsx", "orders.xlsx"))
    mixed = c.put(f"/api/jobs/{job}/files/more.csv", content=b"a\n1\n", headers=SAFE)
    assert mixed.status_code == 200
    assert "not a mix" in c.post(f"/api/jobs/{job}/scan", headers=SAFE).json()["error"]
    c.delete(f"/api/jobs/{job}/files/more.csv", headers=SAFE)
    plan = c.post(f"/api/jobs/{job}/scan", headers=SAFE).json()
    assert plan["format"] == "xlsx"
    assert plan["relationships"] == ["orders.customer_id -> customers.id"]
    assert {"year", "month"} <= {o["id"] for o in _columns(plan, "customers")["birth_date"]["options"]}

    body = {"choices": {"customers": "reversible", "orders": "reversible"}, "picked": {}}
    preview = c.post(f"/api/jobs/{job}/preview", headers=SAFE, json=body)
    assert preview.status_code == 200, preview.text
    done = c.post(f"/api/jobs/{job}/mask", headers=SAFE, json=body)
    assert done.status_code == 200, done.text
    assert done.json()["ok"]
    archive = zipfile.ZipFile(io.BytesIO(c.get(f"/api/jobs/{job}/download/masked.zip").content))
    assert sorted(archive.namelist()) == [
        "customers.xlsx",
        "masking.yaml",
        "orders.xlsx",
        "report.html",
        "report.json",
    ]

    back = c.post("/api/jobs", headers=SAFE).json()["id"]
    for name in ("customers.xlsx", "orders.xlsx", "report.json"):
        c.put(f"/api/jobs/{back}/files/{name}", content=archive.read(name), headers=SAFE)
    read = c.post(f"/api/jobs/{back}/unmask", headers=SAFE, json={})
    assert read.status_code == 200, read.text
    readable = zipfile.ZipFile(io.BytesIO(c.get(f"/api/jobs/{back}/download/readable.zip").content))
    original = pl.read_excel(folder / "customers.xlsx", engine="calamine")
    again = pl.read_excel(io.BytesIO(readable.read("customers.xlsx")), engine="calamine")
    for column in original.columns:
        assert again[column].equals(original[column]), column


def test_reversible_files_offer_three_ciphers_and_phones_keep_their_format(
    logged_in: TestClient, shop_csv: Path
) -> None:
    c = logged_in
    job = _job(c, shop_csv, ("customers.csv", "orders.csv"))
    plan = c.post(f"/api/jobs/{job}/scan", headers=SAFE).json()
    phone = _columns(plan, "customers")["phone"]
    assert [o["id"] for o in phone["rev_options"]] == ["siv", "keep", "ff1", "ff1an", "gcm", "null", "drop"]
    assert phone["rev_default"] == "ff1"
    assert [o["id"] for o in _columns(plan, "customers")["id"]["rev_options"]] == ["siv", "keep"]  # it links
    body = {
        "choices": {"customers": "reversible", "orders": "reversible"},
        "picked": {"customers": {"email": "gcm", "phone": "ff1"}, "orders": {"card_number": "ff1"}},
    }
    done = c.post(f"/api/jobs/{job}/mask", headers=SAFE, json=body)
    assert done.status_code == 200, done.text
    assert done.json()["ok"]
    archive = zipfile.ZipFile(io.BytesIO(c.get(f"/api/jobs/{job}/download/masked.zip").content))
    policy = archive.read("masking.yaml").decode()
    assert "algorithm: aes-gcm" in policy
    assert "algorithm: ff1" in policy
    assert "env://SAFETWIN_UI_KEY" in policy  # the page's key reaches a run in its environment, never a file
    masked = pl.read_csv(io.BytesIO(archive.read("customers.csv")), infer_schema=False)
    original = pl.read_csv(shop_csv / "customers.csv", infer_schema=False)
    first = original["phone"].drop_nulls()[0]
    turned = masked.filter(original["phone"] == first)["phone"][0]
    assert turned != first
    assert [ch for ch in turned if not ch.isdigit()] == [ch for ch in first if not ch.isdigit()]


def test_the_key_can_be_this_computers_a_new_one_your_own_or_a_passphrase(
    logged_in: TestClient, shop_csv: Path
) -> None:
    from safetwin.keys import key_from_passphrase

    c = logged_in
    computer = c.get("/api/state").json()["key"]
    made = c.post("/api/key", headers=SAFE, json={"mode": "generate"}).json()
    assert made["source"] == "generate"
    assert len(made["key"]) == 64
    assert made["fingerprint"] != computer["fingerprint"]
    assert "key" not in c.get("/api/state").json()["key"]  # shown once, in that answer only

    own = c.post("/api/key", headers=SAFE, json={"mode": "hex", "value": made["key"]}).json()
    assert own["fingerprint"] == made["fingerprint"]
    assert "key" not in own
    bad = c.post("/api/key", headers=SAFE, json={"mode": "hex", "value": "abc"})
    assert bad.status_code == 400
    short = c.post("/api/key", headers=SAFE, json={"mode": "passphrase", "value": "too short"})
    assert "at least 12" in short.json()["error"]

    phrase = "correct horse battery staple"
    chosen = c.post("/api/key", headers=SAFE, json={"mode": "passphrase", "value": phrase}).json()
    assert chosen["fingerprint"] == key_from_passphrase(phrase).fingerprint
    access = c.get("/api/access-key").text.strip()
    assert access == key_from_passphrase(phrase).access_key().hex()

    # Masking uses the key chosen: what it encrypts, that key's access key reads back.
    job = _job(c, shop_csv, ("customers.csv",))
    c.post(f"/api/jobs/{job}/scan", headers=SAFE)
    done = c.post(
        f"/api/jobs/{job}/mask", headers=SAFE, json={"choices": {"customers": "reversible"}, "picked": {}}
    )
    assert done.json()["ok"]
    archive = zipfile.ZipFile(io.BytesIO(c.get(f"/api/jobs/{job}/download/masked.zip").content))
    assert json.loads(archive.read("report.json"))["key_fingerprint"] == chosen["fingerprint"]
    back = c.post("/api/jobs", headers=SAFE).json()["id"]
    for name in ("customers.csv", "report.json"):
        c.put(f"/api/jobs/{back}/files/{name}", content=archive.read(name), headers=SAFE)
    read = c.post(f"/api/jobs/{back}/unmask", headers=SAFE, json={"access_key": access})
    assert read.status_code == 200, read.text
    assert c.post("/api/key", headers=SAFE, json={"mode": "computer"}).json() == computer


def test_cloud_folders_are_found_and_the_zip_is_saved_there(
    logged_in: TestClient, shop_csv: Path, tmp_path: Path, workspace: Workspace
) -> None:
    from safetwin.ui.server import sync_folders

    home = tmp_path / "home-dir"
    cloud = home / "Library" / "CloudStorage"
    (cloud / "GoogleDrive-ann@example.org" / "My Drive").mkdir(parents=True)
    (cloud / "Dropbox").mkdir()
    (cloud / "SomethingElse").mkdir()
    (home / "Library" / "Mobile Documents" / "com~apple~CloudDocs").mkdir(parents=True)
    (home / "Google Drive").symlink_to(cloud / "GoogleDrive-ann@example.org")  # the app's shortcut: once
    found = sync_folders(home)
    assert [f["name"] for f in found] == ["Dropbox", "Google Drive (ann@example.org)", "iCloud Drive"]
    assert found[1]["path"].endswith("My Drive")
    assert sync_folders(tmp_path / "nobody") == []

    c = logged_in
    job = _job(c, shop_csv, ("customers.csv",))
    early = c.post(f"/api/jobs/{job}/save", headers=SAFE, json={"folder": str(tmp_path)})
    assert "nothing to save" in early.json()["error"]
    c.post(f"/api/jobs/{job}/scan", headers=SAFE)
    assert c.post(f"/api/jobs/{job}/mask", headers=SAFE, json={"choices": {"customers": "one-way"}}).json()[
        "ok"
    ]
    target = Path(found[1]["path"])
    saved = c.post(f"/api/jobs/{job}/save", headers=SAFE, json={"folder": str(target)}).json()["saved"]
    again = c.post(f"/api/jobs/{job}/save", headers=SAFE, json={"folder": str(target)}).json()["saved"]
    assert saved != again  # never over an existing file
    assert Path(saved).parent == target
    assert (
        zipfile.ZipFile(saved).namelist()
        == zipfile.ZipFile(io.BytesIO(c.get(f"/api/jobs/{job}/download/masked.zip").content)).namelist()
    )
    assert not [p for p in target.iterdir() if p.name.startswith(".")]  # no part file left
    for folder, words in (
        ("relative/path", "full path"),
        (str(tmp_path / "missing"), "not a folder"),
        (str(workspace.root), "of your own"),
    ):
        refused = c.post(f"/api/jobs/{job}/save", headers=SAFE, json={"folder": folder})
        assert refused.status_code == 400
        assert words in refused.json()["error"]
