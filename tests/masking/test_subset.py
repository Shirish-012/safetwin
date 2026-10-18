"""Subsetting (docs/guide.md): stable root selection, parents always, children below the root, tables
off the graph copied whole, and a 10% subset of the example shop end to end."""

import hashlib
import hmac
from pathlib import Path
from typing import Any

import polars as pl
import pytest
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.keys import MasterKey
from safetwin.masking.hmacs import Mac
from safetwin.masking.step import build_mask_step
from safetwin.masking.subset import picked, select
from safetwin.spec.models import Node
from safetwin.spec.policy import load_policy_text, validate_policy

from .test_mask_run import KEY, OTHER_KEY, POLICY, _generator, report, table

runner = CliRunner()
KEY_A = MasterKey(bytes.fromhex(KEY))
SUBSET = "  subset:\n    root: customers\n    fraction: 0.10\n"


@pytest.fixture(scope="module")
def shop(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert _generator().main([str(folder)]) == 0
    return folder


def subset_policy(tmp_path: Path, subset: str = SUBSET) -> Path:
    path = tmp_path / "masking.yaml"
    path.write_text(POLICY.read_text(encoding="utf-8") + subset, encoding="utf-8")
    return path


def mask(policy: Path, source: Path, out: Path, key: str = KEY) -> Any:
    return runner.invoke(
        app, ["mask", str(policy), "--source", str(source), "--out", str(out)], env={"SAFETWIN_KEY": key}
    )


def expected_ids(ids: list[int], key: MasterKey, fraction: float) -> set[int]:
    """The root selection recomputed from docs/guide.md: HMAC of the canonical int bytes, below fraction *
    2^64."""
    subkey = key.subkey("subset", "customers")
    out = set()
    for i in ids:
        h = hmac.digest(subkey, b"i" + i.to_bytes(8, "big", signed=True), hashlib.sha256)
        if int.from_bytes(h[:8], "big") < round(fraction * (1 << 64)):
            out.add(i)
    return out


def test_a_10_percent_subset_of_the_example_has_no_orphans_and_is_the_same_every_run(
    shop: Path, tmp_path: Path
) -> None:
    policy = subset_policy(tmp_path)
    first, second, other = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    for out in (first, second):
        result = mask(policy, shop, out)
        assert result.exit_code == 0, result.output
    r = report(first)
    assert r["status"] == "ok"
    assert r["relationships"] == [{"from": "orders.customer_id", "to": "customers.id", "orphans": 0}]
    customers, orders = pl.read_parquet(shop / "customers.parquet"), pl.read_parquet(shop / "orders.parquet")
    picked_ids = expected_ids(customers["id"].to_list(), KEY_A, 0.10)
    wanted_orders = orders.filter(pl.col("customer_id").is_in(sorted(picked_ids))).height
    assert r["subset"] == {
        "root": "customers",
        "key": "id",
        "fraction": 0.1,
        "include_children": True,
        "root_rows_picked": len(picked_ids),
        "copied_whole": [],
    }
    assert r["tables"]["customers"]["rows_out"] == len(picked_ids)
    assert 50 <= len(picked_ids) <= 150
    assert r["tables"]["orders"]["rows_out"] == wanted_orders  # every order of a picked customer
    for name in ("customers", "orders"):
        assert table(first, name).equals(table(second, name))
    assert mask(policy, shop, other, key=OTHER_KEY).exit_code == 0
    assert report(other)["tables"]["customers"]["rows_out"] == len(
        expected_ids(customers["id"].to_list(), MasterKey(bytes.fromhex(OTHER_KEY)), 0.10)
    )


def test_more_rows_later_keep_the_earlier_picks() -> None:
    mac = Mac(KEY_A.subkey("subset", "customers"))
    small = set(picked(pl.Series(range(1, 1001)), mac, 0.1).to_list())
    large = set(picked(pl.Series(range(1, 5001)), mac, 0.1).to_list())
    assert small == large & set(range(1, 1001))
    assert set(picked(pl.Series([1, 2, None]), mac, 1.0).to_list()) == {1, 2}


GRAPH = """apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {{name: graph}}
spec:
  source: {{folder: ., format: parquet}}
  target: {{folder: ./safe}}
  key: env://K
  tables:
    customers: {{id: keep, country_id: keep}}
    orders: {{id: keep, customer_id: keep, product_id: keep}}
    products: {{id: keep}}
    countries: {{id: keep}}
    employees: {{id: keep, manager_id: keep}}
    notes: {{text: keep}}
  relationships:
    - orders.customer_id -> customers.id
    - orders.product_id -> products.id
    - customers.country_id -> countries.id
  subset: {{root: customers, fraction: {fraction}, include_children: {children}}}
"""

FRAMES = {
    "customers": pl.DataFrame({"id": list(range(1, 101)), "country_id": [i % 5 for i in range(100)]}),
    "orders": pl.DataFrame(
        {
            "id": list(range(300)),
            "customer_id": [1 + i % 100 for i in range(300)],
            "product_id": [i % 50 for i in range(300)],
        }
    ),
    "products": pl.DataFrame({"id": list(range(50))}),
    "countries": pl.DataFrame({"id": list(range(5))}),
    "employees": pl.DataFrame({"id": [1, 2, 3], "manager_id": [None, 1, 1]}),
    "notes": pl.DataFrame({"text": ["a", "b"]}),
}


def selection(fraction: float = 0.2, children: bool = True) -> tuple[dict[str, pl.DataFrame], Any]:
    policy = load_policy_text(GRAPH.format(fraction=fraction, children=str(children).lower()))
    assert validate_policy(policy) == []
    plan = select(policy, KEY_A, lambda t: FRAMES[t].lazy())
    out = {
        t: frame if plan.filters[t] is None else frame.filter(plan.filters[t]) for t, frame in FRAMES.items()
    }
    return out, plan


def test_parents_always_children_below_the_root_and_tables_off_the_graph_whole() -> None:
    out, plan = selection()
    ids = set(out["customers"]["id"])
    assert plan.root_rows == len(ids) > 0
    assert ids == expected_ids(list(range(1, 101)), KEY_A, 0.2)
    assert set(out["orders"]["customer_id"]) == ids  # every order of a picked customer, no other
    assert out["orders"].height == FRAMES["orders"].filter(pl.col("customer_id").is_in(sorted(ids))).height
    # Parents of what was picked, and only those: a product's other orders don't come along.
    assert set(out["products"]["id"]) == set(out["orders"]["product_id"])
    assert set(out["countries"]["id"]) == set(out["customers"]["country_id"])
    assert out["employees"].equals(FRAMES["employees"])  # no path to the root: copied whole
    assert out["notes"].equals(FRAMES["notes"])
    assert plan.whole == ["employees", "notes"]


def test_without_children_only_parents_come_along() -> None:
    out, _ = selection(children=False)
    assert out["orders"].height == 0
    assert out["products"].height == 0
    assert set(out["countries"]["id"]) == set(out["customers"]["country_id"])


def test_a_self_reference_pulls_in_managers_and_reports() -> None:
    policy = load_policy_text(
        GRAPH.format(fraction=0.5, children="true")
        .replace("    - orders.customer_id -> customers.id\n", "    - employees.manager_id -> employees.id\n")
        .replace("root: customers", "root: employees")
    )
    plan = select(policy, KEY_A, lambda t: FRAMES[t].lazy())
    employees = FRAMES["employees"].filter(plan.filters["employees"])
    picked_ids = set(picked(FRAMES["employees"]["id"], Mac(KEY_A.subkey("subset", "employees")), 0.5))
    expected = set(picked_ids)
    if picked_ids & {2, 3}:
        expected.add(1)  # the manager of a picked report
    if 1 in picked_ids:
        expected |= {2, 3}  # the reports of a picked manager
    assert set(employees["id"]) == expected


def test_the_filters_stay_out_of_the_pipeline_and_the_step_needs_them(shop: Path, tmp_path: Path) -> None:
    from safetwin.dataplane.operators import ConfigError
    from safetwin.masking.check import discover
    from safetwin.masking.compile import compile_policy
    from safetwin.spec import dump_pipeline
    from safetwin.spec.policy import load_policy_file

    policy = load_policy_file(subset_policy(tmp_path))
    tables, _ = discover(policy, shop)
    compiled = compile_policy(policy, tables, subset_tables=frozenset({"customers", "orders"}))
    text = dump_pipeline(compiled.pipeline)
    assert text.count("subset: true") == 2
    node = Node.model_validate(
        {
            "id": "mask_t",
            "operator": "transform.mask",
            "inputs": ["read_t"],
            "config": {"table": "t", "subset": True, "columns": {"a": {"spec": {"method": "keep"}}}},
        }
    )
    with pytest.raises(ConfigError, match="needs the subset's selection"):
        build_mask_step(node, None)
