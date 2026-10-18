from typing import Any

import polars as pl
import pytest

from safetwin.keys import MasterKey
from safetwin.masking.hmacs import Mac, Subkeys
from safetwin.masking.step import ENCRYPT_USE, ColumnStep, mask_frame, subkey_use

KEY_A = MasterKey(bytes.fromhex("a1" * 32))
KEY_B = MasterKey(bytes.fromhex("b2" * 32))


def mac(method: str, domain: str, key: MasterKey = KEY_A) -> Mac:
    return Mac(key.subkey(method, domain))


def run_mask(
    frame: pl.DataFrame, specs: dict[str, dict[str, Any] | str], *, table: str = "t", key: MasterKey = KEY_A
) -> pl.DataFrame:
    """`frame` through the `transform.mask` step's batch function, with domains as the compiler gives them."""
    steps: dict[str, ColumnStep] = {}
    for column in frame.columns:
        raw = specs.get(column, "keep")
        spec = {"method": raw} if isinstance(raw, str) else dict(raw)
        domain = spec.get("domain")
        if spec["method"] == "pseudonymize":
            domain = domain or f"{table}.{column}"
        elif spec["method"] == "fake" and spec.get("consistent", True):
            domain = f"{table}.{column}"
        elif spec["method"] == "date_shift":
            entity_spec = specs.get(spec["entity"])
            entity_domain = entity_spec.get("domain") if isinstance(entity_spec, dict) else None
            if isinstance(entity_spec, dict) and entity_spec.get("method") == "pseudonymize":
                domain = entity_domain or f"{table}.{spec['entity']}"
            else:
                domain = f"{table}.{spec['entity']}"
        steps[column] = ColumnStep.model_validate({"spec": spec, "domain": domain})
    uses = {name: use for name, step in steps.items() if (use := subkey_use(name, step)) is not None}
    subkeys = Subkeys(key, uses.values())
    macs = {name: subkeys.sealer() if use == ENCRYPT_USE else subkeys.mac(*use) for name, use in uses.items()}
    return mask_frame(frame, columns=steps, macs=macs)


@pytest.fixture
def masker() -> Any:
    return run_mask
