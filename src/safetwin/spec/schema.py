"""The JSON Schemas of pipeline files and masking policies, generated from the models.

Run ``python -m safetwin.spec.schema`` to write schemas/safetwin.pipeline.v1.schema.json and
schemas/safetwin.policy.v1.schema.json, or add ``--check`` to fail when a committed file is out of date. This
module is deliberately not imported by the package ``__init__``, which keeps ``python -m`` free of import
warnings.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .models import Pipeline
from .policy import MaskingPolicy

SCHEMA_ID = "urn:safetwin:schemas:pipeline:v1"
SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas" / "safetwin.pipeline.v1.schema.json"
POLICY_SCHEMA_ID = "urn:safetwin:schemas:policy:v1"
POLICY_SCHEMA_NAME = "safetwin.policy.v1.schema.json"  # next to SCHEMA_PATH (found when main runs)


def pipeline_json_schema() -> dict[str, Any]:
    """The JSON Schema (draft 2020-12) for a pipeline file."""
    schema = Pipeline.model_json_schema()
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": SCHEMA_ID, **schema}


def render_schema() -> str:
    """The schema as the text of the committed file."""
    return json.dumps(pipeline_json_schema(), indent=2, ensure_ascii=False) + "\n"


def policy_json_schema() -> dict[str, Any]:
    """The JSON Schema (draft 2020-12) for a masking policy file."""
    schema = MaskingPolicy.model_json_schema(by_alias=True)
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": POLICY_SCHEMA_ID, **schema}


def render_policy_schema() -> str:
    return json.dumps(policy_json_schema(), indent=2, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m safetwin.spec.schema",
        description="Write the JSON Schemas, or check that the committed files are current.",
    )
    parser.add_argument("--check", action="store_true", help="fail if a committed schema is out of date")
    args = parser.parse_args(argv)

    if not SCHEMA_PATH.parent.is_dir():
        print(f"{SCHEMA_PATH.parent} does not exist: run this from a source checkout", file=sys.stderr)
        return 2
    files = (
        (SCHEMA_PATH, render_schema()),
        (SCHEMA_PATH.parent / POLICY_SCHEMA_NAME, render_policy_schema()),
    )
    if args.check:
        stale = [
            path for path, text in files if not path.is_file() or path.read_text(encoding="utf-8") != text
        ]
        for path in stale:
            print(f"{path} is out of date: run python -m safetwin.spec.schema", file=sys.stderr)
        if stale:
            return 1
        print(", ".join(path.name for path, _ in files) + " are up to date")
        return 0
    for path, text in files:
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
