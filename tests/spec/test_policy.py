"""The masking policy (docs/guide.md): the model, the safe loader, the JSON Schema, and every rule of the
checks that need no data."""

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
import yaml

from safetwin.spec.io import SpecError
from safetwin.spec.policy import (
    DateShift,
    Drop,
    Fake,
    Keep,
    Null,
    Pseudonymize,
    Redact,
    column_class,
    entity_domain,
    load_policy_file,
    load_policy_text,
    pseudonym_domain,
    validate_policy,
)

REPO = Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "examples" / "shop" / "masking.yaml"
SCHEMA = json.loads((REPO / "schemas" / "safetwin.policy.v1.schema.json").read_text(encoding="utf-8"))

BASE = """\
apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {name: test}
spec:
  source: {folder: ./in, format: parquet}
  target: {folder: ./out}
  key: env://SAFETWIN_KEY
  tables:
"""


def policy(tables: str, extra: str = "") -> str:
    return BASE + tables + extra


def codes(text: str) -> list[str]:
    return [p.code for p in validate_policy(load_policy_text(text)) if p.severity == "error"]


def load_errors(text: str) -> list[str]:
    with pytest.raises(SpecError) as err:
        load_policy_text(text)
    return [p.message for p in err.value.problems]


def test_the_example_policy_loads_and_is_valid() -> None:
    p = load_policy_file(EXAMPLE)
    assert p.metadata.name == "shop-to-staging"
    assert validate_policy(p) == []
    assert isinstance(p.spec.tables["customers"]["phone"], Null)  # YAML's bare null
    assert isinstance(p.spec.tables["customers"]["notes"], Drop)
    assert isinstance(p.spec.tables["customers"]["city"], Keep)
    assert p.spec.target.format == "parquet"
    assert p.spec.unknown_columns == "fail"


def test_the_example_policy_validates_against_the_committed_schema() -> None:
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(SCHEMA).validate(raw)


def test_the_schema_refuses_an_unknown_method() -> None:
    raw: dict[str, Any] = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw["spec"]["tables"]["customers"]["city"] = {"method": "shuffle"}
    assert list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(raw))


def test_bare_methods_and_defaults() -> None:
    p = load_policy_text(
        policy("""\
    t:
      a: keep
      b: "null"
      c: drop
      d: null
      e: {method: pseudonymize}
      f: {method: fake, kind: email}
      g: {method: date_shift, entity: e}
""")
    )
    cols = p.spec.tables["t"]
    assert [type(cols[c]) for c in "abcd"] == [Keep, Null, Drop, Null]
    e = cols["e"]
    assert isinstance(e, Pseudonymize)
    assert e.format == "auto"
    assert e.domain is None
    assert e.prefix == ""
    f = cols["f"]
    assert isinstance(f, Fake)
    assert f.consistent
    assert f.locale == "en"
    g = cols["g"]
    assert isinstance(g, DateShift)
    assert g.max_days == 30
    assert pseudonym_domain(p, "t", "e") == "t.e"
    assert entity_domain(p, "t", "e") == "t.e"
    assert entity_domain(p, "t", "a") == "t.a"


def test_a_bare_name_other_than_keep_null_drop_is_refused() -> None:
    (message,) = load_errors(policy("    t:\n      a: pseudonymize\n"))
    assert "keep, null or drop" in message


@pytest.mark.parametrize(
    ("column", "fragment"),
    [
        ("{method: generalize}", "exactly one of to, bucket, bins, keep_chars and ip"),
        ("{method: generalize, to: year, bucket: 5}", "exactly one"),
        ("{method: generalize, bins: [10, 5]}", "increasing order"),
        ("{method: generalize, bins: [1, 1]}", "increasing order"),
        ("{method: generalize, keep_chars: true}", "valid integer"),
        ("{method: generalize, bucket: 0}", "greater than 0"),
        ("{method: generalize, to: decade}", "'year', 'month', 'week' or 'day'"),
        ("{method: generalize, ip: false}", "Input should be True"),
        ("{method: redact}", "exactly one of keep_last, keep_first and with"),
        ("{method: redact, keep_last: 4, with: x}", "exactly one"),
        ("{method: redact, with: x, char: '#'}", "char is for keep_last and keep_first"),
        ("{method: redact, keep_last: 4, char: '##'}", "at most 1 character"),
        ("{method: pseudonymize, format: int, prefix: c_}", "prefix is for text pseudonyms"),
        ("{method: pseudonymize, format: base64}", "'auto', 'hex', 'int' or 'uuid'"),
        ("{method: pseudonymize, domain: 'two words'}", "should match pattern"),
        ("{method: fake, kind: ssn}", "'name'"),
        ("{method: fake, kind: name, locale: de}", "'en'"),
        ("{method: date_shift}", "Field required"),
        ("{method: date_shift, entity: id, max_days: 0}", "greater than or equal to 1"),
        ("{method: shuffle}", "does not match any of the expected tags"),
        ("{method: keep, extra: 1}", "Extra inputs are not permitted"),
    ],
)
def test_method_parameters_are_checked_per_method(column: str, fragment: str) -> None:
    messages = load_errors(policy(f"    t:\n      a: {column}\n"))
    assert any(fragment in m for m in messages), messages


def test_messages_never_repeat_a_value_of_the_file() -> None:
    messages = load_errors(policy("    t:\n      a: {method: fake, kind: SECRETVALUE42}\n"))
    assert messages
    assert not any("SECRETVALUE42" in m for m in messages)


def test_table_names_and_the_relationship_shape() -> None:
    assert load_errors(policy("    Bad-Name:\n      a: keep\n"))
    assert load_errors(policy("    t:\n      a: keep\n", "  relationships: ['t.a = u.b']\n"))
    assert load_errors(policy("    t: {}\n"))


def test_relationships_must_name_columns_of_the_policy() -> None:
    tables = "    t:\n      a: keep\n"
    assert codes(policy(tables, "  relationships: ['t.a -> u.b']\n")) == ["unknown_table"]
    assert codes(policy(tables, "  relationships: ['t.a -> t.zz']\n")) == ["unknown_column"]


@pytest.mark.parametrize(
    ("a", "b", "ok"),
    [
        ("keep", "keep", True),
        ("{method: pseudonymize, domain: c}", "{method: pseudonymize, domain: c}", True),
        ("{method: pseudonymize, domain: c}", "{method: pseudonymize, domain: d}", False),
        ("{method: pseudonymize}", "{method: pseudonymize}", False),  # the defaults are t.a and u.b
        ("keep", "{method: pseudonymize, domain: c}", False),
        ("{method: pseudonymize, domain: c}", "{method: fake, kind: name}", False),
        (
            "{method: pseudonymize, domain: c, format: int}",
            "{method: pseudonymize, domain: c, format: hex}",
            False,
        ),
    ],
)
def test_relationship_sides_share_a_domain_or_are_both_kept(a: str, b: str, ok: bool) -> None:
    text = policy(f"    t:\n      a: {a}\n    u:\n      b: {b}\n", "  relationships: ['t.a -> u.b']\n")
    assert codes(text) == ([] if ok else ["relationship_domain"])


def test_date_shift_entity_must_be_a_column_of_the_same_table() -> None:
    assert codes(policy("    t:\n      d: {method: date_shift, entity: id}\n      id: keep\n")) == []
    assert codes(policy("    t:\n      d: {method: date_shift, entity: nope}\n")) == ["unknown_column"]


def test_the_entity_domain_is_the_entitys_pseudonymize_domain() -> None:
    p = load_policy_file(EXAMPLE)
    assert entity_domain(p, "customers", "id") == entity_domain(p, "orders", "customer_id") == "customer"


@pytest.mark.parametrize(
    ("key", "code"),
    [
        ("keychain://shop", "unsupported_key"),
        ("a1" * 32, "key_reference"),
        ("vault://x", "key_reference"),
        ("env://", "key_reference"),
    ],
)
def test_the_key_must_be_an_env_or_file_reference(key: str, code: str) -> None:
    text = policy("    t:\n      a: keep\n").replace("env://SAFETWIN_KEY", key)
    assert code in codes(text)


def test_an_inline_key_is_reported_as_a_secret_and_never_shown() -> None:
    key = "9f" * 4 + "0123456789abcdef" * 3 + "ab12cd34"
    text = policy("    t:\n      a: keep\n").replace("env://SAFETWIN_KEY", key)
    problems = validate_policy(load_policy_text(text))
    assert "inline_secret" in [p.code for p in problems]
    assert not any(key in p.message for p in problems)


def test_a_secret_elsewhere_is_refused() -> None:
    text = policy("    t:\n      a: {method: redact, with: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789'}\n")
    assert codes(text) == ["inline_secret"]


def test_subset_needs_a_root_table_and_a_key() -> None:
    assert codes(policy("    t:\n      a: keep\n", "  subset: {root: t, fraction: 0.1, key: a}\n")) == []
    assert codes(policy("    t:\n      a: keep\n", "  subset: {root: t, fraction: 0.1}\n")) == ["subset_key"]
    unknown = policy("    t:\n      a: keep\n", "  subset: {root: u, fraction: 0.1}\n")
    assert codes(unknown) == ["unknown_table"]
    assert codes(policy("    t:\n      a: keep\n", "  subset: {root: t, fraction: 1, key: b}\n")) == [
        "unknown_column"
    ]
    for bad in ("fraction: 0", "fraction: 1.5", "fraction: '0.1'", "fraction: 0.1, where: x"):
        assert load_errors(policy("    t:\n      a: keep\n", f"  subset: {{root: t, {bad}}}\n")), bad


def test_aliases_and_duplicate_keys_are_refused() -> None:
    assert any("aliases" in m for m in load_errors(policy("    t:\n      a: &x keep\n      b: *x\n")))
    assert any("duplicate key" in m for m in load_errors(policy("    t:\n      a: keep\n      a: drop\n")))


def test_classes() -> None:
    assert column_class(Keep(method="keep")) == "kept"
    assert column_class(Null(method="null")) == "removed"
    assert column_class(Drop(method="drop")) == "removed"
    assert column_class(Pseudonymize(method="pseudonymize")) == "pseudonymized"
    assert column_class(Fake(method="fake", kind="name")) == "pseudonymized"
    assert column_class(Fake(method="fake", kind="name", consistent=False)) == "removed"
    assert column_class(DateShift(method="date_shift", entity="id")) == "pseudonymized"
    assert column_class(Redact(method="redact", keep_last=4)) == "partially_redacted"
    assert column_class(Redact.model_validate({"method": "redact", "with": "[X]"})) == "removed"


def test_the_policy_module_imports_no_data_library() -> None:
    import subprocess
    import sys

    code = (
        "import sys, safetwin.spec.policy, safetwin.keys, safetwin.detect.validators, safetwin.detect.names;"
        "print(sorted(m for m in ('polars','pyarrow','duckdb','sqlalchemy') if m in sys.modules))"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert done.stdout.strip() == "[]"
