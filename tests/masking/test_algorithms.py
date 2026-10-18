"""The algorithms of `encrypt` (aes-siv, aes-gcm, ff1) and keys made from a passphrase (docs/guide.md)."""

import json
import os
import stat
from pathlib import Path

import polars as pl
import pytest
from typer.testing import CliRunner

from safetwin.cli.main import app
from safetwin.keys import KeyRefError, key_from_passphrase
from safetwin.masking.portable import (
    FF1,
    SEALED_RANDOM_PATTERN,
    Sealer,
    access_key,
    decrypt_ff1_series,
    decrypt_series,
    encrypt_series,
    ff1_texts,
    is_sealed,
)
from safetwin.spec.policy import load_policy_text, validate_policy

from .test_export import export, run_script
from .test_mask_run import KEY, _generator

cli = CliRunner()
RAW = bytes.fromhex("a1" * 32)
SEALER = Sealer(access_key(RAW))

# NIST SP 800-38G, FF1 samples 1-3 (AES-128) and 7-9 (AES-256).
K128 = "2B7E151628AED2A6ABF7158809CF4F3C"
K256 = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"
NIST = [
    (K128, 10, "0123456789", "", "2433477484"),
    (K128, 10, "0123456789", "39383736353433323130", "6124200773"),
    (K128, 36, "0123456789abcdefghi", "3737373770717273373737", "a9tv40mll9kdu509eum"),
    (K256, 10, "0123456789", "", "6657667009"),
    (K256, 10, "0123456789", "39383736353433323130", "1001623463"),
    (K256, 36, "0123456789abcdefghi", "3737373770717273373737", "xs8a0azh2avyalyzuwd"),
]


@pytest.mark.parametrize(("key", "radix", "plain", "tweak", "cipher"), NIST)
def test_ff1_gives_the_nist_samples(key: str, radix: int, plain: str, tweak: str, cipher: str) -> None:
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"[:radix]
    ff1 = FF1(bytes.fromhex(key))
    numerals = [chars.index(c) for c in plain]
    out = ff1.encrypt([numerals], radix, bytes.fromhex(tweak))[0]
    assert "".join(chars[x] for x in out) == cipher
    assert ff1.decrypt([out], radix, bytes.fromhex(tweak))[0] == numerals


def test_ff1_batches_strings_of_many_lengths_as_one_by_one() -> None:
    strings = [[1, 2, 3, 4, 5, 6], [9] * 16, [0, 0, 0, 0, 0, 0, 0], [4, 1] * 20, [3] * 6]
    ff1 = SEALER.ff1()
    together = ff1.encrypt(strings, 10, b"t")
    assert together == [ff1.encrypt([s], 10, b"t")[0] for s in strings]
    assert ff1.decrypt(together, 10, b"t") == strings


def test_ff1_keeps_the_format_and_empties_what_is_too_short() -> None:
    values = ["4111 1111 1111 1111", "(212) 555-0100", "AB-1234-xy"]
    out = ff1_texts(values, SEALER.ff1(), "digits", b"")
    assert out == ["5509 3021 8633 2009", "(642) 937-2042", None]  # pinned: version 1's values
    for before, after in zip(values[:2], out[:2], strict=True):
        assert after is not None
        assert len(after) == len(before)
        assert [c for c in after if not c.isdigit()] == [c for c in before if not c.isdigit()]
    assert ff1_texts(["AB-1234-xy"], SEALER.ff1(), "alphanumeric", b"customer") == ["nr-O1H7-JV"]
    assert ff1_texts(["abc"], SEALER.ff1(), "alphanumeric", b"") == [None]
    assert ff1_texts(["2026-10-18"], SEALER.ff1(), "digits", b"x") != ff1_texts(
        ["2026-10-18"], SEALER.ff1(), "digits", b"y"
    )


def test_ff1_columns_round_trip_and_equal_values_stay_equal() -> None:
    column = pl.Series("card", ["4111-1111-1111-1111", None, "4111-1111-1111-1111", "5500 0000 0000 0004"])
    out = encrypt_series(column, SEALER, "ff1", "digits", "cards")
    assert out[0] == out[2] != column[0]
    assert out[1] is None
    assert decrypt_ff1_series(out, SEALER, "digits", "cards").equals(column)
    assert not is_sealed(out)  # its values look like any others: unmask learns the column from the report


def test_aes_gcm_hides_equal_values_and_decrypts_back() -> None:
    column = pl.Series("email", ["ann@example.org", "ann@example.org", None, "bob@example.org"])
    out = encrypt_series(column, SEALER, "aes-gcm")
    assert out[0] != out[1]  # a nonce of its own per value
    assert out.drop_nulls().str.contains(SEALED_RANDOM_PATTERN).all()
    assert is_sealed(out)
    assert decrypt_series(out, SEALER).equals(column)
    token = "sg1.wEmaYVvv1wCLtEvU1K3k3IT4lYHiUKTonNphDHxunuhwpTQGMee325ZmeJlx_CbjM9hrsrRYo37Odw46"
    assert SEALER.open(token) == b"sann@example.org"  # made by version 1: still opens
    assert Sealer(access_key(bytes(32))).open(token) is None  # another key
    assert SEALER.open(token[:-2] + ("AA" if token[-2:] != "AA" else "BB")) is None  # changed


POLICY = """\
apiVersion: safetwin/v1
kind: MaskingPolicy
metadata: {{ name: algorithms }}
spec:
  source: {{ folder: ./data, format: parquet }}
  target: {{ folder: ./safe }}
  key: env://SAFETWIN_KEY
  tables:
    a: {{ id: {a}, n: keep }}
    b: {{ a_id: {b} }}
  relationships:
    - b.a_id -> a.id
"""


@pytest.mark.parametrize(
    ("a", "b", "codes"),
    [
        ("{ method: encrypt }", "{ method: encrypt }", []),
        ("{ method: encrypt, algorithm: ff1 }", "{ method: encrypt, algorithm: ff1 }", []),
        (
            "{ method: encrypt, algorithm: aes-gcm }",
            "{ method: encrypt, algorithm: aes-gcm }",
            ["relationship_domain"],
        ),
        (
            "{ method: encrypt, algorithm: ff1, domain: x }",
            "{ method: encrypt, algorithm: ff1 }",
            ["relationship_domain"],
        ),
        ("{ method: encrypt, algorithm: ff1 }", "{ method: encrypt }", ["relationship_domain"]),
    ],
)
def test_relationships_need_the_same_deterministic_algorithm(a: str, b: str, codes: list[str]) -> None:
    problems = validate_policy(load_policy_text(POLICY.format(a=a, b=b)))
    assert [p.code for p in problems] == codes


def test_alphabet_and_domain_belong_to_ff1() -> None:
    from safetwin.spec.io import SpecError

    with pytest.raises(SpecError):
        load_policy_text(POLICY.format(a="{ method: encrypt, alphabet: digits }", b="{ method: encrypt }"))


@pytest.fixture(scope="module")
def shop(tmp_path_factory: pytest.TempPathFactory) -> Path:
    folder = tmp_path_factory.mktemp("shop")
    assert _generator().main([str(folder)]) == 0
    return folder


def shop_policy(shop: Path, tmp_path: Path) -> Path:
    done = cli.invoke(app, ["scan", str(shop), "-o", str(tmp_path / "m.yaml")])
    assert done.exit_code == 0, done.output
    text = (tmp_path / "m.yaml").read_text(encoding="utf-8")
    lines = []
    for line in text.splitlines():
        name = line.strip().split(":")[0]
        if name == "phone":
            line = "      phone:      { method: encrypt, algorithm: ff1 }"
        elif name == "card_number":
            line = "      card_number: { method: encrypt, algorithm: ff1, alphabet: digits, domain: cards }"
        elif name == "email":
            line = "      email:      { method: encrypt, algorithm: aes-gcm }"
        lines.append(line)
    path = tmp_path / "m.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_mask_unmask_and_rekey_with_every_algorithm(shop: Path, tmp_path: Path) -> None:
    policy = shop_policy(shop, tmp_path)
    env = {"SAFETWIN_KEY": KEY}
    done = cli.invoke(app, ["mask", str(policy), "--out", str(tmp_path / "safe")], env=env)
    assert done.exit_code == 0, done.output
    report = json.loads((tmp_path / "safe" / "report.json").read_text(encoding="utf-8"))
    assert (
        report["access_fingerprint"]
        == Sealer(bytes.fromhex(KEY) and access_key(bytes.fromhex(KEY))).fingerprint
    )
    assert report["tables"]["orders"]["columns"]["card_number"]["params"] == {
        "algorithm": "ff1", "alphabet": "digits", "domain": "cards"
    }  # fmt: skip
    assert report["residual_scan"]["findings"] == []

    back = cli.invoke(
        app,
        ["unmask", str(tmp_path / "safe"), "--policy", str(policy), "--out", str(tmp_path / "r")],
        env=env,
    )
    assert back.exit_code == 0, back.output
    for table, columns in (("customers", ["phone", "email"]), ("orders", ["card_number"])):
        original = pl.read_parquet(shop / f"{table}.parquet")
        readable = pl.read_parquet(tmp_path / "r" / f"{table}.parquet")
        for column in columns:
            assert readable[column].equals(original[column]), (table, column)

    # Without the report, the ff1 columns can't be known: they are copied as they are, and say so.
    part = next((tmp_path / "safe" / "orders").glob("*.parquet"))
    alone = cli.invoke(
        app, ["unmask", str(part), "--policy", str(policy), "--out", str(tmp_path / "r2")], env=env
    )
    assert alone.exit_code != 0 or "0 column(s) decrypted" in alone.output

    # Another key: refused before anything is written, thanks to the report's fingerprint.
    wrong = cli.invoke(
        app,
        ["unmask", str(tmp_path / "safe"), "--policy", str(policy), "--out", str(tmp_path / "r3")],
        env={"SAFETWIN_KEY": "e5" * 32},
    )
    assert wrong.exit_code == 1
    assert not (tmp_path / "r3").exists() or not list((tmp_path / "r3").iterdir())

    # Rekey: the new key reads it, the report goes along with the new fingerprint.
    new_key = "f6" * 32
    rekeyed = cli.invoke(
        app,
        [
            "rekey",
            str(tmp_path / "safe"),
            "--out",
            str(tmp_path / "rk"),
            "--from-policy",
            str(policy),
            "--to",
            "env://NEW",
        ],
        env={"SAFETWIN_KEY": KEY, "NEW": access_key(bytes.fromhex(new_key)).hex()},
    )
    assert rekeyed.exit_code == 0, rekeyed.output
    moved = json.loads((tmp_path / "rk" / "report.json").read_text(encoding="utf-8"))
    assert moved["access_fingerprint"] == Sealer(access_key(bytes.fromhex(new_key))).fingerprint
    assert moved["files"] == []
    again = cli.invoke(
        app,
        ["unmask", str(tmp_path / "rk"), "--policy", str(policy), "--out", str(tmp_path / "r4")],
        env={"SAFETWIN_KEY": new_key},
    )
    assert again.exit_code == 0, again.output
    original = pl.read_parquet(shop / "orders.parquet")
    assert pl.read_parquet(tmp_path / "r4" / "orders.parquet")["card_number"].equals(original["card_number"])


def test_the_exported_script_encrypts_as_the_engine_does(shop: Path, tmp_path: Path) -> None:
    policy = shop_policy(shop, tmp_path)
    assert (
        cli.invoke(
            app, ["mask", str(policy), "--out", str(tmp_path / "safe")], env={"SAFETWIN_KEY": KEY}
        ).exit_code
        == 0
    )
    script = tmp_path / "job" / "mask.py"
    script.parent.mkdir()
    export(policy, shop, script)
    ran = run_script(script, "--target", str(tmp_path / "script"))
    assert ran.returncode == 0, ran.stderr
    for table in ("customers", "orders"):
        engine = pl.read_parquet(next((tmp_path / "safe" / table).glob("*.parquet")))
        scripted = pl.read_parquet(tmp_path / "script" / f"{table}.parquet")
        for column in engine.columns:
            if column == "email":  # aes-gcm: a fresh nonce per value, so only the plaintext is the same
                assert decrypt_series(scripted[column], SEALER_OF_KEY).equals(
                    decrypt_series(engine[column], SEALER_OF_KEY)
                )
            else:
                assert scripted[column].equals(engine[column]), (table, column)


SEALER_OF_KEY = Sealer(access_key(bytes.fromhex(KEY)))


def test_a_passphrase_gives_the_same_key_everywhere_and_must_be_long() -> None:
    key = key_from_passphrase("correct horse battery staple")
    assert key.fingerprint == "c8c493e26713c4f8"  # pinned: the same passphrase, the same key, forever
    assert key_from_passphrase("correct horse battery staple").fingerprint == key.fingerprint
    assert key_from_passphrase("correct horse battery staplE").fingerprint != key.fingerprint
    with pytest.raises(KeyRefError, match="at least 12"):
        key_from_passphrase("short pass")


def test_key_from_passphrase_writes_a_private_key_file(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "team.key"
    done = cli.invoke(
        app,
        ["key", "from-passphrase", "--file", str(path), "--from-env", "PHRASE"],
        env={"PHRASE": "correct horse battery staple"},
    )
    assert done.exit_code == 0, done.output
    assert "c8c493e26713c4f8" in done.output
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert (
        path.read_text(encoding="ascii").strip()
        == key_from_passphrase("correct horse battery staple").hex_for_key_file()
    )
    assert "correct horse" not in done.output
    prompted = cli.invoke(app, ["key", "from-passphrase", "--print"], input="too short\ntoo short\n")
    assert prompted.exit_code == 1


def test_reversible_drafts_choose_the_cipher_for_a_whole_file(shop: Path) -> None:
    from safetwin.masking.scan import make_reversible
    from safetwin.masking.scan import scan as run_scan

    def methods(algorithm: str) -> dict[str, dict[str, object]]:
        result = run_scan(shop, fmt="parquet")
        make_reversible(result, algorithm=algorithm)
        return {
            f"{t}.{c}": s.method for t, table in result.tables.items() for c, s in table.suggestions.items()
        }

    siv, gcm, auto = methods("aes-siv"), methods("aes-gcm"), methods("auto")
    assert siv["customers.email"] == {"method": "encrypt"}
    assert gcm["customers.email"] == {"method": "encrypt", "algorithm": "aes-gcm"}
    assert (
        gcm["orders.customer_id"] == gcm["customers.id"] == {"method": "encrypt"}
    )  # they link: equal outputs
    assert auto["customers.phone"] == auto["orders.card_number"] == {"method": "encrypt", "algorithm": "ff1"}
    assert auto["customers.email"] == {"method": "encrypt"}  # not number-shaped: standard
    assert siv["customers.city"] == auto["customers.city"] == {"method": "keep"}
    with pytest.raises(ValueError, match="algorithm"):
        methods("rot13")


def test_scan_takes_an_algorithm_only_with_reversible(shop: Path) -> None:
    done = cli.invoke(app, ["scan", str(shop), "--reversible", "--algorithm", "auto"])
    assert done.exit_code == 0, done.output
    assert "algorithm: ff1" in done.stdout
    assert cli.invoke(app, ["scan", str(shop), "--algorithm", "aes-gcm"]).exit_code == 2
    assert cli.invoke(app, ["scan", str(shop), "--reversible", "--algorithm", "rot13"]).exit_code == 2
