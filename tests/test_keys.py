"""Keys (docs/security.md): references, file permissions, messages without values, HKDF (RFC 5869 test
vectors), the fingerprint, new key files, and the fast HMAC of the masking methods."""

import hashlib
import hmac
import os
import re
import stat
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from safetwin.keys import (
    KeyRefError,
    MasterKey,
    fingerprint,
    hkdf_sha256,
    new_key_file,
    resolve_key,
    subkey_info,
)
from safetwin.masking.hmacs import Mac, Subkeys

KEY_HEX = "a1" * 32
KEY = bytes.fromhex(KEY_HEX)

# RFC 5869, appendix A, test cases 1 to 3 (SHA-256): IKM, salt, info, L, PRK, OKM.
RFC5869 = [
    (
        bytes.fromhex("0b" * 22),
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    ),
    (
        bytes(range(0x00, 0x50)),
        bytes(range(0x60, 0xB0)),
        bytes(range(0xB0, 0x100)),
        82,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ),
    (
        bytes.fromhex("0b" * 22),
        b"",
        b"",
        42,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    ),
]


@pytest.mark.parametrize(("ikm", "salt", "info", "length", "prk", "okm"), RFC5869, ids=["A.1", "A.2", "A.3"])
def test_hkdf_matches_the_rfc_5869_test_vectors(
    ikm: bytes, salt: bytes, info: bytes, length: int, prk: str, okm: str
) -> None:
    assert hmac.digest(salt or bytes(32), ikm, "sha256").hex() == prk  # the extract step, as the RFC gives it
    assert hkdf_sha256(ikm, salt, info, length).hex() == okm


def test_a_missing_salt_is_hash_length_zeros() -> None:
    assert hkdf_sha256(b"k" * 32, None, b"x") == hkdf_sha256(b"k" * 32, bytes(32), b"x")


def test_hkdf_refuses_impossible_lengths() -> None:
    with pytest.raises(ValueError, match="8160"):
        hkdf_sha256(b"k", None, b"", 255 * 32 + 1)


def test_subkeys_follow_the_documented_derivation() -> None:
    key = MasterKey(KEY)
    assert subkey_info("pseudonymize", "customer") == b"safetwin/v1/pseudonymize/customer"
    assert key.subkey("pseudonymize", "customer") == hkdf_sha256(
        KEY, None, b"safetwin/v1/pseudonymize/customer", 32
    )
    assert key.subkey("pseudonymize", "customer") != key.subkey("pseudonymize", "orders.id")
    assert key.subkey("pseudonymize", "customer") != key.subkey("fake", "customer")


def test_the_fingerprint_is_the_first_8_bytes_of_an_hmac() -> None:
    expected = hmac.new(KEY, b"safetwin/v1/fingerprint", hashlib.sha256).digest()[:8].hex()
    assert fingerprint(KEY) == expected == MasterKey(KEY).fingerprint
    assert len(expected) == 16


def test_a_key_shows_its_fingerprint_and_never_itself() -> None:
    key = MasterKey(KEY)
    for text in (repr(key), str(key), f"{key}"):
        assert KEY_HEX not in text
        assert key.fingerprint in text
    assert KEY_HEX not in repr(Subkeys(key, [("pseudonymize", "customer")]))
    assert "hidden" in repr(Mac(KEY))


# --- references --------------------------------------------------------------------------------------------


def test_env_reference() -> None:
    assert resolve_key("env://K", {"K": KEY_HEX}).fingerprint == fingerprint(KEY)
    assert resolve_key("env://K", {"K": KEY_HEX.upper() + "\n"}).fingerprint == fingerprint(KEY)


@pytest.mark.parametrize(
    ("environ", "message"),
    [
        ({}, "the environment variable K (key: env://K) is not set"),
        ({"K": ""}, "is not set"),
        ({"K": "zz" * 32}, "does not hold a key: it must be 64 hexadecimal characters"),
        ({"K": "ab" * 31}, "does not hold a key"),
        ({"K": "ab" * 33}, "does not hold a key"),
    ],
)
def test_env_reference_errors_never_show_the_value(environ: dict[str, str], message: str) -> None:
    with pytest.raises(KeyRefError, match=re.escape(message)) as err:
        resolve_key("env://K", environ)
    for value in environ.values():
        if value:
            assert value.strip() not in str(err.value)


def test_a_bad_env_name_and_other_schemes() -> None:
    with pytest.raises(KeyRefError, match="env://NAME"):
        resolve_key("env://not a name", {})
    with pytest.raises(KeyRefError, match="keychain:// keys are not supported yet"):
        resolve_key("keychain://shop", {})
    with pytest.raises(KeyRefError, match="never the key") as err:
        resolve_key(KEY_HEX, {})
    assert KEY_HEX not in str(err.value)


def _key_file(path: Path, text: str, mode: int = 0o600) -> Path:
    path.write_text(text, encoding="ascii")
    os.chmod(path, mode)
    return path


def test_file_reference(tmp_path: Path) -> None:
    path = _key_file(tmp_path / "k", KEY_HEX + "\n")
    assert resolve_key(f"file://{path}").fingerprint == fingerprint(KEY)
    assert resolve_key(f"file://{_key_file(tmp_path / 'k2', KEY_HEX)}").fingerprint == fingerprint(KEY)


def test_file_reference_expands_the_home_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    _key_file(tmp_path / "shop.key", KEY_HEX + "\n")
    assert resolve_key("file://~/shop.key").fingerprint == fingerprint(KEY)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644, 0o700 | 0o004])
def test_a_key_file_that_others_can_use_is_refused(tmp_path: Path, mode: int) -> None:
    path = _key_file(tmp_path / "k", KEY_HEX, mode)
    with pytest.raises(KeyRefError, match="can be read or changed by others") as err:
        resolve_key(f"file://{path}")
    assert KEY_HEX not in str(err.value)


@pytest.mark.parametrize(
    "text", [KEY_HEX + "\n\n", " " + KEY_HEX, KEY_HEX[:-1], "zz" * 32, KEY_HEX + "\r\n", ""]
)
def test_a_key_file_that_holds_no_key_is_refused_without_its_content(tmp_path: Path, text: str) -> None:
    path = _key_file(tmp_path / "k", text)
    with pytest.raises(KeyRefError, match="does not hold a key") as err:
        resolve_key(f"file://{path}")
    if text.strip():
        assert text.strip() not in str(err.value)


def test_a_symlink_a_folder_and_a_missing_file_are_refused(tmp_path: Path) -> None:
    target = _key_file(tmp_path / "k", KEY_HEX)
    (tmp_path / "link").symlink_to(target)
    with pytest.raises(KeyRefError, match="symbolic link"):
        resolve_key(f"file://{tmp_path / 'link'}")
    folder = tmp_path / "folder"
    folder.mkdir(mode=0o700)
    with pytest.raises(KeyRefError, match="not a regular file"):
        resolve_key(f"file://{folder}")
    with pytest.raises(KeyRefError, match="cannot open the key file"):
        resolve_key(f"file://{tmp_path / 'missing'}")


def test_a_key_file_of_another_user_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _key_file(tmp_path / "k", KEY_HEX)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(path).st_uid + 1)
    with pytest.raises(KeyRefError, match="belongs to another user"):
        resolve_key(f"file://{path}")


# --- new keys ----------------------------------------------------------------------------------------------


def test_a_new_key_file_is_0600_and_never_replaced(tmp_path: Path) -> None:
    path = tmp_path / "deep" / "er" / "shop.key"
    old_umask = os.umask(0)
    try:
        key = new_key_file(path)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert resolve_key(f"file://{path}").fingerprint == key.fingerprint
    before = path.read_bytes()
    with pytest.raises(KeyRefError, match="exists already"):
        new_key_file(path)
    assert path.read_bytes() == before


def test_new_keys_are_random() -> None:
    from safetwin.keys import new_key

    assert len({new_key().fingerprint for _ in range(20)}) == 20


@given(key=st.binary(min_size=0, max_size=100), message=st.binary(max_size=200))
def test_the_fast_hmac_equals_the_standard_library(key: bytes, message: bytes) -> None:
    mac = Mac(key)
    assert mac.digest(message) == hmac.digest(key, message, "sha256")
    assert mac.digests([message, b""]) == [hmac.digest(key, m, "sha256") for m in (message, b"")]


def test_every_missing_key_folder_is_private(tmp_path: Path) -> None:
    old = os.umask(0o022)
    try:
        new_key_file(tmp_path / "a" / "b" / "c" / "shop.key")
    finally:
        os.umask(old)
    for folder in ("a", "a/b", "a/b/c"):
        assert stat.S_IMODE((tmp_path / folder).stat().st_mode) == 0o700, folder
