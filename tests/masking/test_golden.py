"""Pinned outputs: the exact values every method makes from fixed inputs with a fixed key.

These are the `safetwin/v1` formats (docs/security.md). A change that makes any of these fail changes what
users' twins hold: their pseudonyms no longer match older twins, or their encrypted files no longer open. Such
a change needs a new derivation version, not an edit of the values below.
"""

from datetime import date, datetime

import polars as pl

from safetwin.masking.hmacs import Mac
from safetwin.masking.portable import Keys, Sealer, access_key, decrypt_series, subset_filters

from .conftest import KEY_A, run_mask

RAW = bytes.fromhex("a1" * 32)

FRAME = pl.DataFrame(
    {
        "id": [1, 2, 42],
        "code": ["A-1", "B-2", "C-3"],
        "email": ["ann@example.org", "bob@example.org", "cy@example.org"],
        "name": ["Ann Lee", "Bob Ray", "Cy Doe"],
        "phone": ["+1 212 555 0100", "+1 212 555 0101", "+1 212 555 0102"],
        "born": [date(1980, 5, 17), date(1991, 12, 1), date(2001, 2, 28)],
        "seen": [datetime(2024, 3, 1, 12, 30), datetime(2024, 3, 2, 8, 0), datetime(2024, 3, 3, 23, 59)],
        "card": ["4111111111111111", "5500005555555559", "340000000000009"],
        "ip": ["192.168.1.77", "10.0.0.5", "2001:db8::1"],
    }
)
SPECS = {
    "id": {"method": "pseudonymize", "domain": "customer"},
    "code": {"method": "pseudonymize", "format": "hex", "prefix": "c_"},
    "email": {"method": "fake", "kind": "email"},
    "name": {"method": "fake", "kind": "name"},
    "phone": {"method": "fake", "kind": "phone"},
    "born": {"method": "generalize", "to": "year"},
    "seen": {"method": "date_shift", "entity": "id"},
    "card": {"method": "redact", "keep_last": 4},
    "ip": {"method": "generalize", "ip": True},
}
EXPECTED = {
    "id": [2322497238483933968, 20682186173356418, 1404663369146038838],
    "code": ["c_grn4gh5afgoof74k3uydn4344y", "c_rs6mshb37o6vddfnwgyct5a7tq", "c_y7oh2emgcsc2bjo2olbwwzxat4"],
    "email": [
        "gregory.miller.zr25xi@example.org",
        "sarah.phillips.zwk2r4@example.net",
        "david.white.mid6mb@example.net",
    ],
    "name": ["Douglas Morales", "Michael Garcia", "Carl Clark"],
    "phone": ["+1 213 555-0134", "+1 201 555-0189", "+1 312 555-0102"],
    "born": [date(1980, 1, 1), date(1991, 1, 1), date(2001, 1, 1)],
    "seen": [datetime(2024, 2, 16, 12, 30), datetime(2024, 3, 14, 8, 0), datetime(2024, 3, 28, 23, 59)],
    "card": ["************1111", "************5559", "***********0009"],
    "ip": ["192.168.1.0", "10.0.0.0", "2001:db8::"],
}


def test_every_one_way_method_makes_the_same_values_as_in_version_1() -> None:
    out = run_mask(FRAME, SPECS)
    for column, values in EXPECTED.items():
        assert out[column].to_list() == values, column


def test_uuid_pseudonyms_are_pinned() -> None:
    out = run_mask(pl.DataFrame({"u": ["x", "y"]}), {"u": {"method": "pseudonymize", "format": "uuid"}})
    assert out["u"].to_list() == [
        "f4c5947a-b1dd-8a98-a390-1670e5fb1ded",
        "1eb36221-d4e7-8088-a6f5-12ff9bf1b50d",
    ]


def test_the_key_fingerprint_and_the_access_key_are_pinned() -> None:
    assert KEY_A.fingerprint == "ea8427e75815808d"
    assert access_key(RAW).hex() == "c30f0ac3556daf0ec83a693d84ca6d459081cd7490bc387c2ced1fa42f25ee97"
    assert KEY_A.access_key() == access_key(RAW)
    assert Keys(RAW).sealer().fingerprint == "04439f0e74ada3be"


def test_encrypted_values_made_by_version_1_still_open() -> None:
    sealer = Sealer(access_key(RAW))
    tokens = [
        "st1.br3yhjuskDX0wF5GjDo8Y56kWo_aWr217lfLpdBQajoYbSqzMI5rXmStHOXPvKPZ",
        "st1.V-gTetDxnn69Uh6w5YRMpDWNKHB2q69Sw6PtABcXI5M",
    ]
    assert sealer.seal(b"sann@example.org") == tokens[0]  # deterministic: the same token every time
    assert decrypt_series(pl.Series("e", tokens), sealer).to_list() == ["ann@example.org", ""]
    number = "st1.nOoUfbK6aVVbgY3GhdAXnNJePkd7eAiD0Z_e3btH0i4"
    assert decrypt_series(pl.Series("n", [number]), sealer).to_list() == [42]
    out = run_mask(pl.DataFrame({"n": [42]}), {"n": "encrypt"})
    assert out["n"].to_list() == [number]


def test_the_subset_picks_the_same_root_rows_as_in_version_1() -> None:
    frames = {"customers": pl.DataFrame({"id": list(range(1, 101))})}
    mac = Mac(KEY_A.subkey("subset", "customers"))
    found, rows = subset_filters(frames, "customers", "id", 0.2, False, [], mac)
    picked = frames["customers"].filter(found["customers"])["id"].to_list()
    assert rows == 19
    assert picked == [2, 4, 6, 9, 12, 13, 16, 24, 26, 48, 65, 72, 77, 79, 81, 82, 89, 95, 97]
