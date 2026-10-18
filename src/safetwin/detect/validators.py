"""Value validators on single Python values (docs/guide.md).

They answer yes or no; nothing here keeps, logs or returns a value. The Polars versions that count matches in
a whole column are in `exprs.py`; the tests check that the two agree.
"""

import ipaddress
import re
from datetime import date, datetime

EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
# E.164 (+ and 7 to 15 digits, optionally grouped), North American (415) 555-0142 / 415-555-0142 /
# 415.555.0142, and national numbers with a trunk 0 and groups (020 7946 0018).
PHONE = (
    r"(?:^|[^\w+])(?:"
    r"\+[1-9]\d{0,2}(?:[ .-]?\(?\d{1,4}\)?){2,5}"
    r"|\(\d{3}\) ?\d{3}[-. ]\d{4}"
    r"|\d{3}[-.]\d{3}[-.]\d{4}"
    r"|0\d{2,4}[ -]\d{3,4}[ -]\d{3,4}"
    r")(?:$|[^\w])"
)
CARD_CANDIDATE = r"\d(?:[ -]?\d){12,18}"
IBAN_CANDIDATE = r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"
IPV4 = r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
_H = "[0-9A-Fa-f]{1,4}"
IPV6 = (
    r"(?:^|[^0-9A-Za-z:])(?:"
    rf"(?:{_H}:){{7}}{_H}"
    rf"|(?:{_H}:){{1,7}}:"
    rf"|(?:{_H}:){{1,6}}:{_H}"
    rf"|(?:{_H}:){{1,5}}(?::{_H}){{1,2}}"
    rf"|(?:{_H}:){{1,4}}(?::{_H}){{1,3}}"
    rf"|(?:{_H}:){{1,3}}(?::{_H}){{1,4}}"
    rf"|(?:{_H}:){{1,2}}(?::{_H}){{1,5}}"
    rf"|{_H}:(?::{_H}){{1,6}}"
    rf"|:(?::{_H}){{1,7}}"
    rf"|(?:(?:{_H}:){{1,6}}|::(?:{_H}:){{0,5}})(?:\d{{1,3}}\.){{3}}\d{{1,3}}"  # an IPv4 tail
    r"|::"
    r")(?:$|[^0-9A-Za-z:])"
)
UUID = r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"
ISO_DATE = r"^\s*\d{4}-\d{2}-\d{2}\s*$"
BIRTH_MIN = date(1900, 1, 1)
MIN_AGE_YEARS = 13


def birth_max(today: date | None = None) -> date:
    """The latest plausible birth date: today minus 13 years (28 February in a non-leap year for 29 Feb)."""
    today = today or date.today()
    try:
        return today.replace(year=today.year - MIN_AGE_YEARS)
    except ValueError:
        return today.replace(year=today.year - MIN_AGE_YEARS, day=28)


def is_email(text: str) -> bool:
    return re.fullmatch(EMAIL, text.strip()) is not None


def is_phone(text: str) -> bool:
    return re.search(PHONE, text) is not None


def luhn_ok(digits: str) -> bool:
    """The Luhn check on a string of digits."""
    if not digits.isdigit():
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def is_card(text: str) -> bool:
    """13 to 19 digits once spaces and dashes are removed, passing Luhn."""
    digits = re.sub(r"[ -]", "", text.strip())
    return 13 <= len(digits) <= 19 and digits.isdigit() and luhn_ok(digits)


def iban_ok(text: str) -> bool:
    """ISO 13616 mod-97: move the first four characters to the end, letters become 10..35, remainder 1."""
    s = text.replace(" ", "").upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1


def is_ipv4(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_ipv6(text: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(text.strip()), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_uuid(text: str) -> bool:
    return re.fullmatch(UUID, text.strip()) is not None


def is_birth_date(value: date | datetime | str, today: date | None = None) -> bool:
    """A date in [1900-01-01, today - 13 years]; text must be an ISO date (YYYY-MM-DD)."""
    if isinstance(value, str):
        if not re.fullmatch(ISO_DATE, value):
            return False
        try:
            value = date.fromisoformat(value.strip())
        except ValueError:
            return False
    if isinstance(value, datetime):
        value = value.date()
    return BIRTH_MIN <= value <= birth_max(today)
