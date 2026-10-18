"""Column-name signals (docs/guide.md): what a column's name suggests it holds.

A name is split into lower-case words (`firstName`, `first_name` and `FIRST-NAME` are all `first`, `name`), so
a short pattern such as `ip` matches the word `ip` and never the inside of `zip` or `description`.
"""

import re
from itertools import pairwise

# signal -> (whole words or word pairs, word prefixes)
_SIGNALS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "email": (("email", "mail", "e_mail"), ("email", "mail")),
    "phone": (("phone", "mobile", "tel", "telephone", "cell", "fax"), ("phone", "mobile", "telephone")),
    "name": (("name", "first_name", "last_name", "full_name", "surname", "given_name", "forename"), ()),
    "address": (("address", "street", "addr"), ("address", "street")),
    "postcode": (
        ("zip", "postcode", "postal", "zipcode", "post_code", "postal_code"),
        ("postcode", "zipcode"),
    ),
    "birth_date": (("dob", "birth", "birthday", "birthdate", "date_of_birth"), ("birth",)),
    "national_id": (("ssn", "national_id", "passport", "nin", "social_security"), ("passport",)),
    "iban": (("iban",), ("iban",)),
    "card": (("card", "pan", "cc", "card_number", "credit_card"), ("card",)),
    "ip": (("ip", "ip_address", "ipaddr", "ipv4", "ipv6"), ("ipaddr",)),
    "geo": (("lat", "lon", "lng", "latitude", "longitude"), ("latitude", "longitude")),
    "user_agent": (("user_agent", "useragent"), ("useragent",)),
}


def words(column: str) -> list[str]:
    """`customerFirstName` and `customer_first_name` → ['customer', 'first', 'name']."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", column)
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [w for w in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if w]


def name_signals(column: str) -> list[str]:
    """The signals a column name gives, in a fixed order (an empty list when it gives none)."""
    ws = words(column)
    pairs = {f"{a}_{b}" for a, b in pairwise(ws)}
    found = []
    for signal, (whole, prefixes) in _SIGNALS.items():
        if (
            any(w in whole for w in ws)
            or pairs & set(whole)
            or any(w.startswith(prefixes) for w in ws if prefixes)
        ):
            found.append(signal)
    return found
