"""The example shop: a synthetic `customers` and `orders` table with planted personal data, for
`safetwin demo` and the tests (examples/shop/generate.py runs it from the repository).

    safetwin demo DIR                 writes DIR/data/customers.parquet and DIR/data/orders.parquet
    python examples/shop/generate.py OUT_DIR [--customers N] [--csv]

Everything is made up, from a fixed seed: the same command always writes the same data. Names are built from
invented syllables, emails use the reserved example.* domains, phone numbers the 555-0100..0199 range reserved
for fiction, card numbers are random 16-digit numbers starting with 4 that pass the Luhn check (test numbers,
not real cards), and IP addresses come from the documentation ranges (RFC 5737, RFC 3849).

customers: id, full_name, email, phone, birth_date, postcode, city, notes (free text, some with an email in
it), created_at. orders: id, customer_id (→ customers.id), card_number, ip_address, placed_at, total.
"""

import argparse
import random
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

import polars as pl

SEED = 20261003
_ONSETS = [
    "b",
    "br",
    "c",
    "d",
    "dr",
    "f",
    "g",
    "gr",
    "h",
    "j",
    "k",
    "l",
    "m",
    "n",
    "p",
    "r",
    "s",
    "t",
    "v",
    "z",
]
_VOWELS = ["a", "e", "i", "o", "u", "ae", "ia", "ou"]
_CODAS = ["", "n", "r", "l", "s", "th", "nd", "x"]
_CITIES = [
    "Avenmoor",
    "Brackwell",
    "Corrinth",
    "Dovelake",
    "Embervale",
    "Frostholm",
    "Gallowmere",
    "Hearthby",
]
_WORDS = ["called", "about", "delivery", "refund", "prefers", "evening", "calls", "wrote", "from", "asked"]


def _name(rng: random.Random) -> str:
    syllables = rng.randint(2, 3)
    return "".join(
        rng.choice(_ONSETS) + rng.choice(_VOWELS) + rng.choice(_CODAS) for _ in range(syllables)
    ).title()


def _card(rng: random.Random) -> str:
    digits = [4] + [rng.randint(0, 9) for _ in range(14)]
    total = 0
    for i, d in enumerate(reversed(digits)):  # the check digit goes last: positions shift by one
        total += (d * 2 - 9 if d > 4 else d * 2) if i % 2 == 0 else d
    digits.append((10 - total % 10) % 10)
    text = "".join(map(str, digits))
    return " ".join(text[i : i + 4] for i in range(0, 16, 4))


def _ip(rng: random.Random) -> str:
    if rng.random() < 0.8:
        return f"{rng.choice(['192.0.2', '198.51.100', '203.0.113'])}.{rng.randint(1, 254)}"
    return f"2001:db8:{rng.randint(0, 0xFFFF):x}:{rng.randint(0, 0xFFFF):x}::{rng.randint(1, 0xFFFF):x}"


def generate(customers: int = 1000, orders_per_customer: int = 3) -> tuple[pl.DataFrame, pl.DataFrame]:
    rng = random.Random(SEED)
    start = datetime(2023, 1, 1)
    rows: list[dict[str, Any]] = []
    for i in range(1, customers + 1):
        first, last = _name(rng), _name(rng)
        email = f"{first.lower()}.{last.lower()}{i}@example.com"
        note = None
        if rng.random() < 0.5:
            note = f"{rng.choice(_WORDS)} {rng.choice(_WORDS)}"
            if rng.random() < 0.5:
                note += f", reach at {first.lower()}{i}@example.org"
        rows.append(
            {
                "id": i,
                "full_name": f"{first} {last}",
                "email": email,
                "phone": f"({rng.randint(201, 989)}) 555-01{rng.randint(0, 99):02d}"
                if rng.random() < 0.9
                else None,
                "birth_date": date(1940, 1, 1) + timedelta(days=rng.randint(0, 365 * 60)),
                "postcode": f"{rng.randint(10000, 99999)}",
                "city": rng.choice(_CITIES),
                "notes": note,
                "created_at": start + timedelta(seconds=rng.randint(0, 3 * 365 * 86400)),
            }
        )
    customers_df = pl.DataFrame(rows, schema_overrides={"id": pl.Int64, "created_at": pl.Datetime("us")})
    order_rows = []
    for n in range(1, customers * orders_per_customer + 1):
        customer = rng.randint(1, customers)
        created = rows[customer - 1]["created_at"]
        order_rows.append(
            {
                "id": n,
                "customer_id": customer,
                "card_number": _card(rng),
                "ip_address": _ip(rng),
                "placed_at": created + timedelta(days=rng.randint(0, 200), seconds=rng.randint(0, 86400)),
                "total": round(rng.uniform(5, 500), 2),
            }
        )
    orders_df = pl.DataFrame(
        order_rows, schema_overrides={"id": pl.Int64, "customer_id": pl.Int64, "placed_at": pl.Datetime("us")}
    )
    return customers_df, orders_df


def write(out: Path, customers: int = 1000, *, csv: bool = False) -> tuple[int, int]:
    """Write the shop's Parquet files (and CSV files with `csv`) into `out`; return the rows of each table."""
    out.mkdir(parents=True, exist_ok=True)
    customers_df, orders_df = generate(customers)
    for name, frame in (("customers", customers_df), ("orders", orders_df)):
        frame.write_parquet(out / f"{name}.parquet")
        if csv:
            frame.write_csv(out / f"{name}.csv")
    return customers_df.height, orders_df.height


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the synthetic example shop (customers, orders).")
    parser.add_argument("out", type=Path, help="the folder to write into (created if missing)")
    parser.add_argument("--customers", type=int, default=1000, help="number of customers (orders: 3 each)")
    parser.add_argument("--csv", action="store_true", help="also write CSV files")
    args = parser.parse_args(argv)
    customers, orders = write(args.out, args.customers, csv=args.csv)
    print(f"wrote customers ({customers:,} rows) and orders ({orders:,} rows) to {args.out}")
    return 0
