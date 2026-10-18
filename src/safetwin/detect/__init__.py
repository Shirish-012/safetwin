"""Detectors of personal data (docs/guide.md), shared by `safetwin mask` (the residual scan) and
`safetwin scan` (M1b).

- `validators`: yes/no on one Python value (email, phone, card + Luhn, IBAN mod-97, IPv4/IPv6, UUID,
  plausible birth date). No data library.
- `names`: what a column's name suggests. No data library.
- `exprs`: the validators as Polars expressions, match counts per column, and the residual-scan API. Import it
  explicitly: it loads Polars, which this package's `__init__` must not (the control plane may import it).
"""
