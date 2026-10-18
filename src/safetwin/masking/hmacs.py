"""Keyed hashing for the masking methods: the subkeys of a run, and (from `portable`) the canonical bytes of
values and HMAC-SHA-256.

- **Canonical bytes** and the **HMAC** are in `portable.py` (its `canonical` documents every format), the
  code that `safetwin export` copies into the exported script, so both compute the same bytes.
- **Subkeys** are derived once per run from the key (`safetwin.keys`) and kept in memory: the pipeline text
  only names the method and domain.
"""

from collections.abc import Iterable

from safetwin.keys import MasterKey

from .portable import Mac, Sealer, canonical, is_text

__all__ = ["Mac", "Sealer", "Subkeys", "canonical", "is_text"]


class Subkeys:
    """The subkeys of one run, by (method, domain), as `Mac`s. Only the methods and domains show in a repr."""

    __slots__ = ("_macs", "_sealer")

    def __init__(self, key: MasterKey, uses: Iterable[tuple[str, str]]) -> None:
        uses = sorted(set(uses))
        self._macs = {use: Mac(key.subkey(*use)) for use in uses if use[0] != "encrypt"}
        self._sealer = Sealer(key.access_key()) if any(use[0] == "encrypt" for use in uses) else None

    def sealer(self) -> Sealer:
        if self._sealer is None:
            raise LookupError("no access key was derived for encrypt")
        return self._sealer

    def mac(self, method: str, domain: str) -> Mac:
        try:
            return self._macs[(method, domain)]
        except KeyError:
            raise LookupError(f"no subkey was derived for {method} in domain {domain}") from None

    def __repr__(self) -> str:
        return f"Subkeys({len(self._macs)} uses)"
