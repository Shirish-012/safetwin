# Security policy

safetwin exists to keep personal data where it belongs, so we treat these as security problems:

- a data value, a key or a database password that ends up somewhere it shouldn't: a log, a message, a
  report, a temporary file (a staging folder left behind included), a cache, an exported script, the run
  history or the page's history;
- a write to a Postgres source, or to a target before every check has passed;
- a masked column that still holds input values, or a method that is weaker than its documentation says;
- a way to recover input values from a twin without the key (beyond what the report's privacy classes
  already say: pseudonymized data is still personal data while the key exists);
- a mistake in the key handling or the cryptography (HKDF, HMAC-SHA-256, AES-SIV), or an access key that
  reads more than the columns `encrypt` masked;
- a way for another program or website to reach `safetwin ui` (it should answer only the page it opened);
- a policy, a source file or a column name that makes safetwin or an exported script run code or touch
  files it shouldn't.

## Reporting a problem

Please report it privately, through GitHub's **Report a vulnerability** button on the repository's
Security tab. Don't open a public issue, and don't include real data or keys: a made-up file that shows the
problem is enough.

1.0.0 is the final release and safetwin is no longer actively developed, so answers and fixes are best
effort. Reports are still welcome: they warn other users, and anyone running a fork can act on them.

## Supported versions

1.0.0, the final release.
