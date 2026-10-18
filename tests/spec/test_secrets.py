"""How inline secrets are recognised (shapes of token, places they hide) and that no message repeats one."""

import base64
import random
import string
from collections.abc import Callable
from typing import Any

import pytest

from safetwin.spec import Pipeline, Problem, find_secrets, redacted, validate_pipeline

Make = Callable[..., Pipeline]
Doc = Callable[..., dict[str, Any]]

REDACTED = "<redacted>"


def flagged(value: str) -> bool:
    """Whether the validator takes `value` for a secret: `redacted` hides exactly those."""
    return redacted(value) == REDACTED


def rate(values: list[str]) -> float:
    return sum(map(flagged, values)) / len(values)


# All the random test data comes from one seeded generator, in this order, so it never changes.
_rng = random.Random(20260930)


def tokens(alphabet: str, length: int, count: int) -> list[str]:
    return ["".join(_rng.choices(alphabet, k=length)) for _ in range(count)]


LOWER_HEX = "0123456789abcdef"
HEX_KEYS = [(n, key) for n in (32, 40, 64) for key in tokens(LOWER_HEX, n, 6)]
BASE64 = [base64.b64encode(_rng.randbytes(30)).decode() for _ in range(10)]
BASE64URL = [base64.urlsafe_b64encode(_rng.randbytes(32)).decode().rstrip("=") for _ in range(10)]
BASE62 = tokens(string.ascii_letters + string.digits, 32, 10)
BASE36_LOWER = tokens(string.ascii_lowercase + string.digits, 32, 10)
BASE36_UPPER = tokens(string.ascii_uppercase + string.digits, 32, 10)
BASE32_SEEDS = [base64.b32encode(_rng.randbytes(20)).decode() for _ in range(300)]  # 32 of A-Z and 2-7
LOWER_LETTERS = tokens(string.ascii_lowercase, 40, 300)
GITHUB_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


# --- token shapes --------------------------------------------------------------------------------


@pytest.mark.parametrize(("length", "key"), HEX_KEYS)
def test_hex_keys_are_secrets_at_any_length_from_32(length: int, key: str) -> None:
    assert len(key) == length
    assert flagged(key)
    assert flagged(key.upper())


@pytest.mark.parametrize("length", [8, 16, 24, 31])
def test_short_hex_strings_are_not_keys(length: int) -> None:
    # 24 hex characters is a MongoDB ObjectId; nothing below 32 counts.
    assert not any(flagged(key) for key in tokens(LOWER_HEX, length, 20))


def test_a_long_run_of_digits_is_a_number_not_a_key() -> None:
    assert not any(flagged(number) for number in tokens(string.digits, 40, 20))


@pytest.mark.parametrize("token", BASE64 + BASE64URL + BASE62)
def test_mixed_case_tokens_are_secrets(token: str) -> None:
    assert flagged(token)


@pytest.mark.parametrize("token", BASE36_LOWER + BASE36_UPPER)
def test_single_case_tokens_with_digits_are_secrets(token: str) -> None:
    assert flagged(token)


def test_base32_seeds_are_secrets() -> None:
    # TOTP seeds and other base32 keys: A-Z and 2-7. About 98% of random ones are recognised.
    assert rate(BASE32_SEEDS) >= 0.95
    assert all(flagged(seed) for seed in BASE32_SEEDS[:5])


def test_random_lowercase_letters_are_mostly_secrets() -> None:
    # Letters only give the least away, so this is the weakest family: about 98% at 40 characters.
    assert rate(LOWER_LETTERS) >= 0.93


@pytest.mark.parametrize(
    "credential",
    [
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # the sample AWS secret access key
        "sk_" + "test_4eC39HqLyjWDarjtT1zdp7dc",  # the sample Stripe key
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",  # Azure
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "SG."
        + "ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr",  # the sample SendGrid key
        "key-3ax6xnjp29jd6fds4gc373sgvjxteol0",  # the sample Mailgun key
    ],
)
def test_the_credentials_from_vendor_docs_are_secrets(credential: str) -> None:
    assert flagged(credential)


# --- where a token can hide ----------------------------------------------------------------------

CONTEXTS = {
    "alone": "{}",
    "bearer-header": "Authorization: Bearer {}",
    "bearer": "Bearer {}",
    "after-a-word": "token {}",
    "key=value": "api_key={}",
    "url-query": "https://api.example.com/v1/items?api_key={}&limit=10",
    "url-password": "postgres://user:{}@db.internal:5432/warehouse",
    "sql-literal": "SELECT * FROM t WHERE k = '{}' AND x > 1",
    "json": '{{"key": "{}", "n": 1}}',
    "cli-flag": "--token={} --verbose",
    "prefixed": "secret_{}",
}
HIDERS = [BASE64[0], BASE62[0], BASE36_LOWER[0], BASE36_UPPER[0], HEX_KEYS[7][1], HEX_KEYS[13][1]]


@pytest.mark.parametrize("token", HIDERS, ids=lambda token: token[:6])
@pytest.mark.parametrize("context", CONTEXTS.values(), ids=CONTEXTS.keys())
def test_a_token_is_found_wherever_it_sits(context: str, token: str) -> None:
    assert flagged(context.format(token))


def test_a_bearer_header_in_a_config_is_reported_with_its_path(make: Make, nodes: Any) -> None:
    header = {"headers": {"Authorization": f"Bearer {BASE64[1]}"}}
    problems = validate_pipeline(make([nodes.source(config=header)]))
    assert [p.code for p in problems] == ["inline_secret"]
    assert "spec.nodes[read].config.headers.Authorization" in problems[0].message
    assert BASE64[1] not in problems[0].message


# --- what must not be flagged --------------------------------------------------------------------

LONG_SQL = """SELECT date_trunc('hour', placed_at) AS hour,
       country,
       count(*)                        AS orders,
       sum(amount_net + amount_tax)    AS amount
FROM input
GROUP BY 1, 2
ORDER BY amount DESC"""

NOT_SECRETS = [
    "SafeTwin/shop/orders/dt={yyyy}-{MM}-{dd}/hr={HH}/",
    "SafeTwin/shop/orders/dt=2026-09-01/hr=13/",
    "/Users/me/projects/safetwin/examples/",
    "s3://my-analytics-bucket/SafeTwin/shop/orders/",
    "https://storage.googleapis.com/bucket-name/path/to/file.csv",
    "postgresql://analytics_ro@db-prod-01.internal:5432/warehouse",
    "arn:aws:s3:::my-analytics-bucket/reports/network/2026-09-29/summary",
    "https://accounts.google.com/o/oauth2/v2/auth?client_id=1234567890-abcdefg.apps.googleusercontent.com",
    "com/o/oauth2/v2/auth",
    "my-company-analytics-data-lake-prod-eu-west-1",
    "customer_lifetime_value_estimate_usd_2026q3",
    "risk-assessment-for-customer-orders-2026",
    "AssumeRoleWithWebIdentityCommand",
    "TypeScriptInlayHintPreferencePage",
    "run=2026-09-29T02-00-00Z_44",
    "dt=2026-09-29/part-00000-r45",
    "backup_2026_09_29_02_00_00_full",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "72F988BF-86F1-41AF-91AB-2D7CD011DB47",
    "collection-a712d850-b71a-4a5e-af70-15281e61c948",
    "projects/my-project/locations/eu/instances/a712d850-b71a-4a5e-af70-15281e61c948",
    "507f1f77bcf86cd799439011",
    "12345678901234567890123456789012",
    "sha256_checksum_validation_report",
    "secret://" + HEX_KEYS[7][1],
    "keychain://safetwin/shop-key",
    "socket://local-inbox",
    LONG_SQL,
    "The quick brown fox jumps over the lazy dog and keeps on running for miles and miles",
]


@pytest.mark.parametrize("value", NOT_SECRETS)
def test_paths_names_dates_ids_prose_sql_and_references_are_not_secrets(value: str) -> None:
    assert not flagged(value)


def test_the_docs_own_paths_and_sql_pass_validation(make: Make, nodes: Any) -> None:
    config = {"path": NOT_SECRETS[0], "sql": LONG_SQL}
    assert validate_pipeline(make([nodes.source(config=config)])) == []


VOCABULARY = [
    *[
        "customer",
        "order",
        "payment",
        "invoice",
        "shipment",
        "network",
        "flow",
        "refund",
        "session",
        "device",
    ],
    *[
        "sensor",
        "reading",
        "temperature",
        "daily",
        "hourly",
        "summary",
        "total",
        "average",
        "lifetime",
        "value",
    ],
    *[
        "estimate",
        "report",
        "archive",
        "backup",
        "staging",
        "production",
        "analytics",
        "warehouse",
        "lake",
        "raw",
    ],
    *[
        "clean",
        "masked",
        "encrypted",
        "source",
        "target",
        "region",
        "account",
        "balance",
        "transaction",
        "ledger",
    ],
    "audit",
]


def names(count: int) -> list[str]:
    """Names of the kinds people write: snake, kebab, Pascal and camel case, paths, and names with a year."""
    made = []
    for _ in range(count):
        words = [_rng.choice(VOCABULARY) for _ in range(_rng.randint(3, 6))]
        made += ["_".join(words), "-".join(words), "".join(w.title() for w in words), "/".join(words)]
        made += [
            "_".join(words).upper(),
            "_".join(words) + f"_{_rng.randint(2020, 2030)}q{_rng.randint(1, 4)}",
        ]
        made.append(words[0] + "".join(w.title() for w in words[1:]))
    return [name for name in made if len(name) >= 20]


def test_names_and_paths_made_of_words_are_never_secrets() -> None:
    generated = names(400)
    assert len(generated) > 1500
    assert [name for name in generated if flagged(name)] == []


# --- digests and revisions are not secrets ------------------------------------------------------

DIGEST_KEYS = [
    "checksum",
    "sha256",
    "sha1",
    "md5",
    "hash",
    "digest",
    "etag",
    "commit",
    "revision",
    "rev",
    "git_sha",
]
SHA256 = next(key for length, key in HEX_KEYS if length == 64)
SHA1 = next(key for length, key in HEX_KEYS if length == 40)
MD5 = next(key for length, key in HEX_KEYS if length == 32)


def flagged_in_config(make: Make, nodes: Any, config: dict[str, Any]) -> list[Problem]:
    """The problems of a pipeline whose source has this config. The only ones that can come up are secrets."""
    return validate_pipeline(make([nodes.source(config=config)]))


@pytest.mark.parametrize("digest", [SHA256, SHA1, BASE64[0]], ids=["sha256", "git-commit", "base64"])
@pytest.mark.parametrize("key", DIGEST_KEYS)
def test_a_digest_under_a_digest_key_is_not_a_secret(make: Make, nodes: Any, key: str, digest: str) -> None:
    assert flagged(digest)  # on its own it would be taken for a secret
    assert flagged_in_config(make, nodes, {key: digest}) == []


@pytest.mark.parametrize("key", ["Checksum", "SHA256", "ETag", "Git_SHA", "MD5", "REVISION"])
def test_digest_keys_are_matched_without_regard_to_case(make: Make, nodes: Any, key: str) -> None:
    assert flagged_in_config(make, nodes, {key: SHA256}) == []


def test_digests_are_found_in_lists_and_in_nested_configs(make: Make, nodes: Any) -> None:
    config = {
        "checksum": [SHA256, SHA1],
        "files": [{"path": "a.csv", "sha256": SHA256}, {"path": "b.csv", "md5": MD5}],
        "pinned": {"commit": SHA1, "hashes": {"sha256": SHA256, "md5": MD5}},
    }
    assert flagged_in_config(make, nodes, config) == []


@pytest.mark.parametrize(
    ("prefix", "digest"),
    [("sha256:", SHA256), ("sha1:", SHA1), ("md5:", MD5), ("SHA256:", SHA256), ("Md5:", MD5.upper())],
)
def test_a_value_that_is_its_algorithm_and_a_digest_of_the_right_length_is_not_a_secret(
    make: Make, nodes: Any, prefix: str, digest: str
) -> None:
    value = prefix + digest
    assert flagged(digest)  # the digest alone would be taken for a key
    assert not flagged(value)
    assert flagged_in_config(make, nodes, {"expected": value, "seen": [value]}) == []


@pytest.mark.parametrize(
    "value",
    [
        "sha1:" + SHA256,  # 64 hex digits are not a sha1
        "md5:" + SHA1,
        "md5:" + SHA256,
        "sha256:" + SHA1,
        "sha256:" + SHA256[:-1],  # one digit short
        "sha256:" + SHA256 + "0",  # one digit too many
        "sha1:" + SHA1[:-1],
        "md5:" + MD5 + "0",
        "sha256:" + BASE64[0],  # not hex at all
        "sha256:" + BASE62[0],
        "SHA256:" + BASE36_LOWER[0],
    ],
)
def test_a_prefix_in_front_of_anything_but_a_digest_of_its_length_hides_nothing(
    make: Make, nodes: Any, value: str
) -> None:
    assert flagged(value)
    assert [p.code for p in flagged_in_config(make, nodes, {"expected": value})] == ["inline_secret"]


@pytest.mark.parametrize("value", [f"x sha256:{SHA256}", f"sha256:{SHA256} x", f"sha256:{SHA256}\n"])
def test_the_prefix_and_the_digest_must_be_the_whole_value(value: str) -> None:
    assert flagged(value)


def test_a_value_that_only_mentions_an_algorithm_is_not_exempt(make: Make, nodes: Any) -> None:
    value = f"Bearer {BASE64[1]} sha256:"
    assert flagged(value)
    assert [p.code for p in flagged_in_config(make, nodes, {"note": value})] == ["inline_secret"]


@pytest.mark.parametrize(
    "key",
    [
        "token",
        "api_key",
        "password",
        "secret",
        "value",
        "checksums",
        "checksum_token",
        "hash_key",
        "sha256_key",
    ],
)
@pytest.mark.parametrize(
    "secret", [SHA256, SHA1, BASE64[0], BASE36_LOWER[0]], ids=["sha256", "sha1", "base64", "base36"]
)
def test_the_same_values_under_other_keys_are_still_secrets(
    make: Make, nodes: Any, key: str, secret: str
) -> None:
    problems = flagged_in_config(make, nodes, {key: secret})
    assert [p.code for p in problems] == ["inline_secret"]
    assert f"spec.nodes[read].config.{key} looks like a secret" in problems[0].message
    assert secret not in problems[0].message


def test_a_digest_key_does_not_cover_what_is_nested_under_other_keys(make: Make, nodes: Any) -> None:
    config = {"checksum": {"token": BASE64[2]}, "commit": [{"password": SHA256}]}
    problems = flagged_in_config(make, nodes, config)
    assert [p.code for p in problems] == ["inline_secret", "inline_secret"]
    assert "config.checksum.token looks like" in problems[0].message
    assert "config.commit[0].password looks like" in problems[1].message


@pytest.mark.parametrize("credential", [AWS_KEY_ID, GITHUB_TOKEN])
def test_a_known_credential_is_a_secret_even_under_a_digest_key_or_after_a_prefix(
    make: Make, nodes: Any, credential: str
) -> None:
    for config in ({"commit": credential}, {"etag": [credential]}, {"value": f"sha256:{credential}"}):
        problems = flagged_in_config(make, nodes, config)
        assert [p.code for p in problems] == ["inline_secret"], config
        assert credential not in problems[0].message


def test_find_secrets_says_where_and_what_kind_and_never_shows_the_secret() -> None:
    value = {
        "a": [GITHUB_TOKEN, "fine"],
        "checksum": SHA256,  # under a digest key: not a secret
        "nested": {"key": AWS_KEY_ID},
        AWS_KEY_ID: GITHUB_TOKEN,  # a name that looks like a secret is redacted in the place
        "keys": {"are": "not looked at", AWS_KEY_ID + "x": "fine"},
    }
    found = list(find_secrets(value, "p"))
    assert found == [
        ("p.a[0]", "a GitHub token"),
        ("p.nested.key", "an AWS access key ID"),
        ("p.<redacted>", "a GitHub token"),
    ]
    assert not any(secret in where for where, _ in found for secret in (GITHUB_TOKEN, AWS_KEY_ID))
    assert list(find_secrets("a string on its own", "p")) == []
    assert list(find_secrets(GITHUB_TOKEN, "p")) == [("p", "a GitHub token")]


# --- messages never repeat a secret --------------------------------------------------------------

LOWER_ID = "k" + tokens(string.ascii_lowercase + string.digits, 31, 1)[0]  # a valid node id that looks random
SECRETS = [GITHUB_TOKEN, AWS_KEY_ID, HEX_KEYS[7][1], BASE64[2], BASE62[1], LOWER_ID]


def messages(problems: list[Problem]) -> str:
    return "\n".join(problem.message for problem in problems)


def test_redacted_hides_secrets_and_nothing_else() -> None:
    assert redacted("inbox") == "inbox"
    assert redacted("secret://keys/a") == "secret://keys/a"
    assert redacted(LONG_SQL) == LONG_SQL
    for secret in SECRETS:
        assert redacted(secret) == REDACTED


def problem_with(problems: list[Problem], code: str) -> Problem:
    """The one problem with this code. A secret in a free-form field is also an `inline_secret`."""
    found = [problem for problem in problems if problem.code == code]
    assert len(found) == 1, [problem.code for problem in problems]
    return found[0]


@pytest.mark.parametrize("secret", SECRETS)
def test_a_secret_used_as_a_socket_is_not_repeated(make: Make, nodes: Any, secret: str) -> None:
    problems = validate_pipeline(make([nodes.source(socket=secret)]))
    assert secret not in messages(problems)
    assert f"uses socket '{REDACTED}'" in problem_with(problems, "unknown_socket_alias").message


@pytest.mark.parametrize("secret", SECRETS)
def test_a_secret_used_as_a_reference_is_not_repeated(make: Make, nodes: Any, secret: str) -> None:
    in_inputs = make([nodes.source(), nodes.trim("clean", "read", secret)])
    on_a_port = make([nodes.source(), nodes.trim("clean", "read"), nodes.sink("write", f"clean.{secret}")])
    for p in (in_inputs, on_a_port):
        problems = validate_pipeline(p)
        assert secret not in messages(problems)
        assert REDACTED in problem_with(problems, "unknown_reference").message


def test_a_secret_used_as_an_operator_is_not_repeated(make: Make, nodes: Any) -> None:
    operator = "k" + tokens(string.ascii_lowercase + string.digits, 31, 1)[0] + ".step"
    problems = validate_pipeline(make([nodes.source(), nodes.step("clean", operator, "read")]))
    assert operator not in messages(problems)
    assert REDACTED in problem_with(problems, "unknown_operator").message


def test_a_node_id_that_looks_like_a_secret_is_hidden_in_messages_but_kept_in_node_id(
    make: Make, nodes: Any
) -> None:
    missing = validate_pipeline(make([nodes.source(), nodes.trim(LOWER_ID)]))
    duplicated = validate_pipeline(make([nodes.source(LOWER_ID), nodes.source(LOWER_ID)]))
    assert LOWER_ID not in messages(missing) + messages(duplicated)
    assert (
        problem_with(missing, "missing_input").node_id == LOWER_ID
    )  # the field is for tools that point at it
    assert problem_with(duplicated, "duplicate_id").node_id == LOWER_ID
    assert f"node id '{REDACTED}' is used 2 times" in problem_with(duplicated, "duplicate_id").message


def test_a_cycle_through_secret_looking_ids_is_not_repeated(make: Make, nodes: Any) -> None:
    other = "k" + tokens(string.ascii_lowercase + string.digits, 31, 1)[0]
    problems = validate_pipeline(make([nodes.trim(LOWER_ID, other), nodes.trim(other, LOWER_ID)]))
    assert LOWER_ID not in messages(problems)
    assert other not in messages(problems)
    assert f"{REDACTED} → {REDACTED} → {REDACTED}" in problem_with(problems, "cycle").message


def test_a_secret_used_as_an_alias_is_not_listed(make: Make, nodes: Any) -> None:
    sockets = {GITHUB_TOKEN: "socket://a", "inbox": "socket://b"}
    problems = validate_pipeline(make([nodes.source(socket="nowhere")], sockets=sockets))
    assert GITHUB_TOKEN not in messages(problems)
    assert f"aliases: {REDACTED}, inbox" in problem_with(problems, "unknown_socket_alias").message


def test_a_secret_used_as_a_config_key_is_not_repeated_in_the_path(make: Make, nodes: Any) -> None:
    config = {AWS_KEY_ID: AWS_KEY_ID, "nested": {HEX_KEYS[7][1]: [AWS_KEY_ID]}}
    problems = validate_pipeline(make([nodes.source(config=config)]))
    assert [p.code for p in problems] == ["inline_secret", "inline_secret"]
    assert AWS_KEY_ID not in messages(problems)
    assert HEX_KEYS[7][1] not in messages(problems)
    assert f"spec.nodes[read].config.{REDACTED} looks like" in problems[0].message
    assert f"config.nested.{REDACTED}[0] looks like" in problems[1].message


def test_no_message_repeats_any_secret_however_many_places_they_are_in(doc: Doc) -> None:
    document = doc(
        [
            {"id": LOWER_ID, "operator": "source.csv", "socket": SECRETS[0], "config": {"k": SECRETS[1]}},
            {"id": "clean", "operator": "transform.trim", "inputs": [f"{LOWER_ID}.{SECRETS[3]}", SECRETS[4]]},
        ],
        sockets={SECRETS[4]: "socket://x", "other": f"socket://{SECRETS[2]}"},
    )
    document["metadata"]["description"] = f"key {SECRETS[1]}"
    problems = validate_pipeline(Pipeline.model_validate(document))
    assert len(problems) >= 6
    shown = messages(problems)
    assert [secret for secret in SECRETS if secret in shown] == []
