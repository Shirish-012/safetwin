"""Checks a loaded pipeline: the rules a pipeline must follow before any of it runs.

Implemented here: duplicate ids and unknown operators, references (an input names a node and one of its
output ports), cycles, sources without inputs and steps with them, sockets, and inline secrets.

Messages never repeat a value that looks like a secret: user text goes through `redacted` first
(docs/security.md).

Column references are not checked here: they need the upstream schema, which only the run knows (a step that
names a column that is not there fails when its stage is planned, before any data moves).
"""

import math
import re
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Literal

from .catalog import BUILTIN, Catalog
from .models import SOCKET_URI_PATTERN, Node, Pipeline

Severity = Literal["error", "warning"]
REDACTED = "<redacted>"


@dataclass(frozen=True)
class Problem:
    """One problem found in a pipeline.

    `node_id` says which node it is about, when it is about one. It is the node's real id, for tools that
    point at the node; a program that prints it should pass it through `redacted` first, as the CLI does.
    """

    severity: Severity
    code: str
    message: str
    node_id: str | None = None


def _error(code: str, message: str, node_id: str | None = None) -> Problem:
    return Problem("error", code, message, node_id)


def validate_pipeline(p: Pipeline, catalog: Catalog = BUILTIN) -> list[Problem]:
    """Every problem in `p`. An empty list means the pipeline is valid."""
    checks: tuple[Callable[[Pipeline, Catalog], Iterator[Problem]], ...] = (
        _check_nodes,
        _check_references,
        _check_cycles,
        _check_ports,
        _check_sockets,
        _check_secrets,
    )
    problems: list[Problem] = []
    for check in checks:
        try:
            problems.extend(check(p, catalog))
        except RecursionError:  # a config nested about a thousand levels deep
            problems.append(_error("too_deep", "the pipeline is nested too deeply to check"))
    return problems


def redacted(value: str) -> str:
    """`value` as it may appear in a message: itself, or `<redacted>` when it looks like a secret."""
    return REDACTED if _secret_kind(value) else value


def _q(value: str) -> str:
    """`value` in quotes for a message, redacted when it looks like a secret."""
    return f"'{redacted(value)}'"


def _by_id(p: Pipeline) -> dict[str, Node]:
    """Nodes by id. If an id is repeated the first node wins; `duplicate_id` reports the rest."""
    nodes: dict[str, Node] = {}
    for node in p.spec.nodes:
        nodes.setdefault(node.id, node)
    return nodes


def _split(ref: str) -> tuple[str, str]:
    """`node` or `node.port` to (node, port). The default port is `out`."""
    node, dot, port = ref.partition(".")
    return node, port if dot else "out"


def _check_nodes(p: Pipeline, catalog: Catalog) -> Iterator[Problem]:
    for node_id, count in Counter(node.id for node in p.spec.nodes).items():
        if count > 1:
            yield _error(
                "duplicate_id", f"node id {_q(node_id)} is used {count} times; ids must be unique", node_id
            )
    for node in p.spec.nodes:
        if node.operator not in catalog:
            yield _error(
                "unknown_operator",
                f"{_q(node.id)} uses {_q(node.operator)}, which is not a known operator",
                node.id,
            )


def _check_references(p: Pipeline, catalog: Catalog) -> Iterator[Problem]:
    nodes = _by_id(p)
    for node in p.spec.nodes:
        for ref in node.inputs:
            target_id, port = _split(ref)
            if target_id == node.id:
                yield _error("self_reference", f"{_q(node.id)} lists itself in inputs", node.id)
            elif target_id not in nodes:
                yield _error(
                    "unknown_reference",
                    f"{_q(node.id)} lists {_q(ref)} in inputs, but no node has that id",
                    node.id,
                )
            else:
                op = catalog.get(nodes[target_id].operator)
                if op is not None and port not in op.outputs:
                    ports = ", ".join(op.outputs) or "none"
                    yield _error(
                        "unknown_reference",
                        f"{_q(node.id)} reads {_q(ref)}, but {_q(target_id)} ({op.id}) has no output port "
                        f"{_q(port)} (output ports: {ports})",
                        node.id,
                    )


def _check_cycles(p: Pipeline, catalog: Catalog) -> Iterator[Problem]:
    nodes = _by_id(p)
    downstream: dict[str, list[str]] = {node_id: [] for node_id in nodes}  # edges run upstream to downstream
    for node in nodes.values():
        for ref in (_split(ref)[0] for ref in node.inputs):
            if ref in nodes and ref != node.id:
                downstream[ref].append(node.id)
    for cycle in _find_cycles(downstream):
        path = " → ".join(redacted(node_id) for node_id in cycle)
        yield _error("cycle", f"steps form a loop: {path}. Remove one of these connections", cycle[0])


def _find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """Cycles of a directed graph, each as a path that starts and ends on the same node."""
    cycles: list[list[str]] = []
    reported: set[frozenset[str]] = set()
    done: set[str] = set()
    for start in graph:
        if start in done:
            continue
        path = [start]  # the walk from `start`, iterative so long chains can't hit the recursion limit
        on_path = {start}
        pending = [iter(graph[start])]
        while pending:
            for node in pending[-1]:
                if node in on_path:
                    cycle = [*path[path.index(node) :], node]
                    if frozenset(cycle) not in reported:
                        reported.add(frozenset(cycle))
                        cycles.append(cycle)
                elif node not in done:
                    path.append(node)
                    on_path.add(node)
                    pending.append(iter(graph[node]))
                    break
            else:
                finished = path.pop()
                on_path.remove(finished)
                done.add(finished)
                pending.pop()
    return cycles


def _check_ports(p: Pipeline, catalog: Catalog) -> Iterator[Problem]:
    for node in p.spec.nodes:
        op = catalog.get(node.operator)
        if op is None:
            continue
        if node.inputs and op.category == "source":
            yield _error(
                "source_has_inputs",
                f"{_q(node.id)} is a source ({op.id}), so it can't take inputs: sources start the data flow",
                node.id,
            )
        elif not node.inputs and op.inputs:
            yield _error(
                "missing_input",
                f"{_q(node.id)} ({op.id}) needs data: list the step that feeds it in inputs",
                node.id,
            )


def _check_sockets(p: Pipeline, catalog: Catalog) -> Iterator[Problem]:
    for node in p.spec.nodes:
        op = catalog.get(node.operator)
        if op is None or not op.needs_socket:
            continue
        if node.socket is None:
            yield _error(
                "missing_socket",
                f"{_q(node.id)} ({op.id}) needs a socket: set socket to a spec.sockets alias or a URI",
                node.id,
            )
        elif not _is_socket(p, node.socket):
            yield _unknown_socket(p, _q(node.id), node.socket, node.id)


def _is_socket(p: Pipeline, reference: str) -> bool:
    """Whether `reference` is an alias defined in spec.sockets or a socket:// URI."""
    return reference in p.spec.sockets or re.fullmatch(SOCKET_URI_PATTERN, reference) is not None


def _unknown_socket(p: Pipeline, subject: str, reference: str, node_id: str | None) -> Problem:
    known = ", ".join(redacted(alias) for alias in p.spec.sockets) or "none defined"
    return _error(
        "unknown_socket_alias",
        f"{subject} uses socket {_q(reference)}, which is neither a socket:// URI "
        f"nor an alias in spec.sockets (aliases: {known})",
        node_id,
    )


# Values that point at a secret instead of containing one.
_REFERENCE_PREFIXES = ("secret://", "keychain://", "socket://")

_NOT_AFTER_ALNUM = r"(?<![A-Za-z0-9])"
_KNOWN_SECRETS = (
    ("an AWS access key ID", re.compile(_NOT_AFTER_ALNUM + r"(?:AKIA|ASIA)[A-Z0-9]{16}")),
    (
        "a GitHub token",
        re.compile(_NOT_AFTER_ALNUM + r"(?:gh[po]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,})"),
    ),
    ("a Slack token", re.compile(_NOT_AFTER_ALNUM + r"xox[abprs]-[A-Za-z0-9-]{8,}")),
    ("an API key (sk-...)", re.compile(_NOT_AFTER_ALNUM + r"sk-[A-Za-z0-9_-]{20,}")),
    ("a Google API key", re.compile(_NOT_AFTER_ALNUM + r"AIza[A-Za-z0-9_-]{35}")),
    ("a Google OAuth token", re.compile(_NOT_AFTER_ALNUM + r"ya29\.[A-Za-z0-9_-]{8,}")),
    ("a private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
)

# A token is a run of 20 or more characters that base64, base64url, base32 and hex are written in. Anything
# else ends a run (whitespace, : , @ ? & { } . quotes, brackets), so `Bearer <token>`, a token inside a URL or
# SQL are found, while prose falls apart into runs too short to score. `/`, `=`, `+`, `_` and `-` belong to
# base64 and base64url, so they stay inside a run; a run is scored whole, and again piece by piece where those
# characters cut it (`api_key=<token>`, `prefix_<token>`), because a token can also be glued to a word.
_TOKEN_RUN = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_CUTS = re.compile(r"[/=_-]")
_UUID = re.compile(r"(?<![A-Za-z0-9])[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}(?![A-Za-z0-9])")
_HEX = re.compile(r"[0-9a-fA-F]+")
# Words, acronyms and numbers: SafeTwin is Safe + Twin, and HTTP or 2026 count once.
_WORDS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+|[0-9]+")
_CONSONANTS = re.compile(r"[b-df-hj-np-tv-xzB-DF-HJ-NP-TV-XZ]{6,}")  # y is left out: "encrypted" is fine


def _entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    return -sum(n / len(text) * math.log2(n / len(text)) for n in Counter(text).values())


def _mean_word_length(text: str) -> float:
    """Average length of the words, acronyms and numbers in `text`.

    Each counts for 6 at most, so one long word (the `EXAMPLEKEY` at the end of AWS's sample secret key)
    cannot hide the random characters around it.
    """
    words = _WORDS.findall(text)
    return sum(min(len(word), 6) for word in words) / len(words) if words else 0.0


def _is_random_run(run: str) -> bool:
    """Whether a run of token characters looks machine-generated rather than written by a person.

    Random tokens give themselves away in different ways, so each family has its own test:
    - Hex keys use only 16 symbols, so their entropy cannot pass 4.0 bits per character; random ones land
      near 3.7. From 32 characters, 3.0 bits is enough.
    - Mixed-case tokens (base64, base62) switch between lower case, upper case and digits about every other
      character. Words, paths and names stay in one kind for a whole word (3 or more characters on average).
    - Single-case tokens (base32, base36) have digits mixed in among the letters: three or more switches
      between a digit and a letter. Names like `sha256_checksum` have one or two.
    - Letters only: hardly any vowels, or a run of six consonants inside a word.
    Everything but hex also needs 3.0 bits per character, at most half digits (40% for the mixed-case test),
    which leaves out dates and numeric ids, and fewer than one `/` in ten characters (base64 has one in 64,
    a path many more). A dataset path such as `SafeTwin/shop/orders/dt={yyyy}-...` scores 4.3 bits, so
    entropy alone cannot be the test.
    """
    entropy = _entropy(run)
    if _HEX.fullmatch(run):
        return len(run) >= 32 and entropy >= 3.0 and not run.isdigit()
    digit_share = sum(c.isdigit() for c in run) / len(run)
    if entropy < 3.0 or digit_share > 0.5 or run.count("/") * 10 >= len(run):
        return False
    if _mean_word_length(run) < 2.75 and digit_share <= 0.4:
        return True
    if run.isalnum() and sum(a.isdigit() != b.isdigit() for a, b in pairwise(run)) >= 3:
        return True
    if not run.isalpha():
        return False
    vowels = sum(c in "aeiouAEIOU" for c in run)
    return vowels / len(run) < 0.25 or any(_CONSONANTS.search(word) for word in _WORDS.findall(run))


def _looks_random(value: str) -> bool:
    """Whether a token-like run in `value`, or a long piece of one, looks random. UUIDs are not secrets."""
    for run in _TOKEN_RUN.findall(_UUID.sub(" ", value)):
        candidates = {run, *(piece for piece in _CUTS.split(run) if len(piece) >= 20)}
        if any(_is_random_run(candidate) for candidate in candidates):
            return True
    return False


# Config keys whose values are digests or revisions: long and random-looking, but public.
_DIGEST_KEYS = frozenset(
    {"checksum", "sha256", "sha1", "md5", "hash", "digest", "etag", "commit", "revision", "rev", "git_sha"}
)
# A value that says what it is: `sha256:` and exactly 64 hex characters, `sha1:` and 40, `md5:` and 32. Only
# the whole value counts: a prefix in front of anything else (`sha256:<a token>`) hides nothing.
_DIGEST_VALUE = re.compile(r"sha256:[0-9a-f]{64}|sha1:[0-9a-f]{40}|md5:[0-9a-f]{32}", re.IGNORECASE)


def _secret_kind(value: str, *, digest: bool = False, references: bool = True) -> str | None:
    """What kind of secret `value` looks like, or None.

    `digest` says the value sits under a key such as `checksum` or `commit`. A digest, and a value that is
    exactly `sha256:` and 64 hex characters (`sha1:` and 40, `md5:` and 32), is exempt from the random-looking
    test, which would flag every hash. It still counts when it has the exact shape of a known credential,
    such as an AWS key ID. With `references` false, a value that starts with a reference (`secret://...`) is
    tested like any other (for free text, where a reference can be followed by anything).
    """
    if references and value.startswith(_REFERENCE_PREFIXES):
        return None
    for kind, pattern in _KNOWN_SECRETS:
        if pattern.search(value):
            return kind
    if digest or _DIGEST_VALUE.fullmatch(value):
        return None
    return "a random-looking token" if _looks_random(value) else None


def _strings(value: object, path: str, key: str = "") -> Iterator[tuple[str, str, str]]:
    """Every string inside `value` as (path, closest key above it, string).

    The path reads like `spec.nodes[read].config.token`. The key is the last name before the string, so
    the items of a list belong to the key of the list, and `""` means there is none.
    """
    if isinstance(value, str):
        yield path, key, value
    elif isinstance(value, dict):
        for name, item in value.items():
            yield from _strings(item, f"{path}.{redacted(str(name))}", str(name))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}[{index}]", key)


def find_secrets(value: object, path: str) -> Iterator[tuple[str, str]]:
    """Where a string inside `value` looks like a secret, as (where, kind).

    `where` is `path` and the way down to the string, like `spec.nodes[read].config.token`; a name that
    looks like a secret is redacted in it, so it is safe to show. Only strings that are values are looked at:
    the keys of a mapping are not. `kind` says what it looks like, such as "a GitHub token".
    """
    for where, key, text in _strings(value, path):
        if (kind := _secret_kind(text, digest=key.lower() in _DIGEST_KEYS)) is not None:
            yield where, kind


def text_secrets(text: str) -> Iterator[tuple[int, str]]:
    """Each line of free text (a pipeline file with its comments and keys) that looks like it holds a secret,
    as (line number, kind). Every line is tested whole, and a line that starts with a reference is not exempt.

    It finds what has a known shape or looks random. A plain password (a dictionary word with a digit, say)
    inside a URL or a comment looks like nothing in particular and may not be found.
    """
    for number, line in enumerate(text.splitlines(), start=1):
        if (kind := _secret_kind(line.strip(), references=False)) is not None:
            yield number, kind


def _check_secrets(p: Pipeline, catalog: Catalog) -> Iterator[Problem]:
    scopes: list[tuple[str | None, str, dict[str, Any]]] = [
        (None, "metadata", p.metadata.model_dump(exclude_unset=True)),
        (None, "spec", p.spec.model_dump(exclude_unset=True, exclude={"nodes"})),
        *((n.id, f"spec.nodes[{redacted(n.id)}]", n.model_dump(exclude_unset=True)) for n in p.spec.nodes),
    ]
    for node_id, path, data in scopes:
        for where, kind in find_secrets(data, path):
            yield _error(
                "inline_secret",
                f"{where} looks like a secret ({kind}). Don't put secrets in the pipeline file: "
                "keep it in the keychain and refer to it as secret://<name>",
                node_id,
            )
