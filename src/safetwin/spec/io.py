"""Read pipeline files from YAML and write them back."""

import re
from collections.abc import Hashable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError
from pydantic_core import ErrorDetails
from yaml.composer import ComposerError

from .models import Pipeline
from .validate import REDACTED, Problem, redacted

_BOOL = "tag:yaml.org,2002:bool"
_INT = "tag:yaml.org,2002:int"
_FLOAT = "tag:yaml.org,2002:float"
_TIMESTAMP = "tag:yaml.org,2002:timestamp"
# The keys `<<` and `=` are not values: PyYAML takes them out before it builds a mapping.
_SPECIAL_KEYS = ("tag:yaml.org,2002:merge", "tag:yaml.org,2002:value")

# Plain scalars a pipeline file reads as something other than a string: YAML 1.2 booleans and plain decimal
# numbers (no `1_000`, `12:30`, `0755` or `0x1f`). Each is (tag, pattern, first characters).
_SCALARS = (
    (_BOOL, r"^(?:true|True|TRUE|false|False|FALSE)$", "tTfF"),
    (_INT, r"^[-+]?(?:0|[1-9][0-9]*)$", "-+0123456789"),
    (
        _FLOAT,
        r"^(?:[-+]?(?:0|[1-9][0-9]*)\.[0-9]*(?:[eE][-+]?[0-9]+)?|[-+]?\.[0-9]+(?:[eE][-+]?[0-9]+)?"
        r"|[-+]?(?:0|[1-9][0-9]*)[eE][-+]?[0-9]+|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
        "-+0123456789.",
    ),
)


class _DuplicateKey(ComposerError):
    """A key used twice. Its message is ours: it names the key (a name, as locations do), redacted if it looks
    like a secret."""


class _Loader(yaml.SafeLoader):
    """SafeLoader that reads a pipeline file the way the spec means it.

    - Scalars follow YAML 1.2 (see `_SCALARS`) and dates stay strings, so a key such as `on:` is a string,
      not `True`, and a pipeline holds nothing but JSON values.
    - Aliases (`*name`) are refused. A recursive alias would loop forever and nested ones can expand into
      gigabytes; a pipeline file has no use for them.
    - A key used twice in one mapping is an error. YAML would keep the last one and drop the other without
      a word, so a pasted second `socket:` or `path:` would quietly win.
    """

    def compose_node(self, parent: yaml.Node | None, index: int) -> yaml.Node | None:
        if self.check_event(yaml.AliasEvent):
            mark = self.peek_event().start_mark  # type: ignore[no-untyped-call]
            raise ComposerError(
                None, None, "aliases (*name) are not allowed in a pipeline file: write the value out", mark
            )
        return super().compose_node(parent, index)

    def compose_mapping_node(self, anchor: Any) -> yaml.MappingNode:  # the stubs type the anchor wrongly
        node = super().compose_mapping_node(anchor)
        first_seen: dict[Hashable, yaml.Mark] = {}
        for key_node, _ in node.value:
            if key_node.tag in _SPECIAL_KEYS:
                continue
            key = self.construct_object(key_node, deep=True)  # the value the key will have in the dict
            if not isinstance(key, Hashable):
                continue  # the constructor reports an unhashable key
            if key in first_seen:
                first = first_seen[key].line + 1
                problem = f"found duplicate key '{redacted(str(key))}' (first used on line {first})"
                raise _DuplicateKey(None, None, problem, key_node.start_mark)
            first_seen[key] = key_node.start_mark
        return node


def _with_scalars(resolvers: dict[Any, Any]) -> dict[Any, Any]:
    """A copy of a class's implicit resolvers, without the YAML 1.1 ones that `_SCALARS` replaces."""
    replaced = {_BOOL, _INT, _FLOAT, _TIMESTAMP}
    return {
        first: [(tag, regexp) for tag, regexp in rules if tag not in replaced]
        for first, rules in resolvers.items()
    }


_Loader.yaml_implicit_resolvers = _with_scalars(yaml.SafeLoader.yaml_implicit_resolvers)
for _tag, _pattern, _first in _SCALARS:
    _Loader.add_implicit_resolver(_tag, re.compile(_pattern), list(_first))


class _Dumper(yaml.SafeDumper):
    """SafeDumper that lays a pipeline out the way it is written by hand: indented lists, SQL as a block.

    It keeps the YAML 1.1 rules and adds the number patterns of `_SCALARS`, so any string that some reader
    would take for a boolean, a date or a number gets quoted.
    """

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        super().increase_indent(flow=flow, indentless=False)


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|" if "\n" in data else None)


_Dumper.add_representer(str, _represent_str)
for _tag, _pattern, _first in _SCALARS:
    _Dumper.add_implicit_resolver(_tag, re.compile(_pattern), list(_first))


class SpecError(Exception):
    """A pipeline file that can't be loaded: broken YAML, or not matching the spec."""

    def __init__(self, problems: list[Problem]) -> None:
        self.problems = problems
        super().__init__("; ".join(f"[{p.code}] {p.message}" for p in problems))


def load_pipeline_file(path: Path) -> Pipeline:
    """Load a pipeline from a YAML file.

    Raises `SpecError` if the file isn't a valid pipeline, and `OSError` if it can't be read.
    """
    return _load(path.read_bytes())


def load_pipeline_text(text: str) -> Pipeline:
    """Load a pipeline from YAML text (JSON works too). Raises `SpecError` if it isn't a valid pipeline."""
    return _load(text)


def dump_pipeline(p: Pipeline) -> str:
    """The pipeline as YAML: keys in the order of the models, and only what the file set (no defaults)."""
    text: str = yaml.dump(
        p.model_dump(exclude_unset=True),
        Dumper=_Dumper,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=10_000,  # never fold long lines: diffs stay one line per value
    )
    return text


def _load(source: str | bytes) -> Pipeline:
    return load_model(source, Pipeline)


def load_model[M: BaseModel](source: str | bytes, model: type[M]) -> M:
    """Load YAML text with the safe loader of pipeline files (no aliases, no duplicate keys, YAML 1.2 scalars)
    and validate it as `model`. Raises `SpecError` whose messages never repeat a value of the file. Masking
    policies are loaded this way too (`policy.py`)."""
    try:
        raw = yaml.load(source, Loader=_Loader)  # a SafeLoader subclass
    except yaml.YAMLError as err:
        raise SpecError([_yaml_problem(err)]) from err
    except RecursionError as err:  # YAML nested a few hundred levels deep
        raise SpecError([_too_deep()]) from err
    try:
        return model.model_validate(raw)
    except ValidationError as err:
        raise SpecError(_schema_problems(err, raw)) from err
    except RecursionError as err:
        raise SpecError([_too_deep()]) from err


def _too_deep() -> Problem:
    return Problem("error", "too_deep", "the file is nested too deeply")


# Text that PyYAML puts in quotes: a tag, an anchor, a character, a kind of token. A single character (or its
# escape, such as '\t' or '\x00') and PyYAML's own names in angle brackets ('<stream end>', '<scalar>') are
# hints about the syntax and are kept; anything else is text of the file.
_QUOTED = re.compile(r"'([^'\n]*)'|\"([^\"\n]*)\"")
_ONE_CHARACTER = re.compile(
    r".|\\(?:[0abtnvfre\\'\" ]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})", re.DOTALL
)


_TOKEN_NAME = re.compile(r"<[a-z ]+>")


def _without_quoted_text(message: str) -> str:
    """`message` with every quoted text longer than one character replaced by `<redacted>`."""

    def replace(match: re.Match[str]) -> str:
        quoted = match[1] if match[1] is not None else match[2]
        if _ONE_CHARACTER.fullmatch(quoted) or _TOKEN_NAME.fullmatch(quoted):
            return match[0]
        quote = match[0][0]
        return f"{quote}{REDACTED}{quote}"

    return _QUOTED.sub(replace, message)


def _yaml_problem(err: yaml.YAMLError) -> Problem:
    """The problem for a YAML error: where it is and what PyYAML says, without the text of the file that it
    quotes (a tag or an anchor name: `could not determine a constructor for the tag '<redacted>'`)."""
    if isinstance(err, yaml.MarkedYAMLError) and err.problem_mark is not None:
        mark = err.problem_mark
        what = ", ".join(part for part in (err.context, err.problem) if part)
        if not isinstance(err, _DuplicateKey):
            what = _without_quoted_text(what)
        return Problem(
            "error", "yaml_error", f"line {mark.line + 1}, column {mark.column + 1}: {redacted(what)}"
        )
    return Problem("error", "yaml_error", redacted(_without_quoted_text(str(err))))


def _schema_problems(err: ValidationError, raw: Any) -> list[Problem]:
    return [
        Problem("error", e["type"], f"{_location(e['loc'], raw)}: {_message(e)}")
        for e in err.errors(include_url=False)
    ]


def _message(error: ErrorDetails) -> str:
    """The error's message, without "Value error, " and without any value of the file that it quotes.

    Pydantic's messages name what was expected, not what was found. Some kinds of error can quote what was
    found (the tag of a discriminated union: "Input tag 'x' found using 'type' ..."), so a tag, and the input
    wherever a message quotes it, are always replaced by `<redacted>`: neither `safetwin validate` nor the
    engine repeats a value. What is left of a secret-looking value elsewhere in the message is redacted as
    before.
    """
    message = error["msg"].removeprefix("Value error, ")
    for value in ((error.get("ctx") or {}).get("tag"), error.get("input")):
        if isinstance(value, str) and value and f"'{value}'" in message:
            message = message.replace(f"'{value}'", f"'{REDACTED}'")
    for value in ((error.get("ctx") or {}).get("tag"), error.get("input")):
        if isinstance(value, str) and value in message:
            message = message.replace(value, redacted(value))
    return message


def _location(loc: tuple[int | str, ...], raw: Any) -> str:
    """`spec.nodes[read].config`: where in the file an error is. Nodes are named by id when possible."""
    text = ""
    for depth, part in enumerate(loc):
        if isinstance(part, int):
            label = _node_id(raw, part) if loc[:depth] == ("spec", "nodes") else None
            text += f"[{redacted(label) if label else part}]"
        else:
            text += f".{redacted(part)}" if text else redacted(part)
    return text or "(top level)"


def _node_id(raw: Any, index: int) -> str | None:
    try:
        node_id = raw["spec"]["nodes"][index]["id"]
    except (KeyError, IndexError, TypeError):
        return None
    return node_id if isinstance(node_id, str) else None
