"""The allow-list for filter and derive expressions: what it lets through and what it refuses.

The letters that look like ASCII ones are written as escapes: \\u017f (long s), \\u0131 (dotless i),
\\u212a (Kelvin sign), \\uff33 and its neighbours (full-width), \\u03b1 (Greek alpha), \\u0410 (Cyrillic A).
"""

import os
import threading
import unicodedata
from collections.abc import Iterator
from contextlib import suppress
from datetime import date, datetime
from pathlib import Path
from typing import Any

import polars as pl
import pytest

from safetwin.dataplane.expressions import (
    FUNCTIONS,
    KEYWORDS,
    QUERY_WORDS,
    TIME_TYPES,
    TYPES,
    check_expression,
)
from safetwin.dataplane.operators import ConfigError, build_transform
from safetwin.spec.models import Node


def refusal(text: str) -> str:
    """Why `text` is refused. Fails if it is not."""
    with pytest.raises(ValueError, match=r"\S") as refused:
        check_expression(text)
    return str(refused.value)


def derive(expr: str) -> Any:
    """The `transform.derive` step for `expr`, built the way a pipeline builds it."""
    node = Node.model_validate(
        {"id": "step", "operator": "transform.derive", "inputs": ["x"], "config": {"name": "r", "expr": expr}}
    )
    return build_transform(node)


def words(text: str) -> set[str]:
    return set(text.split())


# --- the lists ----------------------------------------------------------------------------------------------


def test_the_lists_are_the_ones_that_were_decided() -> None:
    keywords = "and or not is null true false in between like ilike case when then else end cast try_cast"
    types = "int integer bigint smallint float double real decimal numeric varchar text string boolean bool"
    functions = (
        "upper lower trim ltrim rtrim length char_length coalesce nullif abs round floor ceil ceiling concat "
        "substr substring left right replace starts_with ends_with strftime"
    )
    assert words(keywords + " as distinct") == KEYWORDS
    assert words(types) == TYPES
    assert words(functions) == FUNCTIONS
    assert words("select with values table from") == QUERY_WORDS
    assert words("date time timestamp datetime") == TIME_TYPES
    assert not QUERY_WORDS & (KEYWORDS | TYPES | FUNCTIONS)  # nothing is allowed and a query word at once
    assert not TIME_TYPES & (
        KEYWORDS | TYPES | FUNCTIONS
    )  # and none of the ways to a date is a type or a function


# --- letters that only look like ASCII ----------------------------------------------------------------------

LOOKALIKES = {
    "a long s for the S of SELECT": "id IN (\u017felect id from t)",
    "a long s on its own": "\u017felect",
    "a dotless i for the I of IN": "id \u0131n ('1')",
    "a dotless i for the I of IS": "id \u0131s null",
    "the Kelvin sign for a K": "\u212aey = 1",
    "full-width letters": "\uff33\uff25\uff2c\uff25\uff23\uff34 1",
    "a full-width letter among ASCII ones": "id IN (SEL\uff25CT 1)",
    "an accented letter in a name": "caf\u00e9 = 1",
    "an accented letter in a keyword": "id IS N\u00dcLL",
    "a Greek letter in a name": "\u03b1 > 1",
    "a Cyrillic letter in a keyword": "a AND b \u0410ND c",
    "a non-ASCII digit": "a = \u0663",
    "a no-break space": "a\u00a0IS NULL",
    "an ideographic space": "a\u3000IS NULL",
    "a zero-width space inside a word": "SEL\u200bECT 1",
    "a zero-width joiner in a function": "upper\u200d(a)",
    "a vertical tab": "a\x0bIS NULL",
    "a form feed": "a\x0cIS NULL",
    "a NUL": "a\x00",
}


@pytest.mark.parametrize("text", LOOKALIKES.values(), ids=LOOKALIKES.keys())
def test_a_letter_that_is_not_ascii_is_refused_outside_quotes(text: str) -> None:
    assert "can't contain" in refusal(text)


def test_these_really_are_lookalikes_for_another_tokenizer() -> None:
    # Python's own case mapping turns them into the ASCII letters of a keyword. So might the tokenizer of
    # Polars, which is why no word that is not ASCII is let through, not even by a list that refuses SELECT.
    assert "\u017felect".upper() == "SELECT"
    assert "\u0131s".upper() == "IS"
    assert "\u0131n".upper() == "IN"
    assert "\u212a".casefold() == "k"


def lookalikes() -> list[str]:
    """Every non-ASCII character, up to the end of plane 1, that a case mapping or a Unicode normalization
    (NFC, NFD, NFKC, NFKD) turns into ASCII letters or digits: what another tokenizer may take for them."""
    found = []
    for code in range(
        0x80, 0x20000
    ):  # the planes above hold ideographs, tags and private use: no such mapping
        char = chr(code)
        forms = {char.upper(), char.lower(), char.casefold(), char.title()}
        forms |= {unicodedata.normalize(form, char) for form in ("NFC", "NFD", "NFKC", "NFKD")}
        if any(form.isascii() and form.isalnum() for form in forms):
            found.append(char)
    return found


def test_no_character_that_maps_to_an_ascii_letter_or_digit_gets_through_outside_quotes() -> None:
    found = lookalikes()
    assert len(found) > 1000  # not an empty check: full-width forms, mathematical letters, Kelvin, long s ...
    assert {"\u017f", "\u0131", "\u212a", "\uff33", "\U0001d400"} <= set(found)
    for char in found:
        for text in (char, f"a{char}", f"{char}a", f"a {char}b = 1", f"upper{char}(a)"):
            assert "can't contain" in refusal(text), ascii(text)
        check_expression(f"a = '{char}' AND \"{char}\" IS NULL")  # inside quotes it is text, like any other


def test_the_message_names_the_character_and_says_what_is_allowed() -> None:
    message = refusal("id \u0131s null")
    assert "'\u0131'" in message
    assert "= <> != < <= > >= + - * / % || ( ) ," in message
    assert "'single quotes'" in message


# --- a word glued to a quote --------------------------------------------------------------------------------

GLUED = {
    "E'...'": "a = E'x'",
    "e'...'": "a = e'x'",
    "X'...'": "a = X'ab'",
    "N'...'": "a = N'x'",
    "B'...'": "a = B'101'",
    "any other word": "a = abc'def'",
    "a keyword": "a LIKE'x%'",
    "a type": "a = DATE'2026-01-01'",
    "a number": "a = 1'x'",
    "a word and a quoted name": 'a = x"y"',
    "a string and a quoted name": "a = 'x'\"y\"",
    "a quoted name and a string": "a = \"x\"'y'",
}


@pytest.mark.parametrize("text", GLUED.values(), ids=GLUED.keys())
def test_a_word_glued_to_a_quote_is_refused(text: str) -> None:
    assert "quote glued to" in refusal(text)


@pytest.mark.parametrize(
    "text", ["a = 'it''s'", 'a = "say ""hi"""', "a = ''", "a = ''''", "a = 'x' || 'y'", "a = 'x'AND b"]
)
def test_quotes_that_belong_together_are_fine(text: str) -> None:
    check_expression(text)


# --- backslashes --------------------------------------------------------------------------------------------

BACKSLASHES = {
    "in a string": r"a = 'C:\temp'",
    "before the closing quote of a string": r"a = '\'",
    "as an escaped quote": r"a = 'it\'s'",
    "twice": r"a = '\\'",
    "at the start of a string": r"a = '\n'",
    "in a string, before what could be a query": r"a = '\' OR id IN (SELECT 1) OR b = '\'",
    "in a quoted name": r'"a\b" IS NULL',
    "before the closing quote of a quoted name": r'"\" IS NULL',
}


@pytest.mark.parametrize("text", BACKSLASHES.values(), ids=BACKSLASHES.keys())
def test_a_backslash_in_a_string_or_a_quoted_name_is_refused(text: str) -> None:
    message = refusal(text)
    assert "can't contain a backslash in a" in message
    assert "write a quote as ''" in message


def test_a_backslash_is_refused_outside_quotes_too() -> None:
    assert "can't contain " + repr("\\") in refusal(r"a \ b")


@pytest.mark.parametrize("text", ["a = 'C:/temp'", "a = 'it''s'", 'a = "say ""hi"""', "a = '\u00e9'"])
def test_a_string_without_a_backslash_is_fine(text: str) -> None:
    check_expression(text)


# --- dots ---------------------------------------------------------------------------------------------------

DOTS = {
    "a qualified name": "t.a = 1",
    "a dot before a quoted name": 't."a" = 1',
    "a dot after a quoted name": '"t".a = 1',
    "a dot after a number": "1.2.3 = a",
    "a dot on its own": "a . b",
    "a dot after a string": "'x'.y",
    "a dot at the start of a name": ".a = 1",
    "a dot at the end": "a.",
}


@pytest.mark.parametrize("text", DOTS.values(), ids=DOTS.keys())
def test_a_dot_outside_a_number_is_refused(text: str) -> None:
    assert "'.'" in refusal(text)


@pytest.mark.parametrize("number", ["1", "1.5", ".5", "5.", "1e5", "1E-3", "2.5e+10", ".5e3", "007", "1.e2"])
def test_numbers(number: str) -> None:
    check_expression(f"a = {number}")
    check_expression(f"a={number}+{number}")


@pytest.mark.parametrize("text", ["a = 1abc", "a = 1e", "a = 1_000", "a = 0x1F", "a = 1e5x", "a = 5e+"])
def test_a_number_with_letters_glued_to_it_is_refused(text: str) -> None:
    assert "glued to the end of a number" in refusal(text)


# --- functions ----------------------------------------------------------------------------------------------

NOT_ALLOWED = [
    "read_csv('/etc/hosts')",
    "read_parquet('x')",
    "READ_CSV ('x')",
    "exists(1)",
    "a IN (read_csv('x'))",
    "a = any(b)",
    "sum(a)",
    "count(*)",
    "avg(a)",
    "max(a) > 1",
    "row_number()",
    "a OVER (b)",
    "unnest(a)",
    "random()",
    "now()",
    "columns('^a$')",
    "upper(a) = lower(read_csv('x'))",
    "json_extract(a, 'x')",
    "date_trunc('month', t)",  # Polars has no such function (yet), and so it is not on the list
]


@pytest.mark.parametrize("text", NOT_ALLOWED)
def test_a_function_that_is_not_on_the_list_is_refused(text: str) -> None:
    message = refusal(text)
    assert "is not allowed in an expression" in message
    assert "function '" in message


def test_the_message_about_a_function_names_it_as_typed_and_lists_the_ones_that_are_allowed() -> None:
    message = refusal("Read_CSV ('x')")
    assert message.startswith(
        "function 'Read_CSV' is not allowed in an expression (the functions that are: abs, "
    )
    assert message.endswith("upper)")
    assert all(name in message for name in FUNCTIONS)


def test_a_name_that_is_not_called_is_a_column_even_if_a_function_has_that_name() -> None:
    check_expression("sum > 1 AND read_csv IS NULL AND count = 2")  # columns of these names, no brackets


# A quoted name before a bracket is a function call to Polars, so it would get past the list of functions.
QUOTED_CALLS = {
    "a function that is not allowed": "\"read_csv\"('x') IS NULL",
    "an aggregate": '"sum"(x) > 1',
    "a function that turns text into a date": '"date"(d) IS NULL',
    "a function that is on the list": "\"upper\"(a) = 'X'",  # a function is a plain word, even this one
    "a space before the bracket": '"date" (d)',
    "a line break and a tab before the bracket": '"date"\n\t(d)',
    "a quoted name in the brackets": '"upper"("a")',
    "among other things": 'a = 1 AND "sum"(x) > 2 OR b IS NULL',
    "a name with quotes in it": '"say ""hi"""(a)',
}


@pytest.mark.parametrize("text", QUOTED_CALLS.values(), ids=QUOTED_CALLS.keys())
def test_a_function_called_by_a_quoted_name_is_refused(text: str) -> None:
    message = refusal(text)
    assert "can't call a function by a quoted name" in message
    assert "as a plain word" in message
    assert "the functions that are allowed:" in message
    assert all(name in message for name in FUNCTIONS)


def test_polars_really_does_call_a_function_by_a_quoted_name() -> None:
    # This is why they are refused: `"date"(d)` turns text into a date (and so it would get past the refusal
    # of date(), which looks at words) and `"sum"(x)` looks at all the rows.
    frame = pl.LazyFrame({"d": ["2026-01-05", None], "x": [1, 2]})
    assert frame.select(pl.sql_expr('"sum"(x)').alias("r")).collect()["r"].to_list() == [3]
    assert frame.select(pl.sql_expr('"date"(d)').alias("r")).collect()["r"].to_list() == [
        date(2026, 1, 5),
        None,
    ]


@pytest.mark.parametrize(
    "text",
    [
        '"a" IN ("b", "c")',  # the bracket follows the word IN
        '"a" = ("b")',
        "upper(\"a\") = 'X'",
        '"a" || upper("b") || "c"',
        'CASE WHEN "a" IS NULL THEN ("b") ELSE "c" END',
        'CAST("a" AS INT) > 1',
        '"a" BETWEEN ("b") AND ("c")',
        "(\"a\") = ('x')",
    ],
)
def test_a_quoted_name_in_brackets_or_before_a_bracket_that_is_not_a_call_is_fine(text: str) -> None:
    check_expression(text)


@pytest.mark.parametrize("fn", sorted(FUNCTIONS))
def test_every_function_on_the_list_is_let_through_however_it_is_written(fn: str) -> None:
    for text in (
        f"{fn}(a)",
        f"{fn.upper()}(a)",
        f"{fn.title()} (a, 'x')",
        f"{fn}\n\t(a)",
        f"x = {fn}(a)||'y'",
    ):
        check_expression(text)


# --- dates --------------------------------------------------------------------------------------------------

TEXT_TO_TIME = {
    "CAST to DATE": "CAST(a AS DATE)",
    "CAST in lower case": "cast(a as date)",
    "TRY_CAST to TIMESTAMP": "TRY_CAST(a AS TIMESTAMP)",
    "CAST to TIME": "CAST(a AS TIME)",
    "CAST to DATETIME": "CAST(a AS DATETIME)",
    "a precision": "CAST(a AS TIMESTAMP(3))",
    "mixed case and a line break": "CAST(a AS\n\tDate)",
    "among casts that are fine": "CAST(a AS INT) + 1 > 0 AND CAST(b AS DATE) IS NOT NULL",
    "the function date": "date(a) IS NULL",
    "the function time": "time (a)",
    "the function timestamp": "TIMESTAMP(a)",
    "the function datetime": "datetime(a)",
}


@pytest.mark.parametrize("text", TEXT_TO_TIME.values(), ids=TEXT_TO_TIME.keys())
def test_turning_text_into_dates_is_refused_and_the_message_says_what_to_use_instead(text: str) -> None:
    message = refusal(text)
    assert "can't convert to" in message
    assert "Use transform.parse_dates" in message


@pytest.mark.parametrize(
    "kind", ["INT", "integer", "BIGINT", "smallint", "FLOAT", "double", "REAL", "DECIMAL(10, 2)", "numeric"]
)
def test_casts_to_numbers_are_fine(kind: str) -> None:
    check_expression(f"CAST(a AS {kind}) > 1")
    check_expression(f"TRY_CAST(a AS {kind}) > 1")


@pytest.mark.parametrize("kind", ["VARCHAR", "varchar(10)", "TEXT", "string", "BOOLEAN", "bool"])
def test_casts_to_text_and_to_booleans_are_fine(kind: str) -> None:
    check_expression(f"CAST(a AS {kind}) = 'x'")
    check_expression(f"TRY_CAST(a AS {kind}) IS NULL")


def test_a_column_may_be_called_date_or_time_and_a_date_may_be_written_out() -> None:
    check_expression("date IS NOT NULL AND time > 5 AND timestamp = 'x' AND datetime IS NULL")
    check_expression('"date" IS NOT NULL')
    check_expression("date '2026-01-05' < t")  # a date written out is read as it is, from no column
    check_expression("strftime(t, '%Y') = '2026'")  # a date turned into text


# A quoted type after AS is a type to Polars too, so it would get past the refusal of CAST(x AS DATE).
QUOTED_TYPES = {
    "a date": 'CAST(d AS "date")',
    "in capitals": 'CAST(d AS "DATE")',
    "a timestamp with TRY_CAST": 'TRY_CAST(d AS "timestamp")',
    "in lower case": 'cast(d as "datetime")',
    "a type that would be fine as a word": 'CAST(a AS "int")',
    "a line break after AS": 'CAST(d AS\n"date")',
    "a tab and spaces": 'CAST(d AS \t "time")',
    "among other things": 'a = 1 AND CAST(d AS "date") IS NOT NULL',
}


@pytest.mark.parametrize("text", QUOTED_TYPES.values(), ids=QUOTED_TYPES.keys())
def test_a_quoted_name_after_as_is_refused(text: str) -> None:
    message = refusal(text)
    assert "can't have a quoted name after AS" in message
    assert "as a plain word, such as INT or VARCHAR" in message


def test_a_quoted_name_that_comes_after_something_else_than_as_is_a_column() -> None:
    check_expression('CAST("as" AS INT) > 1 AND "as" IS NOT NULL')  # a column called as, and not after AS
    check_expression('CAST("a" AS VARCHAR) = "date"')  # the name comes after =, not after AS
    check_expression('"date" = \'x\' AND CAST(d AS INT) = "date"')


def test_a_date_written_out_still_works_but_polars_says_it_is_going_away() -> None:
    # `date '2026-01-05'` is let through by check_expression (above) and Polars 1.x reads it, but Polars warns
    # that casting text to a date "will be removed in Polars 2.0". engine/pyproject.toml pins `polars<2`, and
    # this test is what makes the upgrade impossible to miss: when it fails (the warning is gone, or the
    # literal no longer works), the typed date literals in expressions.py need a new decision.
    with pytest.warns(DeprecationWarning, match="Casting from String to Date is deprecated"):
        result = derive("t >= date '2026-01-05'")(a_frame()).collect()
    assert result["r"].to_list() == [True, False, None]
    assert int(pl.__version__.split(".")[0]) == 1  # the pin in engine/pyproject.toml, as it is installed


# --- punctuation --------------------------------------------------------------------------------------------

PUNCTUATION = [
    ";",
    ":",
    "::",
    "@",
    "$",
    "?",
    "#",
    "[",
    "]",
    "{",
    "}",
    "\\",
    "~",
    "&",
    "|",
    "^",
    "!",
    "!~",
    "`",
]


@pytest.mark.parametrize("mark", PUNCTUATION)
def test_punctuation_that_plain_expressions_do_not_need_is_refused(mark: str) -> None:
    message = refusal(f"a {mark} b")
    assert f"can't contain {mark[0]!r}" in message


@pytest.mark.parametrize(
    "text", ["a -- b", "a--b", "a /* b */", "a /*b", "--", "/*", "a = 1 -- c", "a /* ' */ = 1"]
)
def test_a_comment_is_refused(text: str) -> None:
    assert "can't contain a comment" in refusal(text)


@pytest.mark.parametrize("text", ["a = 'abc", 'a = "abc', "'", '"', "a = 'x' 'y"])
def test_a_quote_that_is_never_closed_is_refused(text: str) -> None:
    assert "never closed" in refusal(text)


def test_a_quote_that_is_never_closed_is_refused_even_when_it_starts_with_a_pair() -> None:
    # `'it''s` could be read as the string 'it' and then a quote: either way it is refused.
    assert refusal("a = 'it''s")


def test_the_operators_that_plain_expressions_need() -> None:
    check_expression(
        "(a = 1 AND b <> 2 AND c != 3 AND d < 4 AND e <= 5 OR f > 6 AND g >= 7) "
        "AND h + 1 - 2 * 3 / 4 % 5 = -6 + +7 AND i || j = k AND l IN (1, 2, 3)"
    )
    check_expression("a - -b = 1")  # a minus and a minus: not a comment


@pytest.mark.parametrize("space", [" ", "  ", "\t", "\n", "\r\n", " \t \n "])
def test_ascii_whitespace_is_fine_anywhere(space: str) -> None:
    check_expression(f"{space}a{space}={space}1{space}")


def test_an_empty_expression_passes_this_check_and_fails_when_polars_reads_it() -> None:
    check_expression("")  # nothing that is refused: the parser of Polars says it is not an expression
    with pytest.raises(ConfigError, match="the expression can't be used"):
        derive("")


# --- queries ------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("word", sorted(QUERY_WORDS))
@pytest.mark.parametrize("spelling", [str.lower, str.upper, str.title, str.swapcase])
def test_the_words_that_start_a_query_are_refused_in_any_case(word: str, spelling: Any) -> None:
    spelled = spelling(word)
    for text in (f"a IN ({spelled} 1)", f"{spelled}", f"a = {spelled}('x')", f"a IN (({spelled} 1))"):
        message = refusal(text)
        assert f"can't contain {spelled!r}" in message
        assert "queries are not allowed" in message


@pytest.mark.parametrize("word", sorted(QUERY_WORDS))
def test_a_column_with_the_name_of_one_of_them_goes_in_double_quotes(word: str) -> None:
    check_expression(f'"{word}" IS NOT NULL AND "{word.upper()}" = 1')


@pytest.mark.parametrize(
    "name",
    ["selection", "fromage", "tablet", "with_tax", "values_count", "island", "ordinal", "_x", "Column2"],
)
def test_a_word_that_only_starts_or_ends_like_a_keyword_is_a_column(name: str) -> None:
    check_expression(f"{name} IS NOT NULL")


# --- what is let through ------------------------------------------------------------------------------------


@pytest.mark.parametrize("word", sorted(KEYWORDS))
def test_every_keyword_is_let_through(word: str) -> None:
    check_expression(f"a {word} b")
    check_expression(f"a {word.upper()} (b)")


@pytest.mark.parametrize("kind", sorted(TYPES))
def test_every_type_name_is_let_through_in_a_cast(kind: str) -> None:
    check_expression(f"CAST(a AS {kind})")
    check_expression(f"try_cast(a AS {kind.upper()}(10, 2))")
    check_expression(f"{kind} IS NULL")  # a column may be called `text`, `string` or `real`


CONTENTS = [
    "",
    "Zo\u00eb",
    "\u65e5\u672c\u8a9e",
    "\u017felect \u0131s \uff33",
    "select from table with values",
    "--",
    "/* not a comment */",
    "a;b[c]{d}`e`$$f::g@h?#~&|^!",
    "C:/temp/new",
    "a\nb\tc\r",
    "\u00a0\u200b",
    "\x00",
    "E'x'",
    ".",
]


@pytest.mark.parametrize("content", CONTENTS, ids=repr)
def test_a_string_or_a_quoted_name_may_hold_any_text(content: str) -> None:
    as_string = "'" + content.replace("'", "''") + "'"
    as_name = '"' + content.replace('"', '""') + '"'
    check_expression(f"a = {as_string}")
    check_expression(f"{as_name} IS NULL")
    check_expression(f"{as_name} = {as_string}")


def test_quotes_inside_a_string_or_a_quoted_name_are_written_twice() -> None:
    check_expression("a = 'it''s' AND b = '''' AND c = 'say \"hi\"'")
    check_expression('"he said ""hi""" IS NULL AND "it\'s" IS NULL')


def test_what_cleaning_a_csv_needs_is_let_through() -> None:
    for text in [
        "id IS NOT NULL",
        "id IS NOT NULL AND name IS NOT NULL",
        "TRY_CAST(amount AS DOUBLE) > 100",
        "CAST(id AS INT) + 1",
        "upper(trim(name)) = 'ALICE'",
        "coalesce(name, 'n/a')",
        "nullif(trim(name), '') IS NOT NULL",
        "name LIKE 'A%' OR name ILIKE 'b%'",
        "length(name) BETWEEN 2 AND 20",
        "city IN ('Berlin', 'Paris', 'Rome')",
        "CASE WHEN amount IS NULL THEN 'none' WHEN TRY_CAST(amount AS INT) > 9 THEN 'big' ELSE 's' END",
        "left(name, 1) || '.' || right(city, 2)",
        "round(TRY_CAST(amount AS DOUBLE) * 1.19, 2)",
        "NOT (a OR b) AND c <> 'x'",
        'concat("first name", \' \', "last name")',
    ]:
        check_expression(text)


# --- with Polars --------------------------------------------------------------------------------------------

SAMPLES = {
    "upper": "upper(a)",
    "lower": "lower(a)",
    "trim": "trim(a)",
    "ltrim": "ltrim(a)",
    "rtrim": "rtrim(a)",
    "length": "length(a)",
    "char_length": "char_length(a)",
    "coalesce": "coalesce(a, 'z')",
    "nullif": "nullif(a, 'x')",
    "abs": "abs(n)",
    "round": "round(n, 1)",
    "floor": "floor(n)",
    "ceil": "ceil(n)",
    "ceiling": "ceiling(n)",
    "concat": "concat(a, 'x')",
    "substr": "substr(a, 1, 2)",
    "substring": "substring(a, 1, 2)",
    "left": "left(a, 2)",
    "right": "right(a, 2)",
    "replace": "replace(a, 'b', 'B')",
    "starts_with": "starts_with(a, 'A')",
    "ends_with": "ends_with(a, 'c')",
    "strftime": "strftime(t, '%Y')",
}


def a_frame() -> pl.LazyFrame:
    return pl.LazyFrame(
        {
            "a": ["Abc ", " x", None],
            "n": [1.5, -2.25, None],
            "t": [datetime(2026, 1, 5), datetime(2025, 2, 11), None],
        }
    )


@pytest.mark.parametrize("fn", sorted(SAMPLES))
def test_every_function_on_the_list_is_one_that_polars_has(fn: str) -> None:
    assert derive(SAMPLES[fn])(a_frame()).collect().height == 3


def test_there_is_a_sample_for_every_function_on_the_list() -> None:
    assert set(SAMPLES) == FUNCTIONS


def test_the_keywords_do_what_they_say() -> None:
    frame = pl.LazyFrame({"a": ["Abc", "x", None, "abd"], "b": ["1", "2.5", "x", None]})
    cases = {
        "a IS NULL": [False, False, True, False],
        "a IS NOT NULL AND a LIKE 'A%'": [True, False, False, False],
        "a ILIKE 'a%'": [True, False, None, True],
        "a IN ('x', 'abd')": [False, True, None, True],
        "a BETWEEN 'a' AND 'b'": [False, False, None, True],
        "NOT (a = 'x')": [True, False, None, True],
        "TRY_CAST(b AS DOUBLE) > 2": [False, True, None, None],
        "CASE WHEN a IS NULL THEN 'none' ELSE upper(a) END = 'none'": [False, False, True, False],
        "a = 'x' OR a = 'abd'": [False, True, None, True],
        "TRUE AND NOT FALSE": [True, True, True, True],
    }
    for expr, expected in cases.items():
        assert derive(expr)(frame).collect()["r"].to_list() == expected, expr


def test_text_outside_the_ascii_range_works_inside_quotes() -> None:
    frame = pl.LazyFrame({"a": ["Zo\u00eb", "\u65e5\u672c\u8a9e", None], "citt\u00e0": ["x", "y", "z"]})
    assert derive("a = 'Zo\u00eb'")(frame).collect()["r"].to_list() == [True, False, None]
    both = derive("a = '\u65e5\u672c\u8a9e' AND \"citt\u00e0\" = 'y'")(frame).collect()
    assert both["r"].to_list() == [False, True, False]  # NULL AND FALSE is FALSE


def test_an_expression_that_is_refused_says_which_node_and_operator_it_was() -> None:
    node = Node.model_validate(
        {"id": "drop", "operator": "transform.filter", "config": {"expr": "\u017felect"}}
    )
    with pytest.raises(ConfigError) as refused:
        build_transform(node)
    assert str(refused.value).startswith("drop (transform.filter): an expression can't contain '\u017f'")


def test_polars_is_not_asked_about_a_text_that_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def asked(text: str) -> pl.Expr:
        raise AssertionError("Polars was asked to parse the expression")

    monkeypatch.setattr(pl, "sql_expr", asked)
    for text in (
        "\u017felect 1",
        "a = E'x'",
        "read_csv('x')",
        "a.b",
        "a; b",
        "a -- b",
        "a ~ 'x'",
        '"date"(a)',
        'CAST(a AS "date")',
    ):
        with pytest.raises(ConfigError):
            derive(text)


# --- the file of a subquery is never opened -----------------------------------------------------------------


@pytest.fixture
def watched(tmp_path: Path) -> Iterator[tuple[Path, threading.Event]]:
    """A named pipe that stands in for a secret file. The event is set when something opens it for reading:
    until then the thread that watches it is stuck in its own `open`, which waits for a reader."""
    if not hasattr(os, "mkfifo"):
        pytest.skip("no named pipes on this system")
    pipe = tmp_path / "secret.csv"
    os.mkfifo(pipe)
    opened = threading.Event()

    def watch() -> None:
        descriptor = os.open(pipe, os.O_WRONLY)
        opened.set()
        os.close(descriptor)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    yield pipe, opened
    if not opened.is_set():
        os.close(os.open(pipe, os.O_RDONLY | os.O_NONBLOCK))  # let the watcher go
    watcher.join(timeout=10)


def attacks(path: Path) -> dict[str, str]:
    """Ways to make Polars read the file at `path` from inside an expression, and to hide that from a scan."""
    return {
        "a subquery": f"id IN (SELECT x FROM read_csv('{path}'))",
        "a long s for the S of SELECT": f"id IN (\u017felect x from read_csv('{path}'))",
        "a dotless i for the i of IN": f"id \u0131n (select x from read_csv('{path}'))",
        "a comment to hide a quote": f"id /* ' */ IN (SELECT x FROM read_csv('{path}')) /* ' */",
        "a line comment": f"id IN (SELECT x FROM read_csv('{path}')) -- '",
        "a prefixed string": f"id IN (SELECT x FROM read_csv(E'{path}'))",
        "a table function in a list": f"id IN (read_csv('{path}'))",
        "FROM first": f"id IN (FROM read_csv('{path}'))",
        "EXISTS": f"EXISTS (SELECT 1 FROM read_csv('{path}'))",
        "a value": f"x = (SELECT max(a) FROM read_csv('{path}'))",
        "TABLE": f"id IN (TABLE '{path}')",
        "a path as the source": f"id IN (SELECT * FROM '{path}')",
        "WITH": f"id IN (WITH t AS (SELECT * FROM read_csv('{path}')) SELECT x FROM t)",
        "a function that is not allowed": f"read_csv('{path}') IS NULL",
        "a function called by a quoted name": f"\"read_csv\"('{path}') IS NULL",
        "a function by a quoted name in a list": f"id IN (\"read_csv\"('{path}'))",
        "a quoted type": f"CAST('{path}' AS \"varchar\") IS NULL",
        "a qualified function": f"polars.read_csv('{path}') IS NULL",
        # A backslash that some tokenizer reads as an escaped quote would end a string in another place:
        "a backslash before the closing quote of the path": f"id IN (SELECT x FROM read_csv('{path}\\'))",
        "a backslash that could escape a quote": (
            f"a = '\\' OR id IN (SELECT x FROM read_csv('{path}')) OR b = '\\'"
        ),
        "a path in a string that ends in a backslash": f"a = '{path}\\'",
        "a path in a quoted name that ends in a backslash": f'"{path}\\" IS NULL',
    }


def test_the_watch_works_raw_polars_opens_the_file_of_a_subquery(
    watched: tuple[Path, threading.Event],
) -> None:
    pipe, opened = watched
    with suppress(Exception):  # it fails on the pipe, after it has opened it
        pl.sql_expr(f"id IN (SELECT x FROM read_csv('{pipe}'))")
    assert opened.wait(timeout=10)


def test_none_of_these_ever_reaches_polars_so_the_file_is_not_opened(
    watched: tuple[Path, threading.Event],
) -> None:
    pipe, opened = watched
    for name, text in attacks(pipe).items():
        for operator, config in (
            ("transform.filter", {"expr": text}),
            ("transform.derive", {"name": "x", "expr": text}),
        ):
            node = Node.model_validate({"id": "step", "operator": operator, "config": config})
            with pytest.raises(ConfigError):
                build_transform(node)
        assert not opened.is_set(), name
    assert not opened.wait(timeout=0.3)


def test_a_path_in_a_string_or_a_quoted_name_is_just_text(watched: tuple[Path, threading.Event]) -> None:
    pipe, opened = watched
    frame = pl.LazyFrame({"a": ["x", None]})
    assert derive(f"a = '{pipe}'")(frame).collect()["r"].to_list() == [False, None]
    assert derive(f'"{pipe}" IS NULL')(pl.LazyFrame({str(pipe): [None, "y"]})).collect()["r"].to_list() == [
        True,
        False,
    ]
    assert not opened.wait(timeout=0.3)
