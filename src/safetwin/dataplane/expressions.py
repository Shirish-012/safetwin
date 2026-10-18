"""What a filter or derive expression may say: a short allow-list, checked before Polars sees the text.

Polars parses an SQL expression itself, and it parses a subquery inside one (and so opens the files of a
`read_csv('...')` in it) while it reads the text: `x IN (SELECT y FROM read_csv('/etc/hosts'))` would read
that file, whatever the socket of the pipeline says. A list of words to refuse cannot be made to agree with
Polars' own tokenizer, which is written in Rust, knows every Unicode letter and more ways to write a string
than a Python regex does. So nothing is decided by what Polars would make of the text: the text is read here,
by rules as plain as possible, and only what this module knows is let through.

- Outside quotes the text is ASCII: whitespace, words (`[A-Za-z_][A-Za-z0-9_]*`), numbers, and the operators
  `= <> != < <= > >= + - * / % || ( ) ,`. Nothing else: no comment, no `;`, no `.` except inside a number,
  no `:` `@` `$` `?` `#`, no brackets or backticks, no letter that is not ASCII.
- A string is `'...'` with `''` for a quote in it, a name is `"..."` with `""`. What is inside is text, any
  text but a backslash: a tokenizer that reads `\\'` as an escaped quote would end the string somewhere else
  than this module does, and what comes after would skip the rules. A word may not touch a quote (`E'...'`,
  `X'...'` and `N'...'` are other kinds of string), and nothing may touch a dot.
- A word is a keyword or type name of the lists below; or a function of the list of functions, and then it is
  followed by `(`; or a column name. The words that start a query are refused by name as well.
- A quoted name is a column name and nothing else. Polars reads `"date"(d)` as a call of the function `date`
  and `CAST(d AS "date")` as a cast to a date, so a quoted name may not be followed by `(` and may not come
  right after `AS`: a function or a type is written as a plain word, which the lists below can decide on.

The functions are row by row. A function that looks at the other rows (`SUM`, `COUNT`, a window with `OVER`)
would give a different answer for every chunk of rows that Polars happens to hand it.

For the same reason nothing here turns text into dates: not `CAST(x AS DATE)` (or `TIMESTAMP`, `DATETIME`,
`TIME`, with `TRY_CAST` too), and not the functions `date()`, `time()`, `timestamp()` and `datetime()`. A CSV
column is text, and Polars would guess its format from the first value of each chunk of rows it is handed, so
the same file could give other dates on another run or on the other path. `transform.parse_dates` reads dates
the same way every time. Casts to numbers and to text are fine.
"""

import re
from typing import Final


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


KEYWORDS: Final = _words(
    "and or not is null true false in between like ilike case when then else end cast try_cast as distinct"
)
TYPES: Final = _words(
    "int integer bigint smallint float double real decimal numeric varchar text string boolean bool"
)
FUNCTIONS: Final = _words(
    "upper lower trim ltrim rtrim length char_length coalesce nullif abs round floor ceil ceiling concat "
    "substr substring left right replace starts_with ends_with strftime"
)
# Every query starts with one of these. They are refused by name, as a second layer, with a message that says
# what is wrong (and `"select"` in double quotes is a column).
QUERY_WORDS: Final = _words("select with values table from")
# Casting to these, or calling a function of the name, makes Polars guess a date format from the text.
TIME_TYPES: Final = _words("date time timestamp datetime")

_TOKEN = re.compile(
    r"""
      (?P<space>[ \t\r\n]+)
    | (?P<comment>--|/\*)
    | (?P<string>'(?:[^']|'')*')
    | (?P<name>"(?:[^"]|"")*")
    | (?P<number>(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?)
    | (?P<word>[A-Za-z_][A-Za-z0-9_]*)
    | (?P<operator><>|!=|<=|>=|\|\||[-+*/%=<>(),])
    """,
    re.VERBOSE,
)
_CALL = re.compile(r"[ \t\r\n]*\(")  # what follows the name of a function
_A_KIND = {"word": "a word", "number": "a number", "string": "a string", "name": "a quoted name"}


def check_expression(text: str) -> None:
    """Raise `ValueError`, saying what is wrong, unless `text` only says what this module allows."""
    position = 0
    after_as = False  # the last thing was the word AS, so the name of a type comes next
    while position < len(text):
        token = _TOKEN.match(text, position)
        if token is None:
            raise ValueError(_cannot_start_with(text[position]))
        kind, end = token.lastgroup, token.end()
        if kind == "comment":
            raise ValueError("an expression can't contain a comment ('--' or '/*')")
        if kind in ("string", "name") and "\\" in token.group():
            raise ValueError(
                f"an expression can't contain a backslash in {_A_KIND[kind]}: a backslash is not allowed "
                "there, write a quote as '' in a string and as \"\" in a quoted name"
            )
        follower = text[end : end + 1]
        if kind in _A_KIND and follower in ("'", '"'):
            raise ValueError(
                f"an expression can't have a quote glued to {_A_KIND[kind]} (E'...', X'...' and N'...' are "
                "other kinds of string): put a space or an operator between them"
            )
        if kind in _A_KIND and follower == ".":
            raise ValueError(
                f"an expression can't have a '.' after {_A_KIND[kind]}: a dot belongs inside a number"
            )
        if kind == "number" and follower.isascii() and (follower.isalnum() or follower == "_"):
            raise ValueError("an expression can't have a letter or a digit glued to the end of a number")
        word = text[token.start() : end] if kind == "word" else ""
        if kind == "word":
            _check_word(word, _CALL.match(text, end) is not None, after_as)
        elif kind == "name":
            _check_quoted_name(token.group(), _CALL.match(text, end) is not None, after_as)
        if kind != "space":
            after_as = word.casefold() == "as"
        position = end


def _check_word(word: str, is_called: bool, after_as: bool) -> None:
    folded = word.casefold()
    if folded in QUERY_WORDS:
        raise ValueError(
            f"an expression can't contain {word!r}: queries are not allowed in it "
            '(a column with that name can be written in "double quotes")'
        )
    if folded in TIME_TYPES and (after_as or is_called):
        raise ValueError(
            f"an expression can't convert to {word.upper()}: Polars would guess the date format from the "
            "first value of each chunk of rows, so the same file could give other dates on another run. "
            "Use transform.parse_dates to read dates"
        )
    if is_called and folded not in KEYWORDS and folded not in TYPES and folded not in FUNCTIONS:
        raise ValueError(
            f"function {word!r} is not allowed in an expression (the functions that are: "
            f"{', '.join(sorted(FUNCTIONS))})"
        )


def _check_quoted_name(name: str, is_called: bool, after_as: bool) -> None:
    if is_called:
        raise ValueError(
            f"an expression can't call a function by a quoted name ({name}(...)): write the name of a "
            f"function as a plain word (the functions that are allowed: {', '.join(sorted(FUNCTIONS))})"
        )
    if after_as:
        raise ValueError(
            f"an expression can't have a quoted name after AS ({name}): write the type of a cast as a plain "
            "word, such as INT or VARCHAR"
        )


def _cannot_start_with(char: str) -> str:
    if char in ("'", '"'):
        return "an expression can't contain a string or a quoted name that is never closed"
    if char == ".":
        return "an expression can't contain a '.' outside a number"
    return (
        f"an expression can't contain {char!r} outside quotes: use ASCII letters and digits and the "
        "operators = <> != < <= > >= + - * / % || ( ) ,  and put any other text in 'single quotes' or "
        '"double quotes"'
    )
