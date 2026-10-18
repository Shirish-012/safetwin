"""The static `report.html` (docs/guide.md): the same facts as `report.json`, for people.

No scripts, no external resources (a Content-Security-Policy says so too), and every string is escaped. It
holds what the report holds: names, counts, classes, hashes and settings, never a data value.
"""

from datetime import datetime
from html import escape
from typing import Any

_CSS = """
:root{--bg:#fff;--fg:#1d1d1f;--muted:#5f6068;--line:#e3e3e8;--head:#f5f5f7;--card:#fafafb;
--ok:#11733b;--ok-bg:#e6f4ea;--bad:#b3261e;--bad-bg:#fce8e6;--warn:#7a5900;--warn-bg:#fff8e1;
--warn-line:#f0d58c;--blue:#1d4ed8;--blue-bg:#e8effd;--amber:#8a5a00;--amber-bg:#fdf1dc;--grey-bg:#ececf0;
--violet:#6b3fd4;--violet-bg:#efe8fd}
@media (prefers-color-scheme:dark){:root{--bg:#151517;--fg:#e8e8ea;--muted:#a0a0a8;--line:#34343a;
--head:#232327;--card:#1c1c1f;--ok:#6fd49a;--ok-bg:#16301f;--bad:#ff8a80;--bad-bg:#3a1a18;--warn:#f2cf6b;
--warn-bg:#2c2614;--warn-line:#6d5a1f;--blue:#9ab8ff;--blue-bg:#1b2540;--amber:#f2c063;--amber-bg:#33270f;
--grey-bg:#2a2a2f;--violet:#b9a0ff;--violet-bg:#2a2142}}
*{box-sizing:border-box}
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0 auto;max-width:1100px;
padding:24px 16px 48px;color:var(--fg);background:var(--bg)}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 8px}
.sub{color:var(--muted);margin:0 0 16px}
code,.mono{font:12px/1.5 ui-monospace,Menlo,monospace}.hash{word-break:break-all}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:600;font-size:13px;
vertical-align:middle;margin-left:8px}
.ok{color:var(--ok);background:var(--ok-bg)}.failed{color:var(--bad);background:var(--bad-bg)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:16px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.stat b{display:block;font-size:20px;font-variant-numeric:tabular-nums}
.stat span{color:var(--muted);font-size:12px}
.stat.bad b{color:var(--bad)}.stat.good b{color:var(--ok)}
.box{border:1px solid var(--line);border-radius:8px;padding:8px 14px;margin:12px 0}
.box ul{margin:4px 0;padding-left:20px}.box.errors{background:var(--bad-bg);border-color:var(--bad)}
.box.warnings,.note{background:var(--warn-bg);border-color:var(--warn-line)}
.note{border:1px solid var(--warn-line);border-radius:8px;padding:8px 14px}
.scroll{overflow-x:auto;margin:8px 0}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid var(--line);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--head);font-weight:600;white-space:nowrap}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.pill{display:inline-block;padding:0 8px;border-radius:999px;font-size:12px;white-space:nowrap;
background:var(--grey-bg)}
.pill.removed,.pill.yes{color:var(--ok);background:var(--ok-bg)}
.pill.pseudonymized,.pill.partially-redacted{color:var(--blue);background:var(--blue-bg)}
.pill.generalized{color:var(--amber);background:var(--amber-bg)}
.pill.encrypted{color:var(--violet);background:var(--violet-bg)}
.pill.kept,.pill.no{color:var(--fg);background:var(--grey-bg)}.pill.bad{color:var(--bad);background:var(--bad-bg)}
.empty{color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:12px}
@media print{:root{--bg:#fff;--fg:#000;--card:#fff}.scroll{overflow:visible}}
"""


def _e(value: Any) -> str:
    return escape("" if value is None else str(value), quote=True)


def _text(value: Any) -> str:
    """A setting or a count as people write it: yes/no, 1,000, a list with commas."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, list | tuple):
        return ", ".join(_text(v) for v in value)
    return "" if value is None else str(value)


def _pill(value: Any, kind: str | None = None) -> str:
    label = _text(value).replace("_", " ")
    css = (kind or label).replace(" ", "-")
    return f"<span class='pill {_e(css)}'>{_e(label)}</span>"


def _cell(cell: Any) -> str:
    """A table cell: raw strings are escaped; `("html", s)` is markup this module made."""
    if isinstance(cell, tuple) and len(cell) == 2 and cell[0] == "html":
        return f"<td>{cell[1]}</td>"
    if isinstance(cell, int) and not isinstance(cell, bool):
        return f"<td class='num'>{_e(_text(cell))}</td>"
    return f"<td>{_e(_text(cell))}</td>"


def _table(headers: list[str], rows: list[list[Any]], empty: str, numeric: tuple[int, ...] = ()) -> str:
    if not rows:
        return f"<p class='empty'>{_e(empty)}</p>"
    head = "".join(f"<th{' class=num' if i in numeric else ''}>{_e(h)}</th>" for i, h in enumerate(headers))
    thead = f"<thead><tr>{head}</tr></thead>" if headers else ""
    body = "".join("<tr>" + "".join(_cell(cell) for cell in row) + "</tr>" for row in rows)
    return f"<div class='scroll'><table>{thead}<tbody>{body}</tbody></table></div>"


def _params(params: dict[str, Any] | None) -> str:
    return ", ".join(f"{k}: {_text(v)}" for k, v in (params or {}).items())


def _when(stamp: Any) -> str:
    return str(stamp).replace("T", " ").replace("Z", " UTC") if stamp else "—"


def _took(report: dict[str, Any]) -> str:
    try:
        seconds = (
            datetime.fromisoformat(str(report["ended_at"]))
            - datetime.fromisoformat(str(report["started_at"]))
        ).total_seconds()
    except (KeyError, TypeError, ValueError):
        return "—"
    return f"{seconds:,.0f} s" if seconds >= 1 else "under 1 s"


def _stat(value: str, label: str, tone: str = "") -> str:
    return f"<div class='stat {tone}'><b>{_e(value)}</b><span>{_e(label)}</span></div>"


def _summary(report: dict[str, Any]) -> str:
    tables = report.get("tables", {})
    rows_in = sum(int(t.get("rows_in") or 0) for t in tables.values())
    rows_out = sum(int(t.get("rows_out") or 0) for t in tables.values())
    columns = [c for t in tables.values() for c in t.get("columns", {}).values()]
    masked = sum(1 for c in columns if c.get("class") != "kept")
    orphans = sum(int(r.get("orphans") or 0) for r in report.get("relationships", []))
    unique = report.get("uniqueness", [])
    not_unique = sum(1 for u in unique if u.get("unique_in") and not u.get("unique_out"))
    findings = len(report.get("residual_scan", {}).get("findings", []))
    stats = [
        _stat(f"{len(tables):,}", "tables"),
        _stat(f"{rows_in:,} → {rows_out:,}", "rows in → out"),
        _stat(f"{masked:,} of {len(columns):,}", "columns masked"),
        _stat(
            f"{orphans:,}",
            f"orphans in {len(report.get('relationships', [])):,} relationship(s)",
            "bad" if orphans else "good",
        ),
        _stat(
            "all unique" if not not_unique else f"{not_unique:,} not unique",
            f"of {len(unique):,} unique column(s)",
            "bad" if not_unique else "good",
        ),
        _stat(f"{findings:,}", "residual scan findings", "bad" if findings else "good"),
    ]
    return "<div class='stats'>" + "".join(stats) + "</div>"


def _messages(kind: str, title: str, items: list[Any]) -> str:
    return (
        f"<div class='box {kind}'><b>{_e(title)}</b><ul>"
        + "".join(f"<li>{_e(x)}</li>" for x in items)
        + ("</ul></div>")
    )


def render_html(report: dict[str, Any]) -> str:
    status = report.get("status", "failed")
    policy = report["policy"]
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<meta name='color-scheme' content='light dark'>",
        "<meta http-equiv='Content-Security-Policy' "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>safetwin report · {_e(policy['name'])}</title><style>{_CSS}</style></head><body>",
        f"<h1>safetwin report: {_e(policy['name'])}"
        f"<span class='badge {'ok' if status == 'ok' else 'failed'}'>{_e(status)}</span></h1>",
        f"<p class='sub'>Run <code>{_e(report.get('run_id'))}</code> · {_e(_when(report.get('started_at')))}"
        f" · took {_e(_took(report))}"
        + (f" · from {_e(report['source'])}" if report.get("source") else "")
        + "</p>",
    ]
    if report.get("errors"):
        parts.append(_messages("errors", "This run failed, so no twin was written:", report["errors"]))
    parts.append(_summary(report))
    if report.get("warnings"):
        parts.append(_messages("warnings", "Warnings", report["warnings"]))
    parts.append(
        "<p class='note'>Pseudonymized is not anonymized: anyone who holds the key can link pseudonymized "
        "columns back to guessed inputs, so they stay personal data while the key exists. Generalized and "
        "kept columns can still single people out in combination (see the quasi-identifiers). Masking lowers "
        "the risk of re-identification; it doesn't remove it."
        + (
            " Encrypted columns are reversible: anyone with the access key reads their values back "
            "(safetwin unmask), so share the access key only with people allowed to see them."
            if any(
                c.get("class") == "encrypted"
                for t in report.get("tables", {}).values()
                for c in t.get("columns", {}).values()
            )
            else ""
        )
        + "</p>"
    )
    subset = report.get("subset")
    if subset:
        parts.append("<h2>Subset</h2>")
        parts.append(
            _table(
                [
                    "Root table",
                    "Fraction",
                    "Picked by",
                    "Root rows picked",
                    "Children included",
                    "Copied whole",
                ],
                [
                    [
                        subset.get("root"),
                        f"{float(subset.get('fraction') or 0) * 100:g}%",
                        subset.get("key"),
                        subset.get("root_rows_picked"),
                        bool(subset.get("include_children")),
                        subset.get("copied_whole") or "—",
                    ]
                ],
                "",
                (3,),
            )
        )
    for name, table in report.get("tables", {}).items():
        parts.append(f"<h2>Table {_e(name)}</h2>")
        parts.append(
            f"<p class='sub'>{_e(_text(table.get('rows_in')))} rows in → "
            f"{_e(_text(table.get('rows_out')))} rows out</p>"
        )
        rows = [
            [
                column,
                info["method"],
                ("html", _pill(info["class"])),
                _params(info.get("params")),
                ("html", _pill("yes", "generalized")) if info.get("quasi_identifier") else "",
            ]
            for column, info in table["columns"].items()
        ]
        parts.append(
            _table(["Column", "Method", "Class", "Settings", "Quasi-identifier"], rows, "No columns.")
        )
    parts.append("<h2>Relationships</h2>")
    parts.append(
        _table(
            ["From", "To", "Orphans"],
            [
                [
                    r["from"],
                    r["to"],
                    ("html", _pill(f"{int(r['orphans']):,}", "bad" if r["orphans"] else "yes")),
                ]
                for r in report.get("relationships", [])
            ],
            "No relationships in the policy.",
        )
    )
    parts.append("<h2>Unique columns</h2>")
    parts.append(
        _table(
            ["Column", "Unique in the source", "Unique in the twin"],
            [
                [
                    u["column"],
                    bool(u["unique_in"]),
                    (
                        "html",
                        _pill(u["unique_out"], "yes" if u["unique_out"] or not u["unique_in"] else "bad"),
                    ),
                ]
                for u in report.get("uniqueness", [])
            ],
            "No unique columns to check.",
        )
    )
    parts.append("<h2>Residual scan</h2>")
    findings = report.get("residual_scan", {}).get("findings", [])
    parts.append(
        _table(
            ["Table", "Column", "Detector", "Count", "Level"],
            [
                [f["table"], f["column"], f["detector"], f["count"], ("html", _pill(f["level"], "bad"))]
                for f in findings
            ],
            "No findings: the detectors found nothing in the twin that looks like personal data left behind.",
            (3,),
        )
    )
    delivered = report.get("delivered")
    if delivered:
        parts.append("<h2>Delivered</h2>")
        where = str(delivered.get("to", "")) + (
            f", schema {delivered['schema']}" if delivered.get("schema") else ""
        )
        parts.append(f"<p class='sub'>{_e(where)}</p>")
        parts.append(
            _table(
                ["Table", "Rows"],
                [[t, int(n)] for t, n in (delivered.get("tables") or {}).items()],
                "No tables.",
                (1,),
            )
        )
    parts.append("<h2>Files</h2>")
    parts.append(
        _table(
            ["Path", "Bytes", "SHA-256"],
            [
                [f["path"], f["bytes"], ("html", f"<code class='hash'>{_e(f['sha256'])}</code>")]
                for f in report.get("files", [])
            ],
            "No files: the twin was delivered as above."
            if report.get("delivered")
            else "No files were written.",
            (1,),
        )
    )
    parts.append("<h2>Run</h2>")
    parts.append(
        _table(
            [],
            [
                ["Run", ("html", f"<code>{_e(report.get('run_id'))}</code>")],
                ["Key fingerprint", ("html", f"<code>{_e(report.get('key_fingerprint') or '—')}</code>")],
                ["Policy SHA-256", ("html", f"<code class='hash'>{_e(policy['sha256'])}</code>")],
                ["Started", _when(report.get("started_at"))],
                ["Ended", _when(report.get("ended_at"))],
                ["safetwin", report.get("engine_version")],
            ],
            "",
        )
    )
    parts.append(
        "<footer>Made by safetwin from report.json, which holds the same facts. This page has no scripts and "
        "loads nothing from the network.</footer>"
    )
    parts.append("</body></html>\n")
    return "\n".join(parts)
