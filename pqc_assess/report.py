"""Write the merged inventory as a Markdown report for the customer."""

from collections import Counter, OrderedDict

from .classify import BROKEN, QUANTUM_SAFE, QUANTUM_VULNERABLE, RISK_ORDER, REVIEW, WEAKENED
from .location import CODE

RISK_TEXT = {
    BROKEN: "Broken today: replace now, quantum computer or not",
    QUANTUM_VULNERABLE: "Broken by a quantum computer (Shor): migrate to PQC",
    WEAKENED: "Weakened by a quantum computer (Grover): use larger keys",
    REVIEW: "Needs review: the scanners could not tell enough",
    QUANTUM_SAFE: "Quantum-safe: no change needed",
}


def _where(m) -> str:
    if not m.file:
        return "(location unknown)"
    return f"{m.file}:{m.line}" if m.line is not None else m.file


def _detail(m) -> str:
    # A hash's parameter is its digest length, not a key size, and the
    # family name already says it.
    size = m.key_size if m.primitive != "hash" else None
    parts = [f"{size}-bit" if size else None, m.mode, m.curve,
             f"v{m.version}" if m.version else None]
    return ", ".join(p for p in parts if p)


MAX_LINES_SHOWN = 6


def _findings_table(out: list, rows: list, with_where: bool = False):
    """One row per file, algorithm and detail: a file that uses MD5 on 27
    lines is one row naming the lines, not 27 rows. findings.json keeps
    every line."""
    head = "| Risk | Algorithm | Detail | Location | Found by | Evidence |"
    if with_where:
        head = "| Risk | Algorithm | Detail | Location | In | Found by | Evidence |"
    out += [head, "|" + "---|" * (head.count("|") - 1)]
    groups = OrderedDict()
    for m in rows:
        groups.setdefault((m.risk, m.family, _detail(m), m.file, m.where), []).append(m)
    for (risk, family, detail, file, where), items in groups.items():
        lines = sorted({m.line for m in items if m.line is not None})
        if not file:
            loc = "(location unknown)"
        elif not lines:
            loc = f"`{file}`"
        elif len(lines) == 1:
            loc = f"`{file}:{lines[0]}`"
        else:
            shown = ", ".join(str(n) for n in lines[:MAX_LINES_SHOWN])
            more = f", … ({len(lines)} lines)" if len(lines) > MAX_LINES_SHOWN else ""
            loc = f"`{file}` lines {shown}{more}"
        tools = sorted(set().union(*(m.tools for m in items)))
        first = items[0]
        evidence = "; ".join(first.contexts[:1] + first.notes).replace("|", "\\|")
        in_col = f" {where} |" if with_where else ""
        out.append(f"| {risk} | {family} | {detail} | {loc} |{in_col} {', '.join(tools)} | {evidence} |")
    out.append("")


def render(target: str, merged: list, libraries: list, coverage: dict, tools_run: dict) -> str:
    code = [m for m in merged if m.where == CODE]
    other = [m for m in merged if m.where != CODE]
    counts = Counter(m.risk for m in code)
    out = [f"# Cryptography inventory: {target}", ""]
    out += ["## Summary", "",
            f"{len(code)} uses of cryptography found in application code and configuration, in "
            f"{len({m.file for m in code if m.file})} files.", ""]
    if other:
        out += [f"A further {len(other)} matches are in tests, documentation, translations or data files, "
                "or name an algorithm only in a file extension, a URL or a query string. They are listed apart "
                "at the end: an algorithm named there is usually mentioned, not used.", ""]
    out += ["| Risk | Findings in code |", "|---|---|"]
    for risk in RISK_ORDER:
        out.append(f"| {RISK_TEXT[risk]} | {counts.get(risk, 0)} |")
    out.append("")

    out += ["## What to migrate", "",
            "| Algorithm | Risk | Findings | Recommendation |", "|---|---|---|---|"]
    families = OrderedDict()
    for m in code:
        families.setdefault((m.family, m.risk), []).append(m)
    for (family, risk), items in families.items():
        if risk == QUANTUM_SAFE:
            continue
        out.append(f"| {family} | {risk} | {len(items)} | {items[0].recommendation} |")
    out.append("")

    out += ["## Findings in code", ""]
    _findings_table(out, code)

    if libraries:
        out += ["## Cryptography libraries", "",
                "A library is listed because a manifest or a binary names it; "
                "the findings above show which of its algorithms the code calls.", "",
                "| Library | Where | Found by |", "|---|---|---|"]
        for lib in libraries:
            where = ", ".join(f"`{loc}`" for loc in sorted(lib.locations)[:3]) or "-"
            out.append(f"| {lib.name} | {where} | {', '.join(sorted(lib.tools))} |")
        out.append("")

    out += ["## Scanners", "",
            "| Scanner | Status | Findings | Found only by this scanner |", "|---|---|---|---|"]
    for tool, status in tools_run.items():
        row = coverage.get(tool, {"findings": 0, "only": 0})
        out.append(f"| {tool} | {status} | {row['findings']} | {row['only']} |")
    out += ["",
            "## Limits of this scan", "",
            "- Source code is read by CBOMkit (Java, Python, Go, C#; semantic), "
            "CryptoScan (all languages and configuration; pattern matching) and qryx. "
            "JWT and JOSE signature algorithms (RS256, ES256, ...) are read by pqc-assess.",
            "- Compiled Java (jar, war, ear, class) and Go binaries are read by pqc-assess's own detectors. "
            "A function linked into a Go binary may be called by the standard library rather than the "
            "application; the evidence column names the functions.",
            "- Native binaries are read by qryx, which sees libraries they import (such as OpenSSL), "
            "not cryptography compiled into a stripped, statically linked binary.",
            "- Pattern matches can still name an algorithm that the code does not use, such as a file "
            "extension `.md5` or a query string. Check the evidence before acting on a finding found by "
            "CryptoScan alone.",
            "- Algorithms chosen at run time (from configuration, a database or user input) are not visible "
            "to a static scan.",
            ""]

    if other:
        out += ["## In tests, documentation, data, and mentions", "",
                "Matches in files that are not application code (`test`, `text`), and lines of code that name "
                "an algorithm only in a file extension, a URL or a query string (`mention`). Most name an "
                "algorithm without using it; a test can still show how the code uses one.", ""]
        _findings_table(out, other, with_where=True)
    return "\n".join(out)
