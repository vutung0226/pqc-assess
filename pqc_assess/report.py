"""Write the merged inventory as a Markdown report for the customer."""

from collections import Counter, OrderedDict

from .classify import BROKEN, QUANTUM_SAFE, QUANTUM_VULNERABLE, RISK_ORDER, REVIEW, WEAKENED

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


def render(target: str, merged: list, libraries: list, coverage: dict, tools_run: dict) -> str:
    counts = Counter(m.risk for m in merged)
    out = [f"# Cryptography inventory: {target}", ""]
    out += ["## Summary", "",
            f"{len(merged)} uses of cryptography found, in "
            f"{len({m.file for m in merged if m.file})} files.", "",
            "| Risk | Findings |", "|---|---|"]
    for risk in RISK_ORDER:
        out.append(f"| {RISK_TEXT[risk]} | {counts.get(risk, 0)} |")
    out.append("")

    out += ["## What to migrate", "",
            "| Algorithm | Risk | Findings | Recommendation |", "|---|---|---|---|"]
    families = OrderedDict()
    for m in merged:
        families.setdefault((m.family, m.risk), []).append(m)
    for (family, risk), items in families.items():
        if risk == QUANTUM_SAFE:
            continue
        out.append(f"| {family} | {risk} | {len(items)} | {items[0].recommendation} |")
    out.append("")

    out += ["## Findings", "",
            "| Risk | Algorithm | Detail | Location | Found by | Evidence |", "|---|---|---|---|---|---|"]
    for m in merged:
        evidence = "; ".join(m.contexts[:1] + m.notes).replace("|", "\\|")
        out.append(f"| {m.risk} | {m.family} | {_detail(m)} | `{_where(m)}` | "
                   f"{', '.join(sorted(m.tools))} | {evidence} |")
    out.append("")

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
            "CryptoScan (all languages and configuration; pattern matching) and qryx.",
            "- Compiled Java (jar, war, ear, class) and Go binaries are read by pqc-assess's own detectors. "
            "A function linked into a Go binary may be called by the standard library rather than the "
            "application; the evidence column names the functions.",
            "- Native binaries are read by qryx, which sees libraries they import (such as OpenSSL), "
            "not cryptography compiled into a stripped, statically linked binary.",
            "- Algorithms chosen at run time (from configuration, a database or user input) are not visible "
            "to a static scan.",
            ""]
    return "\n".join(out)
