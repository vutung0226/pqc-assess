"""Merge the findings of several scanners into one inventory.

Two scanners that see the same call report it under different names, so a
finding is keyed by file, line and algorithm family after classify(): the
"ECC" CryptoScan reports and the "ECDSA-secp256r1" CBOMkit reports on
server.go:4 become one ECDSA finding that both tools saw. Details one tool
recorded and the other did not, such as CBOMkit's key size, are kept.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

from . import location
from .cbom import Finding, component, new_document
from .source import Source
from .classify import BROKEN, REVIEW, RISK_ORDER, classify, is_library_entry, is_noise

# A generic EC finding adds nothing on a line where a scanner named the scheme.
_EC_SCHEMES = {"ECDSA", "ECDH", "EdDSA", "X25519"}


@dataclass
class Merged:
    family: str
    risk: str
    recommendation: str
    primitive: str
    file: Optional[str]
    line: Optional[int]
    key_size: Optional[int] = None
    mode: Optional[str] = None
    curve: Optional[str] = None
    version: Optional[str] = None
    where: str = location.CODE  # code, test or text: see location.kind
    tools: set = field(default_factory=set)
    names: list = field(default_factory=list)
    contexts: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if v not in (None, [], set())}
        d["tools"] = sorted(self.tools)
        return d


@dataclass
class Library:
    name: str
    locations: set = field(default_factory=set)
    tools: set = field(default_factory=set)


def _rank(risk: str) -> int:
    return RISK_ORDER.index(risk)


def merge(findings: list, source: Optional[Source] = None):
    """Return (merged findings sorted most urgent first, libraries)."""
    by_key = {}
    libraries = {}
    for f in findings:
        if is_noise(f.name):
            continue
        if f.asset_type == "library" or is_library_entry(f.name):
            lib = libraries.setdefault(f.name, Library(f.name))
            if f.file:
                lib.locations.add(f.file)
            lib.tools.add(f.tool)
            continue
        if f.asset_type == "issue":
            # An issue a family covers, such as a private key, merges with the
            # same finding from the CBOM; any other keeps its own name.
            c = classify(f.name)
            if c.family != "Other":
                f.asset_type = "algorithm"
            else:
                key = (f.file, f.line, "issue:" + f.name)
                if key not in by_key:
                    risk = BROKEN if f.severity in ("CRITICAL", "HIGH") else REVIEW
                    by_key[key] = Merged(f.name, risk, f.remediation or "Review by hand.", "issue", f.file, f.line)
                by_key[key].tools.add(f.tool)
                continue
        c = classify(f.name, f.key_size, f.mode, f.version)
        # The context can say what the name does not, as CryptoScan's "AES"
        # matched on the text aes-128-cbc.
        if f.context and (c.key_size is None or c.mode is None):
            fromctx = classify(f.context)
            if fromctx.family == c.family:
                c = classify(f.name, c.key_size or fromctx.key_size, c.mode or fromctx.mode, f.version)
        key = (f.file, f.line, c.family)
        m = by_key.get(key)
        if m is None:
            m = by_key[key] = Merged(c.family, c.risk, c.recommendation, c.primitive, f.file, f.line)
        m.tools.add(f.tool)
        if f.name not in m.names:
            m.names.append(f.name)
        # The context of key material is the key; the report must not copy it.
        if f.context and f.context not in m.contexts and c.primitive != "secret":
            m.contexts.append(f.context)
        m.key_size = m.key_size or c.key_size
        m.mode = m.mode or c.mode
        m.curve = m.curve or f.curve
        m.version = m.version or f.version
        if _rank(c.risk) < _rank(m.risk):
            m.risk, m.recommendation = c.risk, c.recommendation
        for note in c.notes:
            if note not in m.notes:
                m.notes.append(note)

    # Classify again with every detail the tools recorded between them, and
    # let that decide: one tool's "AES" with another's key size of 256 is
    # AES-256, which is safe, though the first alone was "review".
    for m in by_key.values():
        if m.primitive == "issue":
            continue
        c = classify(m.names[0], m.key_size, m.mode, m.version)
        if c.family == m.family:
            m.risk, m.recommendation = c.risk, c.recommendation
        for note in c.notes:
            if note not in m.notes:
                m.notes.append(note)

    # Fold a generic EC finding into the scheme on the same line, so the tool
    # that only said "ECC" is still credited with seeing it.
    schemes_at = {(m.file, m.line): m for m in by_key.values() if m.family in _EC_SCHEMES}
    merged = []
    for m in by_key.values():
        scheme = schemes_at.get((m.file, m.line)) if m.family == "EC" and m.line is not None else None
        if scheme is None:
            merged.append(m)
            continue
        scheme.tools |= m.tools
        scheme.curve = scheme.curve or m.curve
        scheme.names += [n for n in m.names if n not in scheme.names]

    merged = _fold_into_key_material(merged)
    src = source or Source(None)
    for m in merged:
        m.where = location.kind(m.file)
        line = src.line(m.file, m.line)
        if line is None:
            continue
        if m.family == "SHA-1" and _HMAC.search(line):
            c = classify("HMAC-SHA1")
            m.family, m.risk, m.recommendation, m.primitive = c.family, c.risk, c.recommendation, c.primitive
        if m.where == location.CODE and m.tools <= _PATTERN_TOOLS and _only_mentioned(m.family, line):
            m.where = location.MENTION
    merged.sort(key=lambda m: (_rank(m.risk), m.family, m.file or "", m.line or 0))
    return merged, sorted(libraries.values(), key=lambda lib: lib.name.lower())


# A key in the code is one finding, not also an RSA finding on the same line:
# the key's algorithm goes into the note, with what to replace it with.
_KEY_ALGORITHMS = {"RSA", "EC", "ECDSA", "ECDH", "DSA", "EdDSA", "X25519", "DH"}


def _fold_into_key_material(merged: list) -> list:
    keys_at = {(m.file, m.line): m for m in merged if m.family == "Key material in code" and m.line}
    out = []
    for m in merged:
        key = keys_at.get((m.file, m.line)) if m.family in _KEY_ALGORITHMS else None
        if key is None:
            out.append(m)
            continue
        key.tools |= m.tools
        key.names += [n for n in m.names if n not in key.names]
        note = f"The key is {m.family}: when rotating it, replace it per this recommendation: {m.recommendation}"
        if note not in key.notes:
            key.notes.append(note)
    return out


_HMAC = re.compile(r"hmac", re.I)
# Scanners that match text rather than code structure: only their findings can
# be a word that merely appears on the line.
_PATTERN_TOOLS = {"cryptoscan"}
_ALG_WORD = {
    "MD5": r"md5", "SHA-1": r"sha-?1(?!\d)", "RSA": r"rsa", "DSA": r"(?<![a-z])dsa", "ECDSA": r"ecdsa",
    "EC": r"ecdsa|ecdh|ecc|secp\d|prime256|p-?(256|384|521)", "3DES": r"3des|des3|desede|des-cbc3|triple",
    "DES": r"(?<![a-z])des(?![a-z])", "RC4": r"rc4|arcfour", "AES": r"aes",
}
_NOT_A_USE = [
    re.compile(r"https?://\S+", re.I),  # a URL
    re.compile(r"\.(md5|sha1|sha256|sha512)\b", re.I),  # a file extension: file.md5
    re.compile(r"%[^%\s]*%"),  # a SQL LIKE pattern: '%md5%'
]


def _only_mentioned(family: str, line: str) -> bool:
    """True when the algorithm's name on this line appears only in a URL, a
    file extension or a LIKE pattern."""
    word = _ALG_WORD.get(family)
    if not word or not re.search(word, line, re.I):
        return False
    rest = line
    for pattern in _NOT_A_USE:
        rest = pattern.sub(" ", rest)
    return not re.search(word, rest, re.I)


def to_cbom(merged: list, libraries: list) -> dict:
    """One component per family and parameters, with every occurrence."""
    groups = {}
    for m in merged:
        if m.primitive == "issue":
            continue  # not a cryptographic asset; report.md and findings.json list it
        groups.setdefault((m.family, m.key_size, m.mode, m.curve), []).append(m)
    comps = []
    for (family, size, mode, curve), items in groups.items():
        name = "-".join(str(p) for p in (family, size, mode, curve) if p)
        occurrences = []
        for m in items:
            occ = {"location": m.file or "(unknown)"}
            if m.line is not None:
                occ["line"] = m.line
            if m.contexts:
                occ["additionalContext"] = m.contexts[0]
            occurrences.append(occ)
        first = items[0]
        comp = component(name, first.primitive, occurrences,
                         asset_type="protocol" if family.startswith(("TLS", "SSL")) else "algorithm",
                         key_size=size, mode=mode,
                         properties=[
                             {"name": "pqc-assess:risk", "value": first.risk},
                             {"name": "pqc-assess:location",
                              "value": ",".join(sorted({m.where for m in items}))},
                             {"name": "pqc-assess:recommendation", "value": first.recommendation},
                             {"name": "pqc-assess:tools",
                              "value": ",".join(sorted(set().union(*(m.tools for m in items))))},
                         ])
        if curve:
            comp["cryptoProperties"]["algorithmProperties"]["curve"] = curve
        comps.append(comp)
    for lib in libraries:
        comps.append({
            "type": "library",
            "bom-ref": f"lib-{len(comps)}",
            "name": lib.name,
            "evidence": {"occurrences": [{"location": loc} for loc in sorted(lib.locations)]},
            "properties": [{"name": "pqc-assess:tools", "value": ",".join(sorted(lib.tools))}],
        })
    return new_document("pqc-assess", comps)


def tool_coverage(merged: list) -> dict:
    """For each tool, how many merged findings it saw and how many only it saw."""
    out = {}
    for m in merged:
        for t in m.tools:
            row = out.setdefault(t, {"findings": 0, "only": 0})
            row["findings"] += 1
            if len(m.tools) == 1:
                row["only"] += 1
    return dict(sorted(out.items()))


def load_all(inputs: list) -> list:
    """inputs holds (tool, path) pairs: a CBOM, or a CryptoScan JSON report
    named *.issues.json."""
    from .cbom import read_cryptoscan_issues, read_findings
    findings: list = []
    for tool, path in inputs:
        if path.endswith(".issues.json"):
            findings.extend(read_cryptoscan_issues(path, tool))
        else:
            findings.extend(read_findings(path, tool))
    return findings


__all__ = ["Finding", "Merged", "Library", "merge", "to_cbom", "tool_coverage", "load_all"]
