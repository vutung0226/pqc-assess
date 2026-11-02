"""Read and write CycloneDX 1.6 CBOM documents.

Every scanner pqc-assess runs, its own detectors included, writes a CBOM, so
the merge step reads one format. A Finding is one occurrence of one asset:
the place a scanner saw it, and what it said about it.
"""

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import __version__

# Prefixes the scanners put before a path, from where the runner mounts the
# target inside each container, or from the scanner's own working directory.
_MOUNT_PREFIXES = re.compile(r"^(?:/?github/workspace/|/scan/|/target/|\./)")
# Material CBOMkit lists beside an algorithm under a generated name, such as
# key@84972f0c-...; its size is already on the algorithm.
_GENERATED_NAME = re.compile(r"^(?:key|private-key|public-key|secret-key)@", re.I)


@dataclass
class Finding:
    tool: str
    name: str
    file: Optional[str]
    line: Optional[int]
    asset_type: str = "algorithm"  # algorithm, protocol or library
    primitive: Optional[str] = None
    key_size: Optional[int] = None
    mode: Optional[str] = None
    curve: Optional[str] = None
    version: Optional[str] = None
    context: Optional[str] = None  # what the scanner saw, such as the call
    severity: Optional[str] = None  # for an issue: the scanner's severity
    remediation: Optional[str] = None


def normalize_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return _MOUNT_PREFIXES.sub("", path)


def _int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def read_findings(path: str, tool: str) -> list:
    """Return one Finding per occurrence in the CBOM at path."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    findings = []
    # qryx writes "components": null when it finds nothing.
    for comp in doc.get("components") or []:
        name = comp.get("name") or ""
        props = comp.get("cryptoProperties") or {}
        asset = props.get("assetType")
        if comp.get("type") == "library":
            asset = "library"
        if asset == "related-crypto-material" and _GENERATED_NAME.match(name):
            continue
        alg = props.get("algorithmProperties", {})
        proto = props.get("protocolProperties", {})
        version = proto.get("version")
        if asset == "protocol" and version and version not in name:
            name = f"{name} {version}"
        occurrences = comp.get("evidence", {}).get("occurrences") or [{}]
        for occ in occurrences:
            findings.append(Finding(
                tool=tool,
                name=name,
                file=normalize_path(occ.get("location")),
                line=_int(occ.get("line")),
                asset_type=asset or "algorithm",
                primitive=alg.get("primitive"),
                key_size=_int(alg.get("parameterSetIdentifier")),
                mode=alg.get("mode"),
                curve=alg.get("curve"),
                version=version,
                context=occ.get("additionalContext") or occ.get("symbol"),
            ))
    return findings


# CryptoScan categories that are not an algorithm and so are not in its CBOM:
# certificate validation turned off, private keys and secrets in the code.
ISSUE_CATEGORIES = {"Configuration", "Secret Detection", "Certificate", "TLS/SSL"}
ISSUE_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM"}


def read_cryptoscan_issues(path: str, tool: str = "cryptoscan") -> list:
    """Return the findings in a CryptoScan JSON report that its CBOM leaves
    out. Only the type, place, severity and fix are kept: a finding's match
    and source lines can hold a private key from the customer's code, and the
    report must not copy it."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    findings = []
    for x in doc.get("findings") or []:
        if x.get("algorithm") or x.get("category") not in ISSUE_CATEGORIES:
            continue
        if (x.get("severity") or "").upper() not in ISSUE_SEVERITIES:
            continue
        findings.append(Finding(
            tool=tool,
            name=x.get("type") or x.get("category"),
            file=normalize_path(x.get("file")),
            line=_int(x.get("line")),
            asset_type="issue",
            severity=(x.get("severity") or "").upper(),
            remediation=x.get("remediation"),
        ))
    return findings


def new_document(tool_name: str, components: list) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": tool_name, "version": __version__}]},
        },
        "components": components,
    }


def component(name: str, primitive: str, occurrences: list, asset_type: str = "algorithm",
              key_size: Optional[int] = None, mode: Optional[str] = None,
              properties: Optional[list] = None) -> dict:
    """Build one cryptographic-asset component. occurrences holds dicts with
    location, line and, when known, additionalContext."""
    if asset_type == "protocol":
        crypto = {"assetType": "protocol", "protocolProperties": {"type": "tls"}}
    else:
        alg = {"primitive": primitive}
        if key_size:
            alg["parameterSetIdentifier"] = str(key_size)
        if mode:
            alg["mode"] = mode.lower()
        crypto = {"assetType": "algorithm", "algorithmProperties": alg}
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto-{uuid.uuid4()}",
        "name": name,
        "cryptoProperties": crypto,
        "evidence": {"occurrences": occurrences},
    }
    if properties:
        comp["properties"] = properties
    return comp


@dataclass
class Collector:
    """Gathers a detector's findings into components, one per asset name."""
    tool: str
    _by_name: dict = field(default_factory=dict)
    _libraries: dict = field(default_factory=dict)

    def add_library(self, name: str, location: str):
        locations = self._libraries.setdefault(name, [])
        if location not in locations:
            locations.append(location)

    def add(self, name: str, primitive: str, location: str, line: Optional[int] = None,
            context: Optional[str] = None, key_size: Optional[int] = None, mode: Optional[str] = None):
        key = (name, key_size, mode)
        entry = self._by_name.setdefault(key, {"primitive": primitive, "occurrences": []})
        occ = {"location": location}
        if line is not None:
            occ["line"] = line
        if context:
            occ["additionalContext"] = context
        if occ not in entry["occurrences"]:
            entry["occurrences"].append(occ)

    def document(self) -> dict:
        comps = [component(name, e["primitive"], e["occurrences"], key_size=size, mode=mode)
                 for (name, size, mode), e in sorted(self._by_name.items(), key=lambda kv: str(kv[0]))]
        for name, locations in sorted(self._libraries.items()):
            comps.append({
                "type": "library",
                "bom-ref": f"lib-{uuid.uuid4()}",
                "name": name,
                "evidence": {"occurrences": [{"location": loc} for loc in locations]},
            })
        return new_document(self.tool, comps)


def write(doc: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
