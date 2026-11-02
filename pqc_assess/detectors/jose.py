"""Find the JWT and JOSE signature algorithms an application names.

A web application usually signs its tokens with RSA or ECDSA through a JWT
library, and names the algorithm with a JOSE identifier: jwt.sign(payload,
key, { algorithm: 'RS256' }), SignatureAlgorithm.ES256, JWSAlgorithm.PS384.
None of the upstream scanners reads these: on OWASP Juice Shop all three
missed the RS256 that signs every login token, which is the signature a
quantum computer would forge.

HS256 and the other HMAC identifiers are quantum-safe and are not reported.
"""

import re

from ..cbom import Collector
from . import walk

TOOL = "pqc-assess-jose"

TEXT_EXTS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".kt", ".scala", ".py", ".go",
             ".rb", ".php", ".cs", ".rs", ".json", ".yml", ".yaml", ".properties", ".toml", ".env",
             ".xml", ".conf")
MAX_BYTES = 2 * 1024 * 1024

# JOSE identifier (RFC 7518) to the family classify() understands.
_FAMILY = {"RS": "RSA", "PS": "RSA", "ES": "ECDSA"}

_PATTERNS = [
    # A quoted identifier: 'RS256', "ES384", `PS512`, as an option or a JSON value.
    re.compile(r"""(?<![A-Za-z0-9])["'`](?P<alg>(?:RS|PS|ES)(?:256|384|512)|EdDSA)["'`]"""),
    # Library enums: jjwt SignatureAlgorithm.RS256, Nimbus JWSAlgorithm.ES256,
    # .NET SecurityAlgorithms.RsaSha256, auth0 java-jwt Algorithm.RSA256(...).
    re.compile(r"\b(?:SignatureAlgorithm|JWSAlgorithm|AlgorithmIdentifiers)\.(?P<alg>(?:RS|PS|ES)(?:256|384|512)|EdDSA)\b"),
    re.compile(r"\bSecurityAlgorithms\.(?P<net>RsaSha|RsaSsaPssSha|EcdsaSha)(?P<bits>256|384|512)\b"),
    re.compile(r"\bAlgorithm\.(?P<auth0>RSA|ECDSA)(?P<abits>256|384|512)\s*\("),
]
_NET = {"RsaSha": "RS", "RsaSsaPssSha": "PS", "EcdsaSha": "ES"}


def _identifier(m: "re.Match") -> str:
    d = m.groupdict()
    if d.get("alg"):
        return d["alg"]
    if d.get("net"):
        return _NET[d["net"]] + d["bits"]
    return ("RS" if d["auth0"] == "RSA" else "ES") + d["abits"]


def scan(root: str) -> dict:
    out = Collector(TOOL)
    for path, rel in walk.files(root):
        if not rel.lower().endswith(TEXT_EXTS) or rel.lower().endswith((".min.js", "package-lock.json")):
            continue
        try:
            text = walk.head(path, MAX_BYTES).decode("utf-8", "replace")
        except OSError:
            continue
        if "\x00" in text[:4096]:
            continue
        for lineno, line in enumerate(text.split("\n"), start=1):
            if len(line) > 2000:  # minified or generated
                continue
            for pattern in _PATTERNS:
                for m in pattern.finditer(line):
                    alg = _identifier(m)
                    family = "EdDSA" if alg == "EdDSA" else _FAMILY[alg[:2]]
                    out.add(f"{family} (JWT {alg})", "signature", rel, lineno,
                            f"JOSE signature algorithm {alg}: {line.strip()[:120]}")
    return out.document()
