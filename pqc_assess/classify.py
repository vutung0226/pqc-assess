"""Turn the algorithm names the scanners write into one family, a risk and a fix.

Every tool names the same thing differently: CryptoScan writes "ECC" for a
line where CBOMkit writes "ECDSA-secp256r1" and qryx writes "ECDSA". The
merge step needs one name per family, so that the three findings on that line
become one, and the report needs to say for each family what a quantum
computer does to it and what to migrate to.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

# Risk levels, most urgent first. The report sorts by this order.
BROKEN = "broken"  # weak today, without a quantum computer
QUANTUM_VULNERABLE = "quantum-vulnerable"  # broken by Shor's algorithm
WEAKENED = "quantum-weakened"  # security halved by Grover's algorithm
REVIEW = "review"  # not enough information to judge
QUANTUM_SAFE = "quantum-safe"

RISK_ORDER = [BROKEN, QUANTUM_VULNERABLE, WEAKENED, REVIEW, QUANTUM_SAFE]

_SIGN = "ML-DSA-65 (FIPS 204), or SLH-DSA (FIPS 205) where signatures are long-lived"
_KEM = "ML-KEM-768 (FIPS 203), in a hybrid such as X25519MLKEM768 during the transition"


@dataclass(frozen=True)
class Family:
    name: str
    pattern: "re.Pattern[str]"
    risk: str
    primitive: str
    recommendation: str


# Checked in order: the first match wins, so a name such as SHA256withECDSA
# reaches ECDSA before it reaches the SHA-2 or RSA entries, and ML-DSA is
# matched before DSA.
FAMILIES = [
    # A key in the code is a finding whatever its algorithm, and the header
    # names RSA, so it goes first.
    Family("Key material in code", re.compile(r"PRIVATE-KEY|KEY-MATERIAL|PRIVATE-KEY-HEADER"), BROKEN, "secret",
           "Remove the key from the code and the repository history, and rotate it."),
    Family("Hybrid PQC", re.compile(r"X25519-?MLKEM|MLKEM-?X25519|SECP256R1-?MLKEM|X25519-?KYBER"),
           QUANTUM_SAFE, "kem", "No change needed."),
    Family("ML-KEM", re.compile(r"ML-?KEM|KYBER"), QUANTUM_SAFE, "kem", "No change needed."),
    Family("ML-DSA", re.compile(r"ML-?DSA|DILITHIUM"), QUANTUM_SAFE, "signature", "No change needed."),
    Family("SLH-DSA", re.compile(r"SLH-?DSA|SPHINCS"), QUANTUM_SAFE, "signature", "No change needed."),
    Family("FN-DSA", re.compile(r"FN-?DSA|FALCON"), QUANTUM_SAFE, "signature", "No change needed."),
    Family("XMSS/LMS", re.compile(r"\bXMSS|\bLMS\b|\bHSS\b"), QUANTUM_SAFE, "signature", "No change needed."),
    Family("ECDSA", re.compile(r"ECDSA"), QUANTUM_VULNERABLE, "signature", f"Migrate signatures to {_SIGN}."),
    Family("ECDH", re.compile(r"ECDH|ECMQV"), QUANTUM_VULNERABLE, "key-agree", f"Migrate key exchange to {_KEM}."),
    Family("EdDSA", re.compile(r"ED25519|ED448|EDDSA"), QUANTUM_VULNERABLE, "signature", f"Migrate signatures to {_SIGN}."),
    Family("X25519", re.compile(r"X25519|X448|CURVE25519"), QUANTUM_VULNERABLE, "key-agree", f"Migrate key exchange to {_KEM}."),
    Family("DSA", re.compile(r"(?<![A-Z])DSA\b|WITHDSA"), QUANTUM_VULNERABLE, "signature",
           f"DSA is withdrawn (FIPS 186-5); migrate signatures to {_SIGN}."),
    Family("RSA", re.compile(r"RSA"), QUANTUM_VULNERABLE, "pke",
           f"Migrate encryption and key transport to {_KEM}, and signatures to {_SIGN}."),
    Family("DH", re.compile(r"^DH\b|^DH-|DIFFIE|FFDHE|^DHE$"), QUANTUM_VULNERABLE, "key-agree",
           f"Migrate key exchange to {_KEM}."),
    Family("EC", re.compile(r"^EC\b|^EC-|^ECC$|SECP\d|PRIME256|\bP-?(256|384|521)\b|NISTP|BRAINPOOL|ELLIPTIC"),
           QUANTUM_VULNERABLE, "pke",
           f"Find whether the key signs or agrees keys: migrate signatures to {_SIGN}, key exchange to {_KEM}."),
    Family("3DES", re.compile(r"3DES|TRIPLE-?DES|DESEDE|DES3|DES-EDE|TDEA|DES-CBC3"), BROKEN, "block-cipher",
           "Replace with AES-256-GCM now (Sweet32; disallowed by NIST after 2023)."),
    Family("DES", re.compile(r"^DES\b|^DES-|\bDES$"), BROKEN, "block-cipher", "Replace with AES-256-GCM now."),
    Family("RC4", re.compile(r"RC4|ARCFOUR|\bARC4\b"), BROKEN, "stream-cipher",
           "Replace with AES-256-GCM or ChaCha20-Poly1305 now."),
    Family("RC2", re.compile(r"\bRC2\b"), BROKEN, "block-cipher", "Replace with AES-256-GCM now."),
    Family("Blowfish", re.compile(r"BLOWFISH|\bBF-"), BROKEN, "block-cipher", "Replace with AES-256-GCM now."),
    Family("MD5", re.compile(r"\bMD[245]\b|^MD5|MD5"), BROKEN, "hash", "Replace with SHA-256 or SHA-3 now."),
    Family("SHA-1", re.compile(r"SHA-?1(?!\d)"), BROKEN, "hash", "Replace with SHA-256 or SHA-3 now."),
    Family("SHA-3", re.compile(r"SHA-?3|SHAKE|KECCAK"), QUANTUM_SAFE, "hash", "No change needed."),
    Family("SHA-2", re.compile(r"SHA-?(224|256|384|512)|SHA-?2\b"), QUANTUM_SAFE, "hash",
           "No change needed; prefer SHA-384 or SHA-512 where collision resistance must hold long term."),
    Family("BLAKE", re.compile(r"BLAKE"), QUANTUM_SAFE, "hash", "No change needed."),
    Family("AES", re.compile(r"AES"), WEAKENED, "block-cipher", "Use 256-bit keys."),
    Family("ChaCha20", re.compile(r"CHACHA"), QUANTUM_SAFE, "stream-cipher", "No change needed."),
    Family("TLS", re.compile(r"^TLS|^SSL"), REVIEW, "protocol",
           "Use TLS 1.3 only, with a hybrid post-quantum key exchange (X25519MLKEM768)."),
    Family("HMAC", re.compile(r"HMAC"), QUANTUM_SAFE, "mac", "No change needed with a SHA-2 or SHA-3 hash."),
    Family("KDF", re.compile(r"PBKDF|HKDF|SCRYPT|ARGON|BCRYPT"), QUANTUM_SAFE, "kdf", "No change needed."),
    Family("Random", re.compile(r"PRNG|DRBG|RANDOM"), REVIEW, "drbg",
           "Check that a cryptographically secure generator is used."),
]

_KEY_SIZE = re.compile(r"(?<!\d)(512|768|1024|1536|2048|3072|4096|7680|8192|15360)(?!\d)")
_AES_SIZE = re.compile(r"(?<!\d)(128|192|256)(?!\d)")
_MODE = re.compile(r"(?<![A-Z])(ECB|CBC|GCM|CTR|CCM|CFB|OFB|XTS|SIV)(?![A-Z])")
_TLS_VERSION = re.compile(r"(?:TLS|SSL)-?V?-?(\d(?:\.\d)?)")


@dataclass
class Classified:
    family: str
    risk: str
    primitive: str
    recommendation: str
    key_size: Optional[int] = None
    mode: Optional[str] = None
    notes: list = field(default_factory=list)


def normalize(name: str) -> str:
    return re.sub(r"[_\s/]+", "-", name.strip().upper())


def classify(name: str, key_size: Optional[int] = None, mode: Optional[str] = None,
             version: Optional[str] = None) -> Classified:
    """Classify an algorithm or protocol name as a scanner wrote it.

    key_size, mode and version are what the scanner recorded beside the name,
    such as CBOMkit's parameterSetIdentifier or a protocol's version; values
    written into the name itself, as in RSA-1024 or AES-128-ECB, are read from
    the name when they are not given.
    """
    norm = normalize(name)
    family = next((f for f in FAMILIES if f.pattern.search(norm)), None)
    if family is None:
        return Classified("Other", REVIEW, "other", "Review by hand: the scanners do not name a known algorithm.")

    result = Classified(family.name, family.risk, family.primitive, family.recommendation,
                        key_size=key_size, mode=mode.upper() if mode else None)

    if result.mode is None:
        m = _MODE.search(norm)
        if m:
            result.mode = m.group(1)

    if family.name == "AES":
        if result.key_size is None:
            m = _AES_SIZE.search(norm)
            if m:
                result.key_size = int(m.group(1))
        if result.key_size == 256:
            result.risk, result.recommendation = QUANTUM_SAFE, "No change needed."
        elif result.key_size is None:
            result.risk, result.recommendation = REVIEW, "Key size not found; use 256-bit keys."
        if result.mode == "ECB":
            result.risk = BROKEN
            result.notes.append("ECB mode leaks plaintext patterns; use GCM.")
            result.recommendation = "Use AES-256-GCM: ECB mode leaks plaintext patterns."
    elif family.name in ("RSA", "DSA", "DH") and result.key_size is None:
        m = _KEY_SIZE.search(norm)
        if m:
            result.key_size = int(m.group(1))
    elif family.name == "TLS":
        m = _TLS_VERSION.search(norm)
        tls = version or (m.group(1) if m else None)
        if tls and "." not in tls:
            tls += ".0"
        ssl = norm.startswith("SSL")
        if ssl or tls in ("1.0", "1.1"):
            result.risk = BROKEN
        if tls:
            result.family = f"{'SSL' if ssl else 'TLS'} {tls}"
        if result.risk == BROKEN:
            result.recommendation = "Disable this protocol version now; " + family.recommendation[0].lower() + family.recommendation[1:]

    if family.name in ("RSA", "DSA", "DH") and result.key_size is not None and result.key_size < 2048:
        result.risk = BROKEN
        result.notes.append(f"{result.key_size}-bit keys are below the 2048-bit minimum (NIST SP 800-131A).")

    return result


# CryptoScan certificate heuristics that match ordinary words rather than
# cryptography: "Certificate Expiration Check" matches "expires", "Subject
# Alternative Name" matches "ip:", "Certificate Signature Algorithm" matches a
# JWT library's SignatureAlgorithm. On OWASP Juice Shop they were 299 of 354
# findings, most in translation files. They name no algorithm, so an
# inventory leaves them out.
NOISE = {
    "Certificate Expiration Check",
    "Subject Alternative Name",
    "Certificate Signature Algorithm",
    "X.509 Certificate Parsing",
    "Certificate Revocation Check",
    "Certificate Chain",
}


def is_noise(name: str) -> bool:
    return name in NOISE


def is_library_entry(name: str) -> bool:
    """CryptoScan names a crypto library dependency by the algorithms it offers,
    as in "RSA, ECC, AES, DES, 3DES"; that is a library, not a use."""
    return "," in name
