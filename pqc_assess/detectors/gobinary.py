"""Find cryptography in compiled Go binaries, stripped ones included.

Go links its packages statically, so a binary that uses crypto/rsa holds the
package's code but no shared-library import that a binary scanner such as
qryx's could see. Stripping (-ldflags="-s -w") removes the symbol table but
not the runtime's function table (pclntab), which keeps every linked
function's full name, such as crypto/rsa.GenerateKey; and the build info
lists the modules the binary was built with.

The linker drops functions nothing calls, so a function name in the binary
means some code calls it. It may be the standard library calling it rather
than the application: crypto/tls links crypto/rsa and crypto/ecdsa to verify
certificates. The finding names the functions it saw, so a reviewer can tell
GenerateKey, which only an application calls, from the verification paths.
"""

import mmap
import re

from ..cbom import Collector
from . import walk

TOOL = "pqc-assess-gobin"

BUILDINFO_MAGIC = b"\xff Go buildinf:"
EXEC_MAGICS = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
               b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

# Package path to the family name classify() understands. crypto/des holds DES
# and 3DES, told apart by the constructor.
PACKAGES = {
    "crypto/rsa": "RSA",
    "crypto/des": "DES",
    "crypto/ecdsa": "ECDSA",
    "crypto/ecdh": "ECDH",
    "crypto/ed25519": "Ed25519",
    "crypto/dsa": "DSA",
    "crypto/rc4": "RC4",
    "crypto/md5": "MD5",
    "crypto/sha1": "SHA-1",
    "crypto/aes": "AES",
    "crypto/mlkem": "ML-KEM",
    "crypto/elliptic": "EC",
    "crypto/tls": "TLS",
    "golang.org/x/crypto/blowfish": "Blowfish",
    "golang.org/x/crypto/md4": "MD4",
    "golang.org/x/crypto/curve25519": "X25519",
    "golang.org/x/crypto/ed25519": "Ed25519",
    "golang.org/x/crypto/chacha20poly1305": "ChaCha20-Poly1305",
    "github.com/cloudflare/circl/kem/mlkem": "ML-KEM",
    "github.com/cloudflare/circl/sign/mldsa": "ML-DSA",
}
_SYMBOL = re.compile(
    rb"(crypto/[a-z0-9]+|golang\.org/x/crypto/[a-z0-9]+|github\.com/cloudflare/circl/(?:kem|sign)/[a-z0-9]+)"
    rb"\.((?:\(\*?[A-Za-z0-9_]+\)\.)?[A-Za-z_][A-Za-z0-9_]*)")
_GO_VERSION = re.compile(rb"go1\.\d+(?:\.\d+)?")
_DEP = re.compile(rb"\ndep\t([^\t\n]+)\t([^\t\n]+)")
CRYPTO_MODULES = ("golang.org/x/crypto", "github.com/cloudflare/circl", "filippo.io/",
                  "github.com/ProtonMail/go-crypto", "github.com/open-quantum-safe/")


def _is_executable(path: str) -> bool:
    try:
        return walk.head(path, 4).startswith(EXEC_MAGICS)
    except OSError:
        return False


def scan_binary(path: str, location: str, out: Collector) -> bool:
    """Add the binary's crypto packages to out; False when it is not Go."""
    with open(path, "rb") as f:
        try:
            data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except ValueError:  # empty file
            return False
        with data:
            info = data.find(BUILDINFO_MAGIC)
            if info < 0:
                return False
            version = _GO_VERSION.search(data, info, info + 65536)
            go = version.group(0).decode() if version else "go"

            functions = {}
            for m in _SYMBOL.finditer(data):
                pkg = m.group(1).decode()
                if pkg in PACKAGES:
                    functions.setdefault(pkg, set()).add(m.group(2).decode())

            deps = [(p.decode(), v.decode()) for p, v in _DEP.findall(data, info, info + (1 << 20))]

    for pkg, names in sorted(functions.items()):
        if pkg == "crypto/des":
            continue
        family = PACKAGES[pkg]
        exported = sorted(n for n in names if n[:1].isupper() or n.startswith("(*"))
        shown = ", ".join(exported[:8]) or ", ".join(sorted(names)[:8])
        out.add(family, "other", location, None, f"{go} binary links {pkg}: {shown}")

    for name in functions.get("crypto/des", ()):
        if name == "NewTripleDESCipher":
            out.add("3DES", "block-cipher", location, None, f"{go} binary links crypto/des.NewTripleDESCipher")
        elif name == "NewCipher":
            out.add("DES", "block-cipher", location, None, f"{go} binary links crypto/des.NewCipher")

    for mod, ver in deps:
        if mod.startswith(CRYPTO_MODULES):
            out.add_library(f"{mod} {ver}", location)
    return True


def scan(root: str) -> dict:
    out = Collector(TOOL)
    for path, rel in walk.files(root):
        if _is_executable(path):
            scan_binary(path, rel, out)
    return out.document()
