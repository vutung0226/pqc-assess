"""Find cryptography in compiled Java: .class files and .jar, .war and .ear archives.

The upstream scanners read source only, and customers often hand over a built
application. Bytecode keeps what an inventory needs: a call such as
Cipher.getInstance("AES/ECB/PKCS5Padding") compiles to an ldc of the string
followed by an invokestatic of the method, and KeyPairGenerator.initialize(1024)
to an sipush of the size followed by an invokevirtual. The LineNumberTable
gives each call its source line.

The archive is untrusted input, read without extracting it to disk, with
limits on entry sizes and nesting depth.
"""

import io
import struct
import zipfile
from typing import Optional

from ..cbom import Collector
from . import walk

TOOL = "pqc-assess-jar"

ARCHIVE_EXTS = (".jar", ".war", ".ear")
MAX_CLASS_BYTES = 16 * 1024 * 1024
MAX_NESTED_BYTES = 256 * 1024 * 1024
MAX_DEPTH = 3
MAX_ENTRIES = 500_000

# JCA factory classes: their getInstance(String, ...) names the algorithm.
FACTORIES = {
    "javax/crypto/Cipher": "block-cipher",
    "java/security/KeyPairGenerator": "pke",
    "java/security/Signature": "signature",
    "java/security/MessageDigest": "hash",
    "javax/crypto/KeyGenerator": "block-cipher",
    "javax/crypto/KeyAgreement": "key-agree",
    "javax/crypto/Mac": "mac",
    "java/security/KeyFactory": "pke",
    "javax/crypto/SecretKeyFactory": "kdf",
    "javax/net/ssl/SSLContext": "protocol",
    "java/security/AlgorithmParameterGenerator": "other",
}
# Methods whose int argument is the key size of the preceding getInstance.
SIZE_METHODS = {
    ("java/security/KeyPairGenerator", "initialize"),
    ("javax/crypto/KeyGenerator", "init"),
}
# BouncyCastle light-weight API classes, which name the algorithm themselves.
BOUNCYCASTLE = {
    "engines/AESEngine": "AES", "engines/AESFastEngine": "AES", "engines/AESLightEngine": "AES",
    "engines/RSAEngine": "RSA", "engines/RSABlindedEngine": "RSA",
    "engines/DESedeEngine": "3DES", "engines/DESEngine": "DES", "engines/RC4Engine": "RC4",
    "engines/BlowfishEngine": "Blowfish",
    "signers/ECDSASigner": "ECDSA", "signers/DSASigner": "DSA", "signers/Ed25519Signer": "Ed25519",
    "signers/RSADigestSigner": "RSA", "signers/PSSSigner": "RSA",
    "generators/RSAKeyPairGenerator": "RSA", "generators/ECKeyPairGenerator": "EC",
    "generators/DHKeyPairGenerator": "DH", "generators/DSAKeyPairGenerator": "DSA",
    "agreement/ECDHBasicAgreement": "ECDH", "agreement/X25519Agreement": "X25519",
    "agreement/DHBasicAgreement": "DH",
    "digests/MD5Digest": "MD5", "digests/SHA1Digest": "SHA-1",
}
BOUNCYCASTLE_PQC = {"mlkem": "ML-KEM", "mldsa": "ML-DSA", "slhdsa": "SLH-DSA", "falcon": "FN-DSA"}
# Classes of crypto providers and the JDK are the library's own code, not the
# customer's use of it: scanning BouncyCastle's jar would list every algorithm
# it implements. The jar is reported as a library instead.
PROVIDER_PREFIXES = ("org/bouncycastle/", "java/", "javax/", "sun/", "com/sun/", "jdk/",
                     "org/conscrypt/", "com/google/crypto/tink/")
LIBRARY_JARS = ("bcprov", "bcpkix", "bcutil", "bcfips", "conscrypt", "tink", "jasypt")


class ClassFormatError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes, pos: int = 0):
        self.data, self.pos = data, pos

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ClassFormatError("truncated class file")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def u1(self) -> int:
        return self.take(1)[0]

    def u2(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u4(self) -> int:
        return struct.unpack(">I", self.take(4))[0]


# Total instruction length for the opcodes that are not one byte long;
# tableswitch, lookupswitch and wide are handled in _instructions.
_LEN = {0x10: 2, 0x12: 2, 0xa9: 2, 0xbc: 2, 0x11: 3, 0x13: 3, 0x14: 3, 0x84: 3,
        0xbb: 3, 0xbd: 3, 0xc0: 3, 0xc1: 3, 0xc6: 3, 0xc7: 3, 0xc5: 4,
        0xb9: 5, 0xba: 5, 0xc8: 5, 0xc9: 5}
_LEN.update({op: 2 for op in range(0x15, 0x1a)})  # iload..aload
_LEN.update({op: 2 for op in range(0x36, 0x3b)})  # istore..astore
_LEN.update({op: 3 for op in range(0x99, 0xa9)})  # if*, goto, jsr
_LEN.update({op: 3 for op in range(0xb2, 0xb9)})  # get/put field/static, invoke*


def _instructions(code: bytes):
    """Yield (pc, opcode, operand bytes) for each instruction in code."""
    pc = 0
    while pc < len(code):
        op = code[pc]
        if op in (0xaa, 0xab):  # tableswitch, lookupswitch
            start = pc + 1 + (3 - pc % 4)
            if start + 12 > len(code):
                return
            if op == 0xaa:
                low, high = struct.unpack(">ii", code[start + 4:start + 12])
                length = start - pc + 12 + 4 * (high - low + 1)
            else:
                npairs = struct.unpack(">i", code[start + 4:start + 8])[0]
                length = start - pc + 8 + 8 * npairs
        elif op == 0xc4:  # wide
            length = 6 if pc + 1 < len(code) and code[pc + 1] == 0x84 else 4
        else:
            length = _LEN.get(op, 1)
        if length <= 0:
            return
        yield pc, op, code[pc + 1:pc + length]
        pc += length


class ClassFile:
    def __init__(self, data: bytes):
        if data[:4] != b"\xca\xfe\xba\xbe":
            raise ClassFormatError("not a class file")
        r = _Reader(data, 8)
        count = r.u2()
        cp = [None] * count
        i = 1
        while i < count:
            tag = r.u1()
            if tag == 1:
                cp[i] = ("utf8", r.take(r.u2()).decode("utf-8", "replace"))
            elif tag == 3:
                cp[i] = ("int", struct.unpack(">i", r.take(4))[0])
            elif tag == 4:
                cp[i] = ("float", r.take(4))
            elif tag in (5, 6):
                cp[i] = ("wide", r.take(8))
                i += 1
            elif tag in (7, 8, 16, 19, 20):
                cp[i] = ({7: "class", 8: "string"}.get(tag, "other"), r.u2())
            elif tag in (9, 10, 11, 12, 17, 18):
                cp[i] = ({9: "ref", 10: "ref", 11: "ref", 12: "nat"}.get(tag, "other"), r.u2(), r.u2())
            elif tag == 15:
                cp[i] = ("other", r.u1(), r.u2())
            else:
                raise ClassFormatError(f"unknown constant pool tag {tag}")
            i += 1
        self.cp = cp
        r.take(2)
        self.name = self.class_name(r.u2()) or "?"
        r.take(2)
        r.take(2 * r.u2())
        for _ in range(r.u2()):
            r.take(6)
            self._skip_attributes(r)
        self.methods = []
        for _ in range(r.u2()):
            r.take(2)
            method_name = self.utf8(r.u2())
            r.take(2)
            code, lines = None, []
            for _ in range(r.u2()):
                attr = self.utf8(r.u2())
                body = r.take(r.u4())
                if attr == "Code":
                    code, lines = self._code(body)
            if code:
                self.methods.append((method_name, code, sorted(lines)))
        self.source_file = None
        for _ in range(r.u2()):
            attr = self.utf8(r.u2())
            body = r.take(r.u4())
            if attr == "SourceFile" and len(body) == 2:
                self.source_file = self.utf8(struct.unpack(">H", body)[0])

    def _skip_attributes(self, r: _Reader):
        for _ in range(r.u2()):
            r.take(2)
            r.take(r.u4())

    def _code(self, body: bytes):
        r = _Reader(body)
        r.take(4)
        code = r.take(r.u4())
        r.take(8 * r.u2())
        lines = []
        for _ in range(r.u2()):
            attr = self.utf8(r.u2())
            sub = _Reader(r.take(r.u4()))
            if attr == "LineNumberTable":
                for _ in range(sub.u2()):
                    lines.append((sub.u2(), sub.u2()))
        return code, lines

    def utf8(self, idx: int) -> Optional[str]:
        e = self.cp[idx] if 0 < idx < len(self.cp) else None
        return e[1] if e and e[0] == "utf8" else None

    def class_name(self, idx: int) -> Optional[str]:
        e = self.cp[idx] if 0 < idx < len(self.cp) else None
        return self.utf8(e[1]) if e and e[0] == "class" else None

    def string(self, idx: int) -> Optional[str]:
        e = self.cp[idx] if 0 < idx < len(self.cp) else None
        return self.utf8(e[1]) if e and e[0] == "string" else None

    def int_const(self, idx: int) -> Optional[int]:
        e = self.cp[idx] if 0 < idx < len(self.cp) else None
        return e[1] if e and e[0] == "int" else None

    def method_ref(self, idx: int):
        """Return (owner class, method name) for a Methodref constant."""
        e = self.cp[idx] if 0 < idx < len(self.cp) else None
        if not e or e[0] != "ref":
            return None, None
        nat = self.cp[e[2]] if 0 < e[2] < len(self.cp) else None
        if not nat or nat[0] != "nat":
            return self.class_name(e[1]), None
        return self.class_name(e[1]), self.utf8(nat[1])


def _line(lines, pc: int) -> Optional[int]:
    line = None
    for start, number in lines:
        if start > pc:
            break
        line = number
    return line


def _bouncycastle(owner: str) -> Optional[str]:
    if not owner.startswith("org/bouncycastle/"):
        return None
    for suffix, family in BOUNCYCASTLE.items():
        if owner.endswith("/" + suffix):
            return family
    parts = owner.split("/")
    if len(parts) > 4 and parts[2] == "pqc" and parts[3] == "crypto":
        return BOUNCYCASTLE_PQC.get(parts[4])
    return None


def scan_class(cls: ClassFile, location: str, out: Collector):
    if cls.name.startswith(PROVIDER_PREFIXES):
        return
    source = cls.source_file or cls.name.rsplit("/", 1)[-1] + ".class"
    for method, code, lines in cls.methods:
        strings, ints = [], []  # pushed since the last call
        pending = None  # the last getInstance, waiting for a key size

        def flush(size=None):
            nonlocal pending
            if pending:
                name, primitive, line, ctx = pending
                out.add(name, primitive, location, line, ctx, key_size=size)
                pending = None

        for pc, op, operands in _instructions(code):
            if op == 0x12:
                idx = operands[0]
            elif op == 0x13:
                idx = struct.unpack(">H", operands)[0]
            else:
                idx = None
            if idx is not None:
                s = cls.string(idx)
                if s is not None:
                    strings.append(s)
                else:
                    n = cls.int_const(idx)
                    if n is not None:
                        ints.append(n)
            elif 0x02 <= op <= 0x08:
                ints.append(op - 0x03)
            elif op == 0x10:
                ints.append(struct.unpack(">b", operands)[0])
            elif op == 0x11:
                ints.append(struct.unpack(">h", operands)[0])
            elif op in (0xb6, 0xb7, 0xb8, 0xb9, 0xbb):
                if op == 0xbb:
                    owner, name = cls.class_name(struct.unpack(">H", operands[:2])[0]), "<new>"
                else:
                    owner, name = cls.method_ref(struct.unpack(">H", operands[:2])[0])
                if not owner:
                    continue
                line = _line(lines, pc)
                ctx = f"{source}:{line} {owner.replace('/', '.')}.{name}" if line else f"{owner}.{name}"
                if name == "getInstance" and owner in FACTORIES:
                    flush()
                    if strings:
                        pending = (strings[0], FACTORIES[owner], line, ctx)
                    else:
                        out.add(f"{owner.rsplit('/', 1)[-1]} (algorithm not a constant)",
                                FACTORIES[owner], location, line, ctx)
                elif (owner, name) in SIZE_METHODS:
                    flush(ints[-1] if ints else None)
                else:
                    family = _bouncycastle(owner)
                    if family and name == "<new>":
                        out.add(family, "other", location, line, ctx)
                if name not in ("<init>", "<new>"):
                    strings, ints = [], []
        flush()


def _scan_archive(data_or_path, location: str, out: Collector, depth: int = 1):
    try:
        zf = zipfile.ZipFile(data_or_path)
    except (zipfile.BadZipFile, OSError):
        return
    with zf:
        infos = zf.infolist()[:MAX_ENTRIES]
        for info in infos:
            name = info.filename
            lower = name.lower()
            if lower.endswith(".class") and info.file_size <= MAX_CLASS_BYTES:
                try:
                    cls = ClassFile(zf.read(info))
                except (ClassFormatError, zipfile.BadZipFile, OSError, struct.error, IndexError):
                    continue
                scan_class(cls, f"{location}!/{name}", out)
            elif lower.endswith(ARCHIVE_EXTS) and depth < MAX_DEPTH and info.file_size <= MAX_NESTED_BYTES:
                base = lower.rsplit("/", 1)[-1]
                if base.startswith(LIBRARY_JARS):
                    out.add_library(base, f"{location}!/{name}")
                    continue
                try:
                    nested = io.BytesIO(zf.read(info))
                except (zipfile.BadZipFile, OSError):
                    continue
                _scan_archive(nested, f"{location}!/{name}", out, depth + 1)


def scan(root: str) -> dict:
    """Return a CBOM of the cryptography in the compiled Java under root."""
    out = Collector(TOOL)
    for path, rel in walk.files(root):
        lower = rel.lower()
        if lower.endswith(ARCHIVE_EXTS):
            base = lower.rsplit("/", 1)[-1]
            if base.startswith(LIBRARY_JARS):
                out.add_library(base, rel)
            else:
                _scan_archive(path, rel, out)
        elif lower.endswith(".class"):
            try:
                cls = ClassFile(walk.head(path, MAX_CLASS_BYTES))
            except (ClassFormatError, OSError, struct.error, IndexError):
                continue
            scan_class(cls, rel, out)
    return out.document()
