import io
import os
import tempfile
import unittest
import zipfile

from pqc_assess.detectors import gobinary, jar, jose, walk

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def occurrences(doc):
    """(name, key size, location, line) for each occurrence in a CBOM."""
    out = []
    for c in doc["components"]:
        size = c.get("cryptoProperties", {}).get("algorithmProperties", {}).get("parameterSetIdentifier")
        for o in c["evidence"]["occurrences"]:
            out.append((c["name"], size, o["location"], o.get("line")))
    return sorted(out, key=lambda t: (t[3] or 0, t[0]))


class JarTest(unittest.TestCase):
    # auth.jar is fixtures/Auth.java compiled with javac 21.
    def test_recovers_each_jca_call_with_its_key_size_and_line(self):
        doc = jar.scan(os.path.join(FIXTURES, "auth.jar"))
        self.assertEqual(occurrences(doc), [
            ("RSA", "1024", "auth.jar!/Auth.class", 4),
            ("AES/ECB/PKCS5Padding", None, "auth.jar!/Auth.class", 5),
            ("SHA256withECDSA", None, "auth.jar!/Auth.class", 6),
            ("DSA", None, "auth.jar!/Auth.class", 7),
            ("SHA-1", None, "auth.jar!/Auth.class", 8),
        ])

    def test_nested_jar_and_library_jars(self):
        with open(os.path.join(FIXTURES, "auth.jar"), "rb") as f:
            inner = f.read()
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("BOOT-INF/lib/auth.jar", inner)
            z.writestr("BOOT-INF/lib/bcprov-jdk18on-1.78.jar", b"not opened")
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "app.jar"), "wb") as f:
                f.write(buf.getvalue())
            doc = jar.scan(d)
        names = {(c["type"], c["name"]) for c in doc["components"]}
        self.assertIn(("library", "bcprov-jdk18on-1.78.jar"), names)
        self.assertIn(("cryptographic-asset", "SHA-1"), names)
        locs = {o["location"] for c in doc["components"] for o in c["evidence"]["occurrences"]}
        self.assertIn("app.jar!/BOOT-INF/lib/auth.jar!/Auth.class", locs)

    def test_garbage_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "x.class"), "wb") as f:
                f.write(b"\xca\xfe\xba\xbe\x00\x00\x00\x41\xff\xff\x01")
            with open(os.path.join(d, "y.jar"), "wb") as f:
                f.write(b"PK not really")
            self.assertEqual(jar.scan(d)["components"], [])


class GoBinaryTest(unittest.TestCase):
    def fake_binary(self, *symbols):
        # The detector reads the build info magic and the pclntab names;
        # a real binary is 2 MB, this holds the same markers.
        body = b"\x7fELF" + b"\x00" * 64 + gobinary.BUILDINFO_MAGIC + b"\x08\x02go1.22.12\n"
        body += b"\ndep\tgolang.org/x/crypto\tv0.17.0\th1:abc\n"
        body += b"\x00".join(symbols) + b"\x00"
        return body

    def test_stripped_binary_names_linked_packages(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "svc"), "wb") as f:
                f.write(self.fake_binary(b"crypto/rsa.GenerateKey", b"crypto/ecdsa.GenerateKey",
                                         b"crypto/des.NewTripleDESCipher", b"runtime.main"))
            doc = gobinary.scan(d)
        names = sorted((c["type"], c["name"]) for c in doc["components"])
        self.assertEqual(names, [("cryptographic-asset", "3DES"), ("cryptographic-asset", "ECDSA"),
                                 ("cryptographic-asset", "RSA"), ("library", "golang.org/x/crypto v0.17.0")])
        rsa = next(c for c in doc["components"] if c["name"] == "RSA")
        self.assertIn("GenerateKey", rsa["evidence"]["occurrences"][0]["additionalContext"])

    def test_non_go_executable_is_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "c-binary"), "wb") as f:
                f.write(b"\x7fELF" + b"\x00" * 64 + b"crypto/rsa.GenerateKey")
            self.assertEqual(gobinary.scan(d)["components"], [])


class WalkTest(unittest.TestCase):
    def test_symbolic_links_are_neither_followed_nor_listed(self):
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as root:
            secret = os.path.join(outside, "id_rsa")
            with open(secret, "w") as f:
                f.write("secret")
            os.makedirs(os.path.join(outside, "dir"))
            with open(os.path.join(root, "real.py"), "w") as f:
                f.write("x")
            os.symlink(secret, os.path.join(root, "innocent.py"))
            os.symlink(os.path.join(outside, "dir"), os.path.join(root, "lib"))
            self.assertEqual([rel for _, rel in walk.files(root)], ["real.py"])


if __name__ == "__main__":
    unittest.main()


class JoseTest(unittest.TestCase):
    def test_signature_algorithm_identifiers(self):
        files = {
            "lib/insecurity.ts": "export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })\n",
            "Auth.java": "Jwts.builder().signWith(key, SignatureAlgorithm.ES384);\nAlgorithm a = Algorithm.RSA256(pub, priv);\n",
            "Token.cs": "new SigningCredentials(key, SecurityAlgorithms.RsaSsaPssSha512);\n",
            "jwks.json": '{"keys": [{"kty": "OKP", "alg": "EdDSA"}]}\n',
            "hmac.js": "jwt.sign(p, secret, { algorithm: 'HS256' })\n",
            "words.txt": "RS256 in a text file is not read\n",
        }
        with tempfile.TemporaryDirectory() as d:
            for name, text in files.items():
                os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
                with open(os.path.join(d, name), "w") as f:
                    f.write(text)
            doc = jose.scan(d)
        self.assertEqual([(n, loc, line) for n, _, loc, line in occurrences(doc)], [
            ("ECDSA (JWT ES384)", "Auth.java", 1),
            ("EdDSA (JWT EdDSA)", "jwks.json", 1),
            ("RSA (JWT PS512)", "Token.cs", 1),
            ("RSA (JWT RS256)", "lib/insecurity.ts", 1),
            ("RSA (JWT RS256)", "Auth.java", 2),
        ])
