import json
import os
import tempfile
import unittest

from pqc_assess import cbom, merge
from pqc_assess.cbom import Finding
from pqc_assess.classify import BROKEN, QUANTUM_SAFE, WEAKENED


def F(tool, name, file="a.go", line=4, **kw):
    return Finding(tool=tool, name=name, file=file, line=line, **kw)


class MergeTest(unittest.TestCase):
    def test_same_line_same_family_is_one_finding_with_every_tool(self):
        merged, _ = merge.merge([
            F("cbomkit", "ECDSA-secp256r1", curve="secp256r1"),
            F("qryx", "ECDSA"),
            F("cryptoscan", "ECC"),
        ])
        self.assertEqual(len(merged), 1, [m.to_dict() for m in merged])
        m = merged[0]
        self.assertEqual(m.family, "ECDSA")
        self.assertEqual(m.tools, {"cbomkit", "qryx", "cryptoscan"})
        self.assertEqual(m.curve, "secp256r1")

    def test_generic_ec_kept_where_no_tool_named_the_scheme(self):
        merged, _ = merge.merge([F("cryptoscan", "ECC", line=2), F("qryx", "ECDSA", line=4)])
        self.assertEqual(sorted(m.family for m in merged), ["EC", "ECDSA"])

    def test_details_from_different_tools_combine(self):
        # qryx alone says "AES", which needs review; CBOMkit's key size makes it AES-256.
        merged, _ = merge.merge([F("qryx", "AES"), F("cbomkit", "AES", key_size=256)])
        self.assertEqual(len(merged), 1)
        self.assertEqual((merged[0].key_size, merged[0].risk), (256, QUANTUM_SAFE))

    def test_short_key_from_one_tool_makes_the_finding_broken(self):
        merged, _ = merge.merge([F("cryptoscan", "RSA"), F("cbomkit", "RSA-1024", key_size=1024)])
        self.assertEqual(merged[0].risk, BROKEN)

    def test_key_size_and_mode_read_from_the_matched_text(self):
        merged, _ = merge.merge([F("cryptoscan", "AES", context="aes-128-cbc")])
        self.assertEqual((merged[0].key_size, merged[0].mode, merged[0].risk), (128, "CBC", WEAKENED))

    def test_libraries_are_listed_apart(self):
        merged, libs = merge.merge([
            F("cryptoscan", "RSA, ECC, AES, DES, 3DES", file="requirements.txt", line=1),
            F("qryx", "pycryptodome", file="requirements.txt", line=2, asset_type="library"),
        ])
        self.assertEqual(merged, [])
        self.assertEqual(sorted(lib.name for lib in libs), ["RSA, ECC, AES, DES, 3DES", "pycryptodome"])

    def test_most_urgent_first(self):
        merged, _ = merge.merge([F("q", "SHA-256", line=1), F("q", "MD5", line=2), F("q", "RSA", line=3)])
        self.assertEqual([m.family for m in merged], ["MD5", "RSA", "SHA-2"])

    def test_cbom_groups_occurrences_and_carries_risk(self):
        merged, libs = merge.merge([F("a", "RSA-2048", line=1), F("b", "RSA-2048", file="b.go", line=9)])
        doc = merge.to_cbom(merged, libs)
        self.assertEqual(doc["specVersion"], "1.6")
        (comp,) = doc["components"]
        self.assertEqual(comp["name"], "RSA-2048")
        self.assertEqual(len(comp["evidence"]["occurrences"]), 2)
        props = {p["name"]: p["value"] for p in comp["properties"]}
        self.assertEqual(props["pqc-assess:risk"], "quantum-vulnerable")
        self.assertEqual(props["pqc-assess:tools"], "a,b")


class ReadTest(unittest.TestCase):
    def write(self, doc, name):
        path = os.path.join(self.dir.name, name)
        with open(path, "w") as f:
            json.dump(doc, f)
        return path

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.dir.cleanup()

    def test_null_components(self):
        # qryx bin writes this when it finds nothing.
        path = self.write({"bomFormat": "CycloneDX", "components": None}, "qryx-bin.cbom.json")
        self.assertEqual(cbom.read_findings(path, "qryx-bin"), [])

    def test_mount_prefixes_and_generated_key_names(self):
        path = self.write({"components": [
            {"type": "cryptographic-asset", "name": "RSA-1024",
             "cryptoProperties": {"assetType": "algorithm",
                                  "algorithmProperties": {"primitive": "pke", "parameterSetIdentifier": "1024"}},
             "evidence": {"occurrences": [{"location": "github/workspace/src/Auth.java", "line": 4}]}},
            {"type": "cryptographic-asset", "name": "key@84972f0c-6cb3",
             "cryptoProperties": {"assetType": "related-crypto-material"}},
            {"type": "cryptographic-asset", "name": "TLS",
             "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"version": "1.1"}},
             "evidence": {"occurrences": [{"location": "/scan/nginx.conf", "line": 1}]}},
        ]}, "cbomkit.cbom.json")
        found = cbom.read_findings(path, "cbomkit")
        self.assertEqual([(f.name, f.file, f.line, f.key_size) for f in found],
                         [("RSA-1024", "src/Auth.java", 4, 1024), ("TLS 1.1", "nginx.conf", 1, None)])

    def test_cryptoscan_issues_never_copy_the_matched_text(self):
        secret = "MIIEpAIBAAKCAQEAsecret"
        path = self.write({"findings": [
            {"type": "Certificate Validation Bypass", "category": "Configuration", "severity": "CRITICAL",
             "file": "/scan/server.go", "line": 6, "match": "InsecureSkipVerify: true",
             "remediation": "Enable certificate validation."},
            {"type": "Private Key Header", "category": "Secret Detection", "severity": "CRITICAL",
             "file": "/scan/key.pem", "line": 1, "match": secret,
             "sourceContext": {"lines": [{"content": secret}]}},
            {"type": "RSA Algorithm", "category": "Asymmetric Encryption", "severity": "HIGH",
             "algorithm": "RSA", "file": "/scan/a.go", "line": 3},
        ]}, "cryptoscan.issues.json")
        found = cbom.read_cryptoscan_issues(path)
        self.assertEqual([(f.name, f.file) for f in found],
                         [("Certificate Validation Bypass", "server.go"), ("Private Key Header", "key.pem")])
        merged, _ = merge.merge(found)
        self.assertNotIn(secret, json.dumps([m.to_dict() for m in merged]))
        self.assertTrue(all(m.risk == BROKEN for m in merged))


if __name__ == "__main__":
    unittest.main()
