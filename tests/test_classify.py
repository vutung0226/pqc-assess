import unittest

from pqc_assess.classify import (BROKEN, QUANTUM_SAFE, QUANTUM_VULNERABLE, REVIEW, WEAKENED,
                                 classify, is_library_entry)


class ClassifyTest(unittest.TestCase):
    def check(self, name, family, risk, **kwargs):
        c = classify(name, **kwargs)
        self.assertEqual((c.family, c.risk), (family, risk), f"classify({name!r})")
        return c

    def test_each_scanner_name_reaches_one_family(self):
        # The names CryptoScan, CBOMkit, qryx and the JCA use for the same things.
        for name in ("ECDSA", "ECDSA-secp256r1", "ECDSA-SHA-256", "SHA256withECDSA"):
            self.check(name, "ECDSA", QUANTUM_VULNERABLE)
        for name in ("RSA", "RSA-2048", "SHA256withRSA", "RSA/ECB/OAEPPadding"):
            self.check(name, "RSA", QUANTUM_VULNERABLE)
        for name in ("3DES", "DESede", "DES3", "DES-CBC3", "TripleDES", "EVP_des_ede3_cbc"):
            self.check(name, "3DES", BROKEN)
        for name in ("EC", "ECC", "EC-secp256r1", "secp384r1"):
            self.check(name, "EC", QUANTUM_VULNERABLE)

    def test_pqc_names_are_not_read_as_their_classical_parts(self):
        self.check("ML-DSA-65", "ML-DSA", QUANTUM_SAFE)
        self.check("ML-KEM-768", "ML-KEM", QUANTUM_SAFE)
        self.check("X25519MLKEM768", "Hybrid PQC", QUANTUM_SAFE)
        self.check("SHA256withDSA", "DSA", QUANTUM_VULNERABLE)

    def test_aes_risk_follows_key_size_and_mode(self):
        self.check("AES-256-GCM", "AES", QUANTUM_SAFE)
        self.check("AES-128-CBC", "AES", WEAKENED)
        self.check("AES", "AES", REVIEW)
        self.check("AES", "AES", QUANTUM_SAFE, key_size=256)
        c = self.check("AES/ECB/PKCS5Padding", "AES", BROKEN)
        self.assertEqual(c.mode, "ECB")
        self.check("EVP_aes_256_gcm", "AES", QUANTUM_SAFE)

    def test_short_rsa_keys_are_broken_today(self):
        self.check("RSA-1024", "RSA", BROKEN)
        self.check("RSA", "RSA", BROKEN, key_size=1024)
        self.check("RSA", "RSA", QUANTUM_VULNERABLE, key_size=3072)

    def test_tls_versions(self):
        for name in ("TLS 1.0", "TLSv1", "TLSv1.1", "SSLv3"):
            self.assertEqual(classify(name).risk, BROKEN, name)
        self.assertEqual(classify("TLS", version="1.1").family, "TLS 1.1")
        self.assertEqual(classify("TLS 1.2").risk, REVIEW)
        self.assertEqual(classify("TLSv1.2").family, "TLS 1.2")

    def test_hashes(self):
        self.check("MD5", "MD5", BROKEN)
        self.check("SHA-1", "SHA-1", BROKEN)
        self.check("SHA1", "SHA-1", BROKEN)
        self.check("SHA-256", "SHA-2", QUANTUM_SAFE)
        self.check("SHA3-256", "SHA-3", QUANTUM_SAFE)

    def test_unknown_name_needs_review(self):
        self.check("FrobnicateCipher", "Other", REVIEW)

    def test_cryptoscan_library_entries(self):
        self.assertTrue(is_library_entry("RSA, ECC, AES, DES, 3DES"))
        self.assertFalse(is_library_entry("RSA-2048"))


if __name__ == "__main__":
    unittest.main()
