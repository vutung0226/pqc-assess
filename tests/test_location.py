import unittest

from pqc_assess.location import CODE, TEST, TEXT, kind


class LocationTest(unittest.TestCase):
    def test_kinds(self):
        cases = {
            "lib/insecurity.ts": CODE,
            "src/main/java/org/x/CryptoUtil.java": CODE,
            "config/fbctf.yml": CODE,
            "infrastructure/terraform/networking.tf": CODE,
            "test/api/checkKeys.test.ts": TEST,
            "frontend/src/app/login.component.spec.ts": TEST,
            "src/test/java/org/x/MD5Test.java": TEST,
            "src/it/java/org/x/CryptoIntegrationTest.java": TEST,
            "pkg/scanner/scanner_test.go": TEST,
            "data/static/i18n/zh_CN.json": TEXT,
            "data/static/challenges.yml": TEXT,
            "docs/crypto.md": TEXT,
            "README.adoc": TEXT,
            "dist/app.jar!/Auth.class": CODE,
            None: CODE,
        }
        for path, want in cases.items():
            self.assertEqual(kind(path), want, path)


if __name__ == "__main__":
    unittest.main()
