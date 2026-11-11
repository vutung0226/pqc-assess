import os
import tempfile
import unittest

from pqc_assess.runner import _ok


class StatusTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def _log(self, name, text):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_failure_names_the_log_that_was_written(self):
        log = self._log("cryptoscan-cbom.log", "")
        r = _ok("cryptoscan", os.path.join(self.dir.name, "none.json"), 2, log)
        self.assertIsNone(r.cbom)
        self.assertEqual(r.status, "failed (exit 2, see raw/cryptoscan-cbom.log)")

    def test_docker_errors_say_what_to_do(self):
        cases = {
            "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock\n":
                "usermod -aG docker",
            "Unable to find image 'pqc-assess/qryx:v1.1.1' locally\n": "pqc_assess build",
        }
        for text, fix in cases.items():
            log = self._log("qryx.log", text)
            r = _ok("qryx", os.path.join(self.dir.name, "none.json"), 125, log)
            self.assertIn(fix, r.status, text)

    def test_success_and_timeout(self):
        out = self._log("qryx.cbom.json", "{}")
        self.assertEqual(_ok("qryx", out, 0, out).status, "ok")
        self.assertTrue(_ok("qryx", out, -1, out).status.startswith("timed out"))


if __name__ == "__main__":
    unittest.main()
