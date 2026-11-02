"""Read one line of the scanned tree, to check what a pattern match matched.

CryptoScan records the word it matched ("sha1"), not the line, and the line
tells a use from a mention: crypto.createHmac('sha1', key) is an HMAC, and
file.endsWith('.md5') is a file name. The tree is untrusted, so a line is
read only from a regular file inside the root, never through a link.
"""

import os
from typing import Optional

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_LINE = 500


class Source:
    def __init__(self, root: Optional[str]):
        self.root = os.path.realpath(root) if root else None
        self._cache = {}

    def line(self, rel: Optional[str], lineno: Optional[int]) -> Optional[str]:
        if not self.root or not rel or not lineno or "!/" in rel:
            return None
        lines = self._lines(rel)
        if lines is None or not 0 < lineno <= len(lines):
            return None
        return lines[lineno - 1].strip()[:MAX_LINE]

    def _lines(self, rel: str):
        if rel in self._cache:
            return self._cache[rel]
        lines = None
        path = os.path.join(self.root, rel)
        real = os.path.realpath(path)
        inside = real == self.root or real.startswith(self.root + os.sep)
        try:
            if inside and not os.path.islink(path) and os.path.isfile(path) \
                    and os.path.getsize(path) <= MAX_FILE_BYTES:
                with open(path, "rb") as f:
                    lines = f.read().decode("utf-8", "replace").split("\n")
        except OSError:
            lines = None
        self._cache[rel] = lines
        return lines
