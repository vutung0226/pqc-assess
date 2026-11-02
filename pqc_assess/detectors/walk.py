"""Walk a customer's target without leaving it.

The target is untrusted input. A symbolic link in it can point anywhere on the
machine that runs the scan, so the walk neither follows nor opens links, the
mistake CryptoScan made; and a file is read only up to a size limit.
"""

import os
from typing import Iterator, Tuple

MAX_FILE_BYTES = 512 * 1024 * 1024
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__"}


def files(root: str) -> Iterator[Tuple[str, str]]:
    """Yield (path, path relative to root) for each regular file under root,
    or root itself when it is a file."""
    if os.path.isfile(root) and not os.path.islink(root):
        yield root, os.path.basename(root)
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not os.path.isfile(path) or os.path.islink(path) or st.st_size > MAX_FILE_BYTES:
                continue
            yield path, os.path.relpath(path, root).replace(os.sep, "/")


def head(path: str, n: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)
