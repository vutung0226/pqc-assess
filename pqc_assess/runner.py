"""Run the upstream scanners, each in a locked-down container.

The target is a customer's code, and the scanners are third-party programs
that read it. Each runs with no network, no Linux capabilities, the target
mounted read-only, and the host user's uid so it can write nothing but its
report. A scanner cannot send the customer's code anywhere, and a scanner bug
such as CryptoScan's symlink one cannot reach files outside the mount.
"""

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 3600


def lock() -> dict:
    with open(os.path.join(ROOT, "tools.lock.json"), encoding="utf-8") as f:
        return json.load(f)


def sandbox() -> list:
    return ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "6g",
            "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:exec", "-e", "HOME=/tmp"]


@dataclass
class Result:
    tool: str
    cbom: Optional[str]
    status: str
    extra: Optional[str] = None  # a second report of the same tool, such as CryptoScan's issues


def _run(cmd: list, log: str, stdout_path: Optional[str] = None) -> int:
    with open(log, "w", encoding="utf-8") as err:
        out = open(stdout_path, "w", encoding="utf-8") if stdout_path else err
        try:
            return subprocess.run(cmd, stdout=out, stderr=err, timeout=TIMEOUT).returncode
        except subprocess.TimeoutExpired:
            return -1
        finally:
            if stdout_path:
                out.close()


def _ok(tool: str, path: str, code: int, ok_codes=(0,)) -> Result:
    if code == -1:
        return Result(tool, None, f"timed out after {TIMEOUT}s")
    if os.path.exists(path) and os.path.getsize(path) > 0 and code in ok_codes:
        return Result(tool, path, "ok")
    return Result(tool, None, f"failed (exit {code}, see raw/{tool}.log)")


def run_cryptoscan(target: str, raw: str) -> Result:
    image = lock()["cryptoscan"]["image"]
    results = {}
    # The CBOM holds the algorithms; the JSON report also holds what is not
    # an algorithm, such as certificate validation turned off.
    for fmt, name in (("cbom", "cryptoscan.cbom.json"), ("json", "cryptoscan.issues.json")):
        # --no-config: a .cryptoscan.yaml in the customer's tree must not hide
        # findings. --include-quantum-safe: an inventory lists AES and SHA-2 too.
        cmd = sandbox() + ["-v", f"{target}:/scan:ro", "-v", f"{raw}:/out", image,
                           "scan", "/scan", "--format", fmt, "--output", f"/out/{name}",
                           "--no-config", "--include-quantum-safe", "--no-color"]
        code = _run(cmd, os.path.join(raw, f"cryptoscan-{fmt}.log"))
        # Exit 1 means a CRITICAL finding, which is what a scan of weak crypto finds.
        results[fmt] = _ok("cryptoscan", os.path.join(raw, name), code, ok_codes=(0, 1))
    result = results["cbom"]
    result.extra = results["json"].cbom
    return result


def run_cbomkit(target: str, raw: str) -> Result:
    image = lock()["cbomkit"]["image"]
    work = os.path.join(raw, "cbomkit")
    os.makedirs(work, exist_ok=True)
    open(os.path.join(work, "gh_output"), "w").close()
    cmd = sandbox() + ["-v", f"{target}:/github/workspace:ro", "-v", f"{work}:/out",
                       "-e", "GITHUB_WORKSPACE=/github/workspace", "-e", "GITHUB_OUTPUT=/out/gh_output",
                       "-e", "CBOMKIT_OUTPUT_DIR=/out", "-e", "CBOMKIT_JAVA_REQUIRE_BUILD=false",
                       "-e", "CBOMKIT_EXCLUDE=", "-e", "CBOMKIT_GENERATE_MODULE_CBOMS=false", image]
    code = _run(cmd, os.path.join(raw, "cbomkit.log"))
    out = os.path.join(raw, "cbomkit.cbom.json")
    produced = os.path.join(work, "cbom.json")
    if os.path.exists(produced):
        shutil.move(produced, out)
    return _ok("cbomkit", out, code)


def run_qryx(target: str, raw: str) -> list:
    image = lock()["qryx"]["image"]
    results = []
    for tool, sub in (("qryx", "scan"), ("qryx-bin", "bin")):
        out = os.path.join(raw, f"{tool}.cbom.json")
        cmd = sandbox() + ["-v", f"{target}:/scan:ro", image, sub, "--format", "cbom", "/scan"]
        code = _run(cmd, os.path.join(raw, f"{tool}.log"), stdout_path=out)
        results.append(_ok(tool, out, code, ok_codes=(0, 1, 2)))
    return results


def build_images(log=print) -> bool:
    """Build CryptoScan and qryx from the pinned sources and pull CBOMkit."""
    cfg = lock()
    steps = [
        ["docker", "build", "-q", "-f", os.path.join(ROOT, cfg["cryptoscan"]["dockerfile"]),
         "--build-arg", f"REPO={cfg['cryptoscan']['repo']}",
         "--build-arg", f"COMMIT={cfg['cryptoscan']['commit']}",
         "-t", cfg["cryptoscan"]["image"], ROOT],
        ["docker", "build", "-q", "-f", os.path.join(ROOT, cfg["qryx"]["dockerfile"]),
         "--build-arg", f"MODULE={cfg['qryx']['module']}",
         "--build-arg", f"VERSION={cfg['qryx']['version']}",
         "-t", cfg["qryx"]["image"], os.path.join(ROOT, "docker")],
        ["docker", "pull", "-q", cfg["cbomkit"]["image"]],
    ]
    for step in steps:
        log("$ " + " ".join(step))
        if subprocess.run(step).returncode != 0:
            return False
    return True


def stage(target: str) -> str:
    """Copy the target to a private directory, without its symbolic links, so
    that the containers mount a tree whose every file is inside it."""
    dest = tempfile.mkdtemp(prefix="pqc-assess-")
    shutil.copytree(target, os.path.join(dest, "t"), symlinks=True,
                    ignore=lambda d, names: [n for n in names if os.path.islink(os.path.join(d, n))])
    return os.path.join(dest, "t")
