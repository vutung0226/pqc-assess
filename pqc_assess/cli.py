"""pqc-assess command line.

  python3 -m pqc_assess build                  build and pull the scanner images
  python3 -m pqc_assess scan TARGET -o OUT     scan a folder, write OUT/report.md
  python3 -m pqc_assess merge -o OUT A.cbom.json B.cbom.json ...
"""

import argparse
import json
import os
import shutil
import sys

from . import cbom, merge, report, runner
from .detectors import gobinary, jar

DOCKER_TOOLS = ("cryptoscan", "cbomkit", "qryx")
LOCAL_TOOLS = ("jar", "gobin")


def _write_outputs(out: str, target: str, inputs: list, status: dict) -> dict:
    findings = merge.load_all(inputs)
    merged, libraries = merge.merge(findings)
    coverage = merge.tool_coverage(merged)
    cbom.write(merge.to_cbom(merged, libraries), os.path.join(out, "cbom.json"))
    with open(os.path.join(out, "findings.json"), "w", encoding="utf-8") as f:
        json.dump([m.to_dict() for m in merged], f, indent=2)
        f.write("\n")
    with open(os.path.join(out, "report.md"), "w", encoding="utf-8") as f:
        f.write(report.render(target, merged, libraries, coverage, status))
    return {"findings": len(merged), "libraries": len(libraries)}


def cmd_scan(args) -> int:
    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"pqc-assess: {target} is not a directory", file=sys.stderr)
        return 2
    out = os.path.abspath(args.output)
    raw = os.path.join(out, "raw")
    os.makedirs(raw, exist_ok=True)
    tools = args.tools.split(",") if args.tools else list(DOCKER_TOOLS + LOCAL_TOOLS)

    staged = runner.stage(target)
    inputs, status = [], {}
    try:
        results = []
        if "cryptoscan" in tools:
            results.append(runner.run_cryptoscan(staged, raw))
        if "cbomkit" in tools:
            results.append(runner.run_cbomkit(staged, raw))
        if "qryx" in tools:
            results.extend(runner.run_qryx(staged, raw))
        for name, mod in (("jar", jar), ("gobin", gobinary)):
            if name in tools:
                path = os.path.join(raw, f"{mod.TOOL}.cbom.json")
                cbom.write(mod.scan(staged), path)
                results.append(runner.Result(mod.TOOL, path, "ok"))
    finally:
        shutil.rmtree(os.path.dirname(staged), ignore_errors=True)

    for r in results:
        status[r.tool] = r.status
        for path in (r.cbom, r.extra):
            if path:
                inputs.append((r.tool, path))
        print(f"  {r.tool:16} {r.status}")
    # The folder's name only: a report handed to the customer must not carry
    # paths of the machine that ran the scan.
    counts = _write_outputs(out, os.path.basename(target), inputs, status)
    print(f"\n{counts['findings']} findings, {counts['libraries']} libraries")
    print(f"Report: {os.path.join(out, 'report.md')}")
    return 0 if all(r.status == "ok" for r in results) else 1


def cmd_merge(args) -> int:
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=True)
    inputs = [(os.path.basename(p).split(".")[0], p) for p in args.cboms]
    counts = _write_outputs(out, args.target or "(merged CBOMs)", inputs, {t: "ok" for t, _ in inputs})
    print(f"{counts['findings']} findings, {counts['libraries']} libraries; report: {os.path.join(out, 'report.md')}")
    return 0


def cmd_build(_args) -> int:
    return 0 if runner.build_images() else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pqc-assess", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a folder with every scanner and merge the results")
    s.add_argument("target")
    s.add_argument("-o", "--output", required=True, help="directory for report.md, cbom.json, findings.json")
    s.add_argument("--tools", help=f"comma-separated subset of {','.join(DOCKER_TOOLS + LOCAL_TOOLS)}")
    s.set_defaults(func=cmd_scan)

    m = sub.add_parser("merge", help="merge CBOM files; each file's tool is its name before the first dot")
    m.add_argument("cboms", nargs="+")
    m.add_argument("-o", "--output", required=True)
    m.add_argument("--target", help="name to print in the report")
    m.set_defaults(func=cmd_merge)

    b = sub.add_parser("build", help="build CryptoScan and qryx images from tools.lock.json and pull CBOMkit")
    b.set_defaults(func=cmd_build)

    args = p.parse_args(argv)
    return args.func(args)
