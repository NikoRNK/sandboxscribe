"""Command line interface.

    sandboxscribe report detonation.json --out report.md --sigma-dir ./sigma
    sandboxscribe report sysmon_export.ndjson --sample-name dropper.js --sample-sha256 <sha>
    sandboxscribe tree detonation.json
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .engine import analyze
from .enrich import MalwareBazaar, VirusTotalHash
from .report import render_iocs_csv, render_json, render_markdown
from .schema import SchemaError, load_report, normalize
from .sysmon import convert, read_rows
from .timeline import process_tree

COLORS = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m"}


def _load(args):
    """Native normalized JSON, or a Sysmon export (auto-detected)."""
    try:
        return load_report(args.input)
    except SchemaError:
        rows = read_rows(args.input)
        sample = {"name": args.sample_name or "", "sha256": args.sample_sha256 or ""}
        return normalize(convert(rows, sample=sample))


def _cmd_report(args) -> int:
    report = _load(args)
    vt = mb = None
    if not args.no_intel:
        vt_key = args.vt_key or os.environ.get("VT_API_KEY")
        mb_key = args.mb_key or os.environ.get("MB_AUTH_KEY")
        vt = VirusTotalHash(vt_key, cache_dir=args.cache) if vt_key else None
        mb = MalwareBazaar(mb_key, cache_dir=args.cache) if mb_key else None
        if not (vt or mb):
            print("[i] No intel keys (VT_API_KEY / MB_AUTH_KEY): offline mode, hash reputation skipped.", file=sys.stderr)
    result = analyze(report, vt=vt, mb=mb, author=args.author)
    md = render_markdown(result)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(render_json(result), encoding="utf-8")
    if args.iocs:
        Path(args.iocs).write_text(render_iocs_csv(result), encoding="utf-8")
    if args.sigma_dir and result["sigma"]:
        d = Path(args.sigma_dir)
        d.mkdir(parents=True, exist_ok=True)
        for name, text in result["sigma"].items():
            (d / name).write_text(text, encoding="utf-8")
    c = COLORS.get(result["verdict"], "") if sys.stdout.isatty() else ""
    reset = "\033[0m" if c else ""
    print(f"{c}[{result['verdict']}]{reset} score={result['score']}/100 confidence={result['confidence']} "
          f"detections={len(result['detections'])} iocs={len(result['ioc_rows'])} sigma_rules={len(result['sigma'])}")
    if not args.out:
        print()
        print(md)
    return 2 if result["verdict"] == "MALICIOUS" else 0


def _cmd_tree(args) -> int:
    print(process_tree(_load(args)))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sandboxscribe",
                                description="Turn sandbox / Sysmon telemetry into a SOC-grade malware report.")
    p.add_argument("--version", action="version", version=f"sandboxscribe {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("input", help="normalized JSON report, or Sysmon export (JSON array / NDJSON)")
        sp.add_argument("--sample-name", help="sample file name (Sysmon input only)")
        sp.add_argument("--sample-sha256", help="sample SHA-256 (Sysmon input only)")

    r = sub.add_parser("report", help="full analysis and report")
    common(r)
    r.add_argument("--out", help="write the Markdown report here")
    r.add_argument("--json", help="write the full result as JSON")
    r.add_argument("--iocs", help="write IOCs as CSV")
    r.add_argument("--sigma-dir", help="write generated Sigma rules into this folder")
    r.add_argument("--author", default="SandboxScribe", help="author field of generated Sigma rules")
    r.add_argument("--no-intel", action="store_true", help="never contact VirusTotal / MalwareBazaar")
    r.add_argument("--vt-key", help="VirusTotal API key (default: $VT_API_KEY)")
    r.add_argument("--mb-key", help="MalwareBazaar Auth-Key (default: $MB_AUTH_KEY)")
    r.add_argument("--cache", default=".intel_cache")
    r.set_defaults(func=_cmd_report)

    t = sub.add_parser("tree", help="print only the process tree")
    common(t)
    t.set_defaults(func=_cmd_tree)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0
    except (SchemaError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
