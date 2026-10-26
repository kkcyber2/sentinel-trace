"""Command-line interface.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel_trace import __version__
from sentinel_trace.corpus import load_corpus, run_corpus
from sentinel_trace.model import SchemaError
from sentinel_trace.replay import replay
from sentinel_trace.report_html import render_html
from sentinel_trace.schema import load_trace


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel-trace",
        description="Agent execution security: authority replay and hijack-path reconstruction.",
    )
    p.add_argument("--version", action="version", version=f"sentinel-trace {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("replay", help="assess a single agent trace")
    r.add_argument("trace", help="path to the trace JSON document")
    r.add_argument("--out", help="write the JSON assessment to this path")
    r.add_argument("--html", help="write a self-contained HTML report to this path")
    r.add_argument("--quiet", action="store_true", help="suppress the console summary")
    r.add_argument(
        "--fail-on",
        choices=["never", "warn", "fail"],
        default="fail",
        help="exit non-zero at or above this verdict (default: fail)",
    )

    c = sub.add_parser("corpus", help="run the adversarial corpus as a CI gate")
    c.add_argument("directory", help="directory of corpus case files")
    c.add_argument("--out", help="write the JSON corpus report to this path")

    v = sub.add_parser("validate", help="validate a trace without assessing it")
    v.add_argument("trace")
    return p


def _write(path: Path, text: str) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _verdict_exit(verdict: str, fail_on: str) -> int:
    rank = {"pass": 0, "warn": 1, "fail": 2}
    threshold = {"never": 99, "warn": 1, "fail": 2}[fail_on]
    return 1 if rank.get(verdict, 2) >= threshold else 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "corpus":
        try:
            cases = load_corpus(args.directory)
            report = run_corpus(cases)
        except SchemaError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        payload = report.to_dict()
        if args.out:
            try:
                _write(Path(args.out), json.dumps(payload, indent=2))
            except OSError as exc:
                print(f"error: cannot write report: {exc}", file=sys.stderr)
                return 3
        print(f"corpus: {report.passed}/{report.total} passed")
        for r in report.results:
            if not r.passed:
                print(f"  FAIL {r.name}: {'; '.join(r.failures)}")
        return 0 if report.ok else 1

    try:
        trace = load_trace(args.trace)
    except SchemaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "validate":
        issues = trace.validate()
        if issues:
            print("valid with warnings:")
            for i in issues:
                print(f"  - {i}")
        else:
            print("valid: no structural issues found")
        return 0

    # replay
    assessment = replay(trace)
    payload = assessment.to_dict()

    try:
        if args.out:
            _write(Path(args.out), json.dumps(payload, indent=2))
        if args.html:
            _write(Path(args.html), render_html(payload))
    except OSError as exc:
        print(f"error: cannot write report: {exc}", file=sys.stderr)
        return 3

    if not args.quiet:
        s = payload["summary"]
        print(f"Sentinel Trace {__version__} — {args.trace}")
        print(f"  events            {s['events']}")
        print(f"  violations        {s['violations']}")
        print(f"  tainted spans     {s['tainted_spans']}")
        print(f"  injection paths   {s['injection_paths']}")
        print(f"  authority exceeded {s['authority_exceeded']}/100")
        print(f"  max blast radius  {s['max_blast_radius']}/100")
        print(f"  risk score        {s['risk_score']}/100  [{s['severity']}]")
        print(f"  verdict           {s['verdict'].upper()}")
        if payload["violations"]:
            print("\n  top violations")
            for v in payload["violations"][:5]:
                print(f"   - {v['kind']}: {v['detail']}")
        if payload["injection_paths"]:
            print("\n  injection paths")
            for p in payload["injection_paths"][:3]:
                print(
                    f"   - {p['source_label']} -> {p['sink_label']} "
                    f"({p['length']} hops)"
                )
        if assessment.warnings:
            print("\n  warnings")
            for w in assessment.warnings:
                print(f"   - {w}")
        if args.out or args.html:
            print()
            if args.out:
                print(f"  json written: {args.out}")
            if args.html:
                print(f"  html written: {args.html}")

    return _verdict_exit(assessment.verdict, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
