"""Command-line interface for the phishing URL analyzer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .analyzer import AnalysisResult, analyze_url


def _print_text(result: AnalysisResult) -> None:
    print(f"\nURL:   {result.url}")
    print(f"Host:  {result.hostname}")
    print(f"Risk:  {result.risk} ({result.score}/100)")
    if result.findings:
        print("Why:")
        for finding in result.findings:
            print(f"  +{finding.points:>2}  {finding.explanation}")
    else:
        print("Why:   No suspicious patterns were detected.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Score URLs for common phishing indicators without opening them.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--url", help="one URL to analyze")
    source.add_argument("--file", type=Path, help="text file containing one URL per line")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args()

    urls = [args.url] if args.url else [
        line.strip() for line in args.file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    try:
        results = [analyze_url(url) for url in urls]
    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([result.to_dict() for result in results], indent=2))
    else:
        for result in results:
            _print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
