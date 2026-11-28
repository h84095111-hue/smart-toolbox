"""Command-line entry point for passive Smart Intel collection.

Usage: python -m smartintel.cli example.org
Only existing passive collectors are invoked. This command does not perform
port scans, login attempts, exploitation, or private-account access.
"""
from __future__ import annotations
import argparse
import json
import sys
from .collectors.all_in_one import run_all

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smart Intel passive OSINT collector")
    parser.add_argument("target", help="Domain, public IP, URL, username, or email")
    parser.add_argument("--misp-url", default="", help="Optional MISP HTTPS base URL")
    parser.add_argument("--output", help="Write JSON results to this file instead of stdout")
    args = parser.parse_args(argv)
    try:
        result = run_all(args.target, args.misp_url)
        payload = json.dumps(result, ensure_ascii=False, indent=2)
        if args.output:
            from pathlib import Path
            Path(args.output).write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
        return 1 if result.get("failures") and not result.get("findings") else 0
    except (ValueError, OSError) as exc:
        print(f"smart-intel: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
