#!/usr/bin/env python3
"""CLI entry point for phpDetector.

Two subcommands:
  files  - scan local files/directories for PHP (extension or <?php tag)
  urls   - fingerprint a URL (or a file of URLs) for an exposed PHP
           backend / CMS, and cross-check against known CVEs

`urls` sends ordinary GET requests and reads response headers/cookies/
HTML -- it never sends exploit payloads. It tries a single request per
URL first and only makes a few extra requests (to well-known CMS paths)
when that first pass is ambiguous. Only point it at hosts you own or are
explicitly authorized to test.

Usage:
    python main.py urls https://example.com
    python main.py urls my_urls.txt
"""
import argparse
import sys
from pathlib import Path

from phpdetector.detector import scan_path
from phpdetector.report import to_console, to_json, write_csv
from phpdetector.scanner import scan_urls
from phpdetector.vulnerabilities import load_cve_db

AUTHORIZATION_NOTICE = (
    "phpDetector sends ordinary HTTP GET requests and reads response "
    "headers/cookies/HTML only -- it never sends exploit payloads. Only "
    "scan hosts you own or are explicitly authorized to test.\n"
)


def _read_url_list(path: Path) -> list[str]:
    urls = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        urls.append(line)
    return urls


def cmd_files(args: argparse.Namespace) -> int:
    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        print(f"Error: path does not exist: {target}", file=sys.stderr)
        return 1

    results = scan_path(target)
    if not results:
        print("No PHP detected.")
        return 0

    for result in results:
        print(result)
    print(f"\n{len(results)} PHP file(s) detected.")
    return 0


def cmd_urls(args: argparse.Namespace) -> int:
    print(AUTHORIZATION_NOTICE, file=sys.stderr)

    target = args.target
    if target.lower().startswith("http://") or target.lower().startswith("https://"):
        urls = [target]
    else:
        path = Path(target).expanduser().resolve()
        if not path.exists():
            print(f"Error: '{target}' is not a URL and not an existing file.", file=sys.stderr)
            return 1
        urls = _read_url_list(path)

    if not urls:
        print("No URLs to scan.", file=sys.stderr)
        return 1

    cve_db = load_cve_db()
    results = scan_urls(urls, cve_db=cve_db)

    if args.json:
        print(to_json(results))
    else:
        print(to_console(results))

    if args.csv:
        csv_path = Path(args.csv).expanduser().resolve()
        write_csv(results, csv_path)
        print(f"\nCSV written to {csv_path}", file=sys.stderr)

    if any(not cve.has_version_data() for cve in cve_db):
        print(
            "\nNote: one or more CVEs in data/vulnerabilities.json still have "
            "affected_versions = UNKNOWN. Those show as 'needs manual follow-up' "
            "rather than a real verdict until the confirmed version range from "
            "the official advisory is filled in.",
            file=sys.stderr,
        )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phpDetector",
        description="Detect PHP locally, or fingerprint URLs for an exposed/vulnerable PHP backend.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    files_parser = sub.add_parser("files", help="Scan local files/directories for PHP")
    files_parser.add_argument(
        "path", nargs="?", default=".",
        help="File or directory to scan (default: current directory)",
    )
    files_parser.set_defaults(func=cmd_files)

    urls_parser = sub.add_parser(
        "urls", help="Fingerprint a URL, or a file of URLs, for an exposed/vulnerable PHP backend"
    )
    urls_parser.add_argument("target", help="A URL to scan, or a path to a text file with one URL per line")
    urls_parser.add_argument("--json", action="store_true", help="Print results as JSON instead of a table")
    urls_parser.add_argument("--csv", help="Also write results to this CSV path")
    urls_parser.set_defaults(func=cmd_urls)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
