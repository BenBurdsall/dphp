#!/usr/bin/env python3
"""CLI entry point for phpDetector.

Scans a file or directory and reports anything that looks like PHP code,
either by file extension or by a `<?php` / `<?=` tag in the file content.
"""
import argparse
import sys
from pathlib import Path

from phpdetector.detector import scan_path


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="phpDetector",
        description="Detect PHP files or embedded PHP code under a path.",
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: current directory)")
    args = parser.parse_args()

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


if __name__ == "__main__":
    sys.exit(main())
