"""Core logic for detecting PHP files and PHP code signatures."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PHP_EXTENSIONS = {".php", ".php3", ".php4", ".php5", ".phtml"}
PHP_TAG_PATTERN = re.compile(rb"<\?php|<\?=")


@dataclass
class DetectionResult:
    path: Path
    reason: str

    def __str__(self) -> str:
        return f"{self.path}: {self.reason}"


def is_php_by_extension(path: Path) -> bool:
    """Return True if the file extension is a known PHP extension."""
    return path.suffix.lower() in PHP_EXTENSIONS


def is_php_by_content(path: Path, chunk_size: int = 4096) -> bool:
    """Return True if the file's opening bytes contain a PHP open tag."""
    try:
        with path.open("rb") as f:
            head = f.read(chunk_size)
    except (OSError, PermissionError):
        return False
    return bool(PHP_TAG_PATTERN.search(head))


def scan_path(root: Path) -> list[DetectionResult]:
    """Walk `root` (file or directory) and report any PHP files found."""
    results: list[DetectionResult] = []
    targets = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())

    for path in targets:
        if is_php_by_extension(path):
            results.append(DetectionResult(path, "PHP extension"))
        elif is_php_by_content(path):
            results.append(DetectionResult(path, "PHP open tag found in content"))

    return results
