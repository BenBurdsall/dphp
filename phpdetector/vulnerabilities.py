"""Known PHP CVEs this scanner checks exposed hosts against.

IMPORTANT: the `affected_versions` field for each CVE in
`data/vulnerabilities.json` must be verified against the authoritative
advisory (php.net ChangeLog, the CVE's CNA record, NVD) before it is
relied on. Until a real version range is filled in, it is left as the
string "UNKNOWN" and this module deliberately refuses to call a version
"safe" or "vulnerable" for it -- `matches()` returns None, meaning
"cannot determine from this data", which callers should surface as
"needs manual follow-up" rather than a false positive or false negative.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "vulnerabilities.json"


@dataclass
class CVEDefinition:
    cve_id: str
    title: str
    severity: str
    cvss: Optional[float]
    summary: str
    affected_versions: str  # a PEP 440-style specifier (e.g. ">=8.1.0,<8.1.30"), or "UNKNOWN"
    references: list[str] = field(default_factory=list)

    def matches(self, version_str: str) -> Optional[bool]:
        """Check whether `version_str` falls in this CVE's affected range.

        Returns True (affected) / False (not affected) only when the range
        is populated and the version string parses cleanly. Returns None
        when the range is "UNKNOWN" or the version can't be parsed -- i.e.
        "cannot determine", never a silent false negative.
        """
        if not self.affected_versions or self.affected_versions.strip().upper() == "UNKNOWN":
            return None
        try:
            spec = SpecifierSet(self.affected_versions)
            version = Version(version_str)
        except (InvalidSpecifier, InvalidVersion):
            return None
        return version in spec


def load_cve_db(path: Path = DEFAULT_DB_PATH) -> list[CVEDefinition]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [
        CVEDefinition(
            cve_id=cve_id,
            title=entry.get("title", ""),
            severity=entry.get("severity", ""),
            cvss=entry.get("cvss_v4"),
            summary=entry.get("summary", ""),
            affected_versions=entry.get("affected_versions", "UNKNOWN"),
            references=entry.get("references", []),
        )
        for cve_id, entry in raw.items()
    ]
