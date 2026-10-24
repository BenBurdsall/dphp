"""Known PHP CVEs this scanner checks exposed hosts against.

A CVE's `affected_versions` in `data/vulnerabilities.json` can be:

  - the string "UNKNOWN" -- no verified range yet. `explain()`/`matches()`
    return None ("cannot determine"), surfaced as "needs manual
    follow-up" rather than a guessed verdict.

  - a plain PEP 440 specifier string (e.g. ">=8.1.0,<8.1.30") -- for a
    CVE whose affected range is a single contiguous band.

  - a fixed-version table, e.g.:
        {
          "fixed_in": {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
          "unsupported_branches_affected": true
        }
    This is how PHP actually ships security fixes -- independently per
    minor branch, not one global cutoff. For a branch listed in
    `fixed_in`, a version is vulnerable iff it's below that branch's
    fixed release. A branch *older* than the oldest one listed (e.g.
    7.x, 8.0, 8.1 when the table starts at 8.2) is EOL and never
    received a backport, so it's treated as vulnerable by default
    (`unsupported_branches_affected: true`) -- set that to false if a
    given CVE is known not to reach back that far. A branch *newer* than
    the newest one listed is assumed to already include the fix (PHP
    doesn't ship new branches with known-old vulnerabilities).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Union

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "vulnerabilities.json"


def _branch_tuple(branch: str) -> tuple[int, int]:
    major, minor = branch.split(".")
    return int(major), int(minor)


@dataclass
class FixedVersionTable:
    fixed_in: dict[str, str]  # {"8.2": "8.2.35", ...}
    unsupported_branches_affected: bool = True

    def explain(self, version: Version) -> tuple[Optional[bool], str]:
        branches = {_branch_tuple(b): fixed for b, fixed in self.fixed_in.items()}
        if not branches:
            return None, "no fixed-version data configured"

        release = version.release
        branch = (release[0], release[1] if len(release) > 1 else 0)
        branch_str = f"{branch[0]}.{branch[1]}"

        if branch in branches:
            fixed_str = branches[branch]
            if version < Version(fixed_str):
                return True, f"PHP {version} is below {fixed_str}, the patched release for the {branch_str} branch"
            return False, f"PHP {version} is at or above {fixed_str}, the patched release for the {branch_str} branch"

        oldest, newest = min(branches), max(branches)
        if branch < oldest:
            oldest_str = f"{oldest[0]}.{oldest[1]}"
            if self.unsupported_branches_affected:
                return True, (
                    f"PHP {version} is on branch {branch_str}, older than {oldest_str} -- "
                    f"that branch is EOL and was never patched for this CVE"
                )
            return None, f"PHP {version} is on branch {branch_str}, below the known fix data and not confirmed affected"
        if branch > newest:
            newest_str = f"{newest[0]}.{newest[1]}"
            return False, f"PHP {version} is on branch {branch_str}, newer than {newest_str} -- assumed to already include the fix"

        return None, f"PHP {version} is on branch {branch_str}, a gap in the known fix data"


@dataclass
class CVEDefinition:
    cve_id: str
    title: str
    severity: str
    cvss: Optional[float]
    summary: str
    affected_versions: Union[str, FixedVersionTable]  # "UNKNOWN", a PEP 440 specifier, or a FixedVersionTable
    references: list[str] = field(default_factory=list)

    def has_version_data(self) -> bool:
        if isinstance(self.affected_versions, str):
            return self.affected_versions.strip().upper() != "UNKNOWN"
        return True

    def explain(self, version_str: str) -> tuple[Optional[bool], str]:
        """Check `version_str` against this CVE's affected-version data.

        Returns (verdict, human-readable reason). verdict is True
        (vulnerable) / False (not vulnerable) / None (cannot determine --
        range not yet confirmed, or the version string didn't parse).
        """
        if not self.has_version_data():
            return None, "affected-version range not yet confirmed for this CVE"

        try:
            version = Version(version_str)
        except InvalidVersion:
            return None, f"could not parse PHP version string '{version_str}'"

        if isinstance(self.affected_versions, FixedVersionTable):
            return self.affected_versions.explain(version)

        try:
            spec = SpecifierSet(self.affected_versions)
        except InvalidSpecifier:
            return None, "configured affected-version specifier is invalid"
        in_range = version in spec
        word = "inside" if in_range else "outside"
        return in_range, f"PHP {version} is {word} the affected range {self.affected_versions}"

    def matches(self, version_str: str) -> Optional[bool]:
        """Convenience wrapper over `explain()` that drops the reason string."""
        verdict, _ = self.explain(version_str)
        return verdict


def load_cve_db(path: Path = DEFAULT_DB_PATH) -> list[CVEDefinition]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    cves = []
    for cve_id, entry in raw.items():
        raw_versions = entry.get("affected_versions", "UNKNOWN")
        if isinstance(raw_versions, dict):
            affected_versions: Union[str, FixedVersionTable] = FixedVersionTable(
                fixed_in=raw_versions.get("fixed_in", {}),
                unsupported_branches_affected=raw_versions.get("unsupported_branches_affected", True),
            )
        else:
            affected_versions = raw_versions

        cves.append(CVEDefinition(
            cve_id=cve_id,
            title=entry.get("title", ""),
            severity=entry.get("severity", ""),
            cvss=entry.get("cvss_v4"),
            summary=entry.get("summary", ""),
            affected_versions=affected_versions,
            references=entry.get("references", []),
        ))
    return cves
