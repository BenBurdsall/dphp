"""Human- and machine-readable output for URL scan results."""
from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .scanner import ScanResult


def to_console(results: list[ScanResult]) -> str:
    lines: list[str] = []
    for r in results:
        if not r.reachable:
            lines.append(f"[UNREACHABLE]  {r.url} -- {r.error}")
            continue

        if r.php_probability < 0.1 and not r.engine_matches:
            lines.append(f"[NO PHP]       {r.url} (status {r.status_code})")
            continue

        version_note = f", version {r.php_version}" if r.php_version else ""
        tier_notes = []
        if r.probed_paths:
            tier_notes.append("probed CMS paths")
        if r.structural_probed:
            tier_notes.append("probed structural checks")
        if r.permission_probe_used:
            tier_notes.append("ran --permission malformed-input probe")
        tier_note = f" [{', '.join(tier_notes)}]" if tier_notes else ""
        lines.append(
            f"[PHP]          {r.url} -- backend probability {r.php_probability:.0%}"
            f"{version_note} (status {r.status_code}){tier_note}"
        )
        if r.url_hint:
            lines.append(f"               hint: {r.url_hint}")
        for m in r.engine_matches:
            lines.append(f"               engine: {m.name} (confidence {m.score:.0%})")
            for ev in m.evidence:
                lines.append(f"                 - {ev}")
        for ev in r.structural_evidence:
            lines.append(f"               structural: {ev}")
        for cve in r.cve_assessments:
            lines.append(f"               {cve.cve_id}: risk {cve.risk_score:.0%} -- {cve.label}")

    total = len(results)
    php_found = sum(1 for r in results if r.php_detected)
    needs_follow_up = sum(
        1 for r in results if any(c.label.startswith("needs manual follow-up") for c in r.cve_assessments)
    )
    lines.append("")
    lines.append(
        f"Scanned {total} URL(s): {php_found} with a PHP backend detected, "
        f"{needs_follow_up} with at least one CVE needing manual follow-up."
    )
    return "\n".join(lines)


def to_json(results: list[ScanResult]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2)


def write_csv(results: list[ScanResult], path: Path) -> None:
    fieldnames = [
        "url", "reachable", "status_code", "php_version", "php_probability",
        "probed_paths", "structural_probed", "permission_probe_used", "url_hint",
        "engines", "structural_evidence", "cve_risks", "error",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "url": r.url,
                "reachable": r.reachable,
                "status_code": r.status_code,
                "php_version": r.php_version,
                "php_probability": f"{r.php_probability:.3f}",
                "probed_paths": r.probed_paths,
                "structural_probed": r.structural_probed,
                "permission_probe_used": r.permission_probe_used,
                "url_hint": r.url_hint,
                "engines": "; ".join(f"{m.name}:{m.score:.2f}" for m in r.engine_matches),
                "structural_evidence": "; ".join(r.structural_evidence),
                "cve_risks": "; ".join(f"{c.cve_id}:{c.risk_score:.2f}:{c.label}" for c in r.cve_assessments),
                "error": r.error,
            })
