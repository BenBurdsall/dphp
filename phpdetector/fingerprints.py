"""Multi-signal fingerprinting for PHP-based CMS/framework engines.

Signal definitions live in `data/fingerprints.json` so they can be tuned
without touching code -- add a cookie pattern, adjust a weight, add a new
engine, all by editing that file. Each signal there is one observable
fact (a cookie name pattern, a response header, a string in the HTML
body, or a known path) paired with a `weight` in [0, 1]: the confidence
that, on its own, this signal implies a PHP backend (specifically, this
engine). Every engine in the default file is PHP-based, so an engine's
own combined score doubles as its contribution to overall PHP-backend
probability. Weights are hand-set priors based on how unique each
artifact is in practice (e.g. `wordpress_logged_in_` is very specific; a
bare `PHPSESSID` cookie is not) -- not an empirically calibrated model.
Treat the resulting scores as a triage aid for prioritizing manual
review, not as ground truth.

Multiple matched signals for the same engine combine with a noisy-OR:
combined = 1 - product(1 - w_i). One weak signal gives a modest score;
several independent weak-to-medium signals together push it up; a single
very specific signal (e.g. a generator meta tag naming the product) can
carry a high score alone.

PATH-kind signals need an extra HTTP request per path. The scanner only
fires those when the cheaper cookie/header/HTML signals from the single
homepage request came back ambiguous -- see `scanner.scan_one`.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "fingerprints.json"


class SignalKind(Enum):
    COOKIE = "cookie"
    HEADER = "header"
    HTML = "html"
    PATH = "path"


@dataclass
class Signal:
    kind: SignalKind
    pattern: str  # regex (cookie/header/html) or a literal URL path (path)
    weight: float
    description: str
    header_name: str = ""  # HEADER kind only
    expect_in_body: str | None = None  # PATH kind only: regex the fetched path's body must match


@dataclass
class EngineFingerprint:
    name: str
    implies_php: bool = True
    signals: list[Signal] = field(default_factory=list)


@dataclass
class EngineMatch:
    name: str
    score: float
    evidence: list[tuple[float, str]] = field(default_factory=list)  # (signal weight, description)


def load_engine_db(path: Path = DEFAULT_DB_PATH) -> list[EngineFingerprint]:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    engines = []
    for name, entry in raw.items():
        signals = [
            Signal(
                kind=SignalKind(sig["kind"]),
                pattern=sig["pattern"],
                weight=float(sig["weight"]),
                description=sig.get("description", ""),
                header_name=sig.get("header_name", ""),
                expect_in_body=sig.get("expect_in_body"),
            )
            for sig in entry.get("signals", [])
        ]
        engines.append(EngineFingerprint(
            name=name,
            implies_php=entry.get("implies_php", True),
            signals=signals,
        ))
    return engines


def combine_noisy_or(weights: list[float]) -> float:
    """1 - product(1 - w_i): combine independent-ish signal weights into one probability."""
    if not weights:
        return 0.0
    prob_absent = 1.0
    for w in weights:
        w = min(max(w, 0.0), 0.999999)
        prob_absent *= (1 - w)
    return 1 - prob_absent


def evaluate_engine(
    engine: EngineFingerprint,
    headers: dict,
    cookie_text: str,
    body_text: str,
    path_probe_results: dict | None = None,
    baseline_status: int | None = None,
) -> tuple[float, list[tuple[float, str]]]:
    """Score one engine against the evidence gathered for a URL.

    Returns (combined score, evidence), where evidence is a list of
    (signal weight, description) pairs -- one per signal that actually
    matched, so callers can show exactly which facts contributed and how
    much weight each one carried, not just the final combined score.

    `path_probe_results` maps a probed path to (status_code, body) or is
    absent/None for a path that wasn't probed -- PATH signals are simply
    skipped (not counted as absent) when no probe was made.

    `baseline_status` is the status code returned for a deliberately
    nonexistent path on the same host. A real path only counts as a hit
    if its status *differs* from that baseline -- otherwise a WAF or
    catch-all route that returns the same status for every path (e.g.
    403 for everything, or 200 for everything via an SPA fallback) would
    look like every engine's paths exist at once.
    """
    path_probe_results = path_probe_results or {}
    evidence: list[tuple[float, str]] = []

    for sig in engine.signals:
        if sig.kind is SignalKind.COOKIE:
            if cookie_text and re.search(sig.pattern, cookie_text, re.IGNORECASE):
                evidence.append((sig.weight, sig.description))

        elif sig.kind is SignalKind.HEADER:
            value = headers.get(sig.header_name, "")
            if value and re.search(sig.pattern, value, re.IGNORECASE):
                evidence.append((sig.weight, sig.description))

        elif sig.kind is SignalKind.HTML:
            if body_text and re.search(sig.pattern, body_text, re.IGNORECASE):
                evidence.append((sig.weight, sig.description))

        elif sig.kind is SignalKind.PATH:
            probe = path_probe_results.get(sig.pattern)
            if probe is None:
                continue
            status, probe_body = probe
            if status is None or status not in (200, 301, 302, 403):
                continue
            if baseline_status is not None and status == baseline_status:
                continue
            if sig.expect_in_body and not re.search(sig.expect_in_body, probe_body or "", re.IGNORECASE):
                continue
            evidence.append((sig.weight, sig.description))

    return combine_noisy_or([w for w, _ in evidence]), evidence


def evaluate_all_engines(
    engines: list[EngineFingerprint],
    headers: dict,
    cookie_text: str,
    body_text: str,
    path_probe_results: dict | None = None,
    baseline_status: int | None = None,
) -> tuple[list[EngineMatch], float]:
    """Score every engine and derive one overall PHP-backend probability.

    Each matched engine's own score (it's already PHP-based) becomes one
    contributing signal; those are combined with the same noisy-OR so a
    confident CMS match and a bare PHP header reinforce each other rather
    than just taking whichever is higher. See `evaluate_engine` for what
    `baseline_status` guards against.
    """
    engine_matches: list[EngineMatch] = []
    php_weights: list[float] = []

    for engine in engines:
        score, evidence = evaluate_engine(
            engine, headers, cookie_text, body_text, path_probe_results, baseline_status
        )
        if score > 0:
            engine_matches.append(EngineMatch(engine.name, score, evidence))
            if engine.implies_php:
                php_weights.append(score)

    engine_matches.sort(key=lambda m: m.score, reverse=True)
    return engine_matches, combine_noisy_or(php_weights)


def all_path_signals(engines: list[EngineFingerprint]) -> list[Signal]:
    """Every distinct PATH-kind signal across all engines, for probing."""
    seen: dict[str, Signal] = {}
    for engine in engines:
        for sig in engine.signals:
            if sig.kind is SignalKind.PATH:
                seen[sig.pattern] = sig
    return list(seen.values())
