"""Non-intrusive HTTP fingerprinting of PHP installations and the
CMS/framework running on top of them.

This module only sends ordinary GET requests -- the kind any browser
would send -- and reads response headers, cookies, and page HTML. It
never sends exploit payloads and never attempts to trigger the
conditions described by any CVE (no memory exhaustion, no crafted
requests racing a use-after-free, etc.).

Every scan starts with a single request to the URL and scores it against
`data/fingerprints.json`. Only when that first pass is ambiguous (low
combined PHP-backend probability) does it escalate to a second round of
requests -- one per known CMS path (e.g. /wp-login.php, /administrator/)
-- to gather stronger evidence. A confident first pass never triggers the
extra requests, so well-identified targets cost exactly one request.

Only point this at hosts you own or are explicitly authorized to test.
"""
from __future__ import annotations

import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import requests

from .fingerprints import (
    EngineFingerprint,
    EngineMatch,
    all_path_signals,
    evaluate_all_engines,
    load_engine_db,
)
from .vulnerabilities import CVEDefinition, load_cve_db

DEFAULT_USER_AGENT = "phpDetector/0.1 (+security-research; non-intrusive banner scan)"
DEFAULT_TIMEOUT = 8.0
DEFAULT_CONCURRENCY = 5

# If the single-request pass already clears this, skip the extra probing
# requests -- we're confident enough without them.
PHP_CONFIDENCE_THRESHOLD = 0.5

# Below this, a CVE isn't even worth listing for the URL -- there's not
# enough signal that this is a PHP backend at all.
CVE_APPLICABILITY_THRESHOLD = 0.1

MAX_BODY_CHARS = 200_000
MAX_PROBE_BODY_CHARS = 20_000

PHP_VERSION_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)


@dataclass
class CVEAssessment:
    cve_id: str
    risk_score: float  # see module docstring in vulnerabilities.py: detection confidence, not a calibrated exploit-probability
    label: str


@dataclass
class ScanResult:
    url: str
    reachable: bool = False
    status_code: Optional[int] = None
    php_version: Optional[str] = None
    php_probability: float = 0.0
    probed_paths: bool = False
    engine_matches: list[EngineMatch] = field(default_factory=list)
    cve_assessments: list[CVEAssessment] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def php_detected(self) -> bool:
        return self.php_probability >= PHP_CONFIDENCE_THRESHOLD


def _extract_php_version(headers: dict) -> Optional[str]:
    """Pull an explicit PHP/x.y.z token out of common fingerprint headers."""
    for header_name in ("X-Powered-By", "Server"):
        match = PHP_VERSION_RE.search(headers.get(header_name, ""))
        if match:
            return match.group(1)
    return None


def _build_cookie_text(resp: requests.Response) -> str:
    """Cookie names from the parsed jar plus the raw Set-Cookie text, for regex matching."""
    parts = list(resp.cookies.keys())
    try:
        raw = resp.raw.headers.get_all("Set-Cookie") or []
        parts.extend(raw)
    except Exception:
        pass
    return ";".join(parts)


def _probe_path(base_url: str, path: str, timeout: float, user_agent: str) -> tuple[Optional[int], str]:
    target = urljoin(base_url, path)
    try:
        resp = requests.get(target, headers={"User-Agent": user_agent}, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None, ""
    return resp.status_code, (resp.text[:MAX_PROBE_BODY_CHARS] if resp.text else "")


def scan_one(
    url: str,
    cve_db: Optional[list[CVEDefinition]] = None,
    engine_db: Optional[list[EngineFingerprint]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
) -> ScanResult:
    """Probe a single URL, fingerprint it, and evaluate it against the CVE list."""
    if cve_db is None:
        cve_db = load_cve_db()
    if engine_db is None:
        engine_db = load_engine_db()

    result = ScanResult(url=url)
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        result.error = str(exc)
        return result

    result.reachable = True
    result.status_code = resp.status_code
    result.headers = dict(resp.headers)

    cookie_text = _build_cookie_text(resp)
    body_text = resp.text[:MAX_BODY_CHARS] if resp.text else ""

    # Pass 1: cookies/headers/HTML already in hand -- no extra requests.
    engine_matches, php_probability = evaluate_all_engines(engine_db, result.headers, cookie_text, body_text)

    # Pass 2 (only if ambiguous): probe the known CMS paths for stronger evidence.
    if php_probability < PHP_CONFIDENCE_THRESHOLD:
        result.probed_paths = True

        # A deliberately nonexistent path, to tell a real "this path exists"
        # apart from a WAF/catch-all that answers every path the same way.
        baseline_path = f"/phpdetector-baseline-check-{uuid.uuid4().hex[:12]}.html"
        baseline_status, _ = _probe_path(url, baseline_path, timeout, user_agent)

        path_probe_results = {
            sig.pattern: _probe_path(url, sig.pattern, timeout, user_agent)
            for sig in all_path_signals(engine_db)
        }
        engine_matches, php_probability = evaluate_all_engines(
            engine_db, result.headers, cookie_text, body_text, path_probe_results, baseline_status
        )

    result.engine_matches = engine_matches
    result.php_probability = php_probability
    result.php_version = _extract_php_version(result.headers)

    for cve in cve_db:
        if php_probability < CVE_APPLICABILITY_THRESHOLD:
            continue

        if result.php_version:
            verdict, reason = cve.explain(result.php_version)
        else:
            verdict, reason = None, "PHP version not visible in response headers"

        if verdict is True:
            # An explicit version header is itself a high-confidence PHP
            # signal (php_probability is already ~0.95+ in this branch),
            # and the version comparison against the known fixed release
            # is deterministic -- so this is as close to "confirmed" as
            # passive fingerprinting gets, short of the header being
            # spoofed or suppressed.
            risk, label = php_probability, f"vulnerable -- {reason}"
        elif verdict is False:
            risk, label = 0.0, f"not vulnerable -- {reason}"
        else:
            risk, label = php_probability, f"needs manual follow-up -- {reason}"

        result.cve_assessments.append(CVEAssessment(cve.cve_id, risk, label))

    return result


def scan_urls(
    urls: list[str],
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = DEFAULT_TIMEOUT,
    delay: float = 0.0,
    user_agent: str = DEFAULT_USER_AGENT,
    cve_db: Optional[list[CVEDefinition]] = None,
    engine_db: Optional[list[EngineFingerprint]] = None,
) -> list[ScanResult]:
    """Scan a list of URLs with bounded concurrency, preserving input order."""
    if cve_db is None:
        cve_db = load_cve_db()
    if engine_db is None:
        engine_db = load_engine_db()

    results: list[ScanResult] = []
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futures = {}
        for url in urls:
            futures[pool.submit(
                scan_one, url, cve_db=cve_db, engine_db=engine_db, timeout=timeout, user_agent=user_agent
            )] = url
            if delay:
                time.sleep(delay)
        for future in as_completed(futures):
            results.append(future.result())

    order = {url: i for i, url in enumerate(urls)}
    results.sort(key=lambda r: order.get(r.url, 0))
    return results
