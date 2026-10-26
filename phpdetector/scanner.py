"""Non-intrusive HTTP fingerprinting of PHP installations and the
CMS/framework running on top of them.

Every scan escalates through up to four tiers, each one firing only if
the previous tier left the result ambiguous (so a confident target stops
as early as possible):

  1. One ordinary GET to the URL. Score cookies/headers/HTML already in
     hand against `data/fingerprints.json`, plus a free check of the
     URL's own extension. No extra requests.
  2. Still ambiguous: probe the known CMS structural paths (e.g.
     /wp-login.php, /administrator/) plus one nonexistent-path baseline,
     to tell a real hit apart from a WAF/catch-all answering every path
     alike.
  3. Still ambiguous: a handful of low-intensity, generic structural
     checks -- comparing a nonexistent .php path against a nonexistent
     .html path (both raw, pre-redirect), requesting /index.php directly,
     comparing the 404 body against a default Apache/nginx template, and
     a trailing-slash redirect check. A few extra requests, all still
     ordinary GETs.
  4. Only with `permission=True` (CLI: `--permission`), and only if still
     ambiguous after tier 3: append an array-typed query parameter to the
     *original* URL to see if it makes the backend leak a PHP warning
     with a file path and line number. This is the one check in this
     module that behaves differently from an ordinary request, is noisy
     enough to show up in logs, and is often a no-op against a
     production site with display_errors off. It never fires without the
     flag, and the flag's help text says why: only use it on hosts you
     have explicit permission to test this way.

Deliberately not implemented, even opt-in: probing for a specific known
exposure like /phpinfo.php. That's hunting for one site's accidental
misconfiguration rather than fingerprinting what's running, and doesn't
belong in a general scanner.

Only point this at hosts you own or are explicitly authorized to test.
"""
from __future__ import annotations

import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from .detector import PHP_EXTENSIONS
from .fingerprints import (
    EngineFingerprint,
    EngineMatch,
    all_path_signals,
    combine_noisy_or,
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

# Requesting the target URL itself is near-certain evidence on its own,
# at zero extra cost -- no request needed to know this.
URL_EXTENSION_WEIGHT = 0.9

MAX_BODY_CHARS = 200_000
MAX_PROBE_BODY_CHARS = 20_000

PHP_VERSION_RE = re.compile(r"PHP/(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)

# Tier 3 weights -- see module docstring. Deliberately modest: these are
# the "weaker evidence" fallback checks, not primary signals.
EXTENSION_BEHAVIOR_WEIGHT = 0.35
FRONT_CONTROLLER_200_WEIGHT = 0.55
FRONT_CONTROLLER_REDIRECT_WEIGHT = 0.3
CUSTOM_ERROR_PAGE_WEIGHT = 0.15
TRAILING_SLASH_WEIGHT = 0.2

# Tier 4 (--permission only).
MALFORMED_INPUT_WEIGHT = 0.85

_DEFAULT_APACHE_404_RE = re.compile(
    r"<address>Apache/[\d.]+.*?Server at|Apache/[\d.]+\s*\([^)]*\)\s*Server at", re.IGNORECASE
)
_DEFAULT_NGINX_404_RE = re.compile(r"<hr><center>nginx|<center>nginx(?:/[\d.]+)?</center>", re.IGNORECASE)


def _looks_like_php_error(body: str) -> bool:
    """A classic display_errors=On PHP error/warning signature."""
    lowered = body.lower()
    if "fatal error" in lowered or "parse error" in lowered or "uncaught" in lowered:
        return True
    return "warning:" in lowered and "on line" in lowered


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
    probed_paths: bool = False  # tier 2 (CMS structural paths) fired
    structural_probed: bool = False  # tier 3 (extension/front-controller/404/trailing-slash) fired
    permission_probe_used: bool = False  # tier 4 (--permission malformed-input probe) fired
    engine_matches: list[EngineMatch] = field(default_factory=list)
    cve_assessments: list[CVEAssessment] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    url_hint: Optional[str] = None  # e.g. "requested URL itself ends in .php"
    structural_evidence: list[tuple[float, str]] = field(default_factory=list)  # (weight, reason) from tiers 3-4
    error: Optional[str] = None

    @property
    def php_detected(self) -> bool:
        return self.php_probability >= PHP_CONFIDENCE_THRESHOLD

    @property
    def positive_signals(self) -> list[tuple[float, str]]:
        """Every (weight, description) pair that contributed positively to
        php_probability, across every tier, highest weight first -- a flat
        "why this score" view instead of per-tier/per-engine fragments."""
        signals: list[tuple[float, str]] = []
        for m in self.engine_matches:
            for weight, description in m.evidence:
                signals.append((weight, f"{description} ({m.name})"))
        if self.url_hint:
            signals.append((URL_EXTENSION_WEIGHT, self.url_hint))
        signals.extend(self.structural_evidence)
        signals.sort(key=lambda pair: pair[0], reverse=True)
        return signals


def _extract_php_version(headers: dict) -> Optional[str]:
    """Pull an explicit PHP/x.y.z token out of common fingerprint headers."""
    for header_name in ("X-Powered-By", "Server"):
        match = PHP_VERSION_RE.search(headers.get(header_name, ""))
        if match:
            return match.group(1)
    return None


def _url_extension_hint(url: str) -> Optional[str]:
    """If the target URL's own path ends in a PHP extension, that's a
    strong signal with no request required to learn it."""
    path = urlparse(url).path.lower()
    for ext in sorted(PHP_EXTENSIONS, key=len, reverse=True):
        if path.endswith(ext):
            return f"requested URL itself ends in {ext}"
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
    """Probe a path, following redirects -- used for CMS structural paths
    (tier 2), where we only care whether the resource ultimately exists."""
    target = urljoin(base_url, path)
    try:
        resp = requests.get(target, headers={"User-Agent": user_agent}, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return None, ""
    return resp.status_code, (resp.text[:MAX_PROBE_BODY_CHARS] if resp.text else "")


def _probe_raw(base_url: str, path: str, timeout: float, user_agent: str) -> tuple[Optional[int], Optional[str], str]:
    """Probe a path WITHOUT following redirects, returning (status,
    Location header, body). Tier 3's checks care about the raw first-hop
    behavior itself (e.g. "does this redirect?"), which following
    redirects would hide."""
    target = urljoin(base_url, path)
    try:
        resp = requests.get(target, headers={"User-Agent": user_agent}, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None, None, ""
    return resp.status_code, resp.headers.get("Location"), (resp.text[:MAX_PROBE_BODY_CHARS] if resp.text else "")


def _structural_signals(
    url: str,
    token: str,
    followed_baseline_status: Optional[int],
    followed_baseline_body: str,
    timeout: float,
    user_agent: str,
) -> tuple[float, list[tuple[float, str]]]:
    """Tier 3: low-intensity, generic structural probes. A few extra GET
    requests.

    `followed_baseline_status`/`followed_baseline_body` are tier 2's
    baseline, measured WITH redirects followed (same as the CMS path
    probes) -- used here only for the error-page-fingerprint check, which
    wants to see the actual rendered "not found" content.

    The extension-behaviour and front-controller checks below care about
    raw, pre-redirect status codes instead, so they fetch their own fresh
    raw baseline rather than reusing tier 2's -- mixing the two was a real
    bug: a site that redirects every nonexistent path (including a
    genuinely random one) to one fixed "page not found" URL, which then
    returns 200 (common on enterprise sites, e.g. tescobank.com -> a 302
    to /oops/page-not-found/), would show status 200 for every real CMS
    path probe (which follows that redirect) while the old raw-only
    baseline stayed at 302 -- so they never matched, and every CMS engine
    looked like a hit. Comparing raw-to-raw and followed-to-followed
    consistently is what actually catches that.

    Returns (combined score, evidence), evidence being a list of (weight,
    description) pairs -- same contract as `fingerprints.evaluate_engine`.
    """
    evidence: list[tuple[float, str]] = []

    raw_baseline_status, _, raw_baseline_body = _probe_raw(
        url, f"/phpdetector-raw-baseline-{token}.html", timeout, user_agent
    )

    # 1. Extension behaviour: a nonexistent .php path vs a nonexistent
    #    .html path, both raw. A PHP backend may answer differently --
    #    but only if it answers differently from ANY nonexistent path,
    #    not just because both happen to be caught by a blanket redirect.
    #
    #    A 403 specifically doesn't count here, confirmed live: a WAF/CDN
    #    managed ruleset can block the .php extension by name on every
    #    site it protects, independent of the real backend -- seen on a
    #    Next.js (non-PHP) site where /x.php got 403 but /x.asp got a
    #    normal 404, i.e. it's an extension-pattern block, not evidence
    #    of PHP. Same principle as the PATH-signal fix in fingerprints.py.
    php_status, _, php_body = _probe_raw(url, f"/phpdetector-ext-check-{token}.php", timeout, user_agent)
    if (
        php_status is not None
        and php_status != 403
        and raw_baseline_status is not None
        and php_status != raw_baseline_status
    ):
        evidence.append((
            EXTENSION_BEHAVIOR_WEIGHT,
            f"nonexistent .php path gets a different raw status than .html ({php_status} vs {raw_baseline_status})",
        ))
    elif (
        php_body and raw_baseline_body and php_body != raw_baseline_body and _looks_like_php_error(php_body)
    ):
        evidence.append((EXTENSION_BEHAVIOR_WEIGHT, "nonexistent .php path triggers a PHP-style error body that .html doesn't"))

    # 2. Front controller routing: request /index.php directly. Only
    #    meaningful if it behaves differently from the raw baseline --
    #    e.g. a blanket "every path redirects/200s the same way" site
    #    makes /index.php returning 200 (or redirecting) uninformative.
    index_status, _, _ = _probe_raw(url, "/index.php", timeout, user_agent)
    if index_status is not None and raw_baseline_status is not None and index_status != raw_baseline_status:
        if index_status == 200:
            evidence.append((FRONT_CONTROLLER_200_WEIGHT, "/index.php returns 200 directly"))
        elif 300 <= index_status < 400:
            evidence.append((FRONT_CONTROLLER_REDIRECT_WEIGHT, f"/index.php redirects ({index_status}) instead of 404ing"))

    # 3. Error page fingerprint: is the (followed) 404 a default
    #    Apache/nginx template, or something custom-rendered? Weak and
    #    non-specific -- any dynamic backend can have a custom 404, not
    #    just PHP -- so it only ever corroborates other evidence, never
    #    carries a result alone.
    if followed_baseline_status == 404 and followed_baseline_body and len(followed_baseline_body) > 200:
        is_default = bool(
            _DEFAULT_APACHE_404_RE.search(followed_baseline_body) or _DEFAULT_NGINX_404_RE.search(followed_baseline_body)
        )
        if not is_default:
            evidence.append((
                CUSTOM_ERROR_PAGE_WEIGHT,
                "404 page isn't a default Apache/nginx template (custom/application-rendered)",
            ))

    # 4. Trailing-slash behaviour -- weaker evidence, only helps ambiguous
    #    cases. Already self-guarding: a blanket redirect-everywhere-to-
    #    one-fixed-URL site won't satisfy the "redirects to this same
    #    path plus a slash" check below.
    slash_path = f"/phpdetector-slash-check-{token}"
    slash_status, slash_location, _ = _probe_raw(url, slash_path, timeout, user_agent)
    if slash_status is not None and 300 <= slash_status < 400 and slash_location and slash_location.rstrip("/").endswith(
        slash_path
    ):
        evidence.append((TRAILING_SLASH_WEIGHT, "a nonexistent path without a trailing slash redirects to the same path with one"))

    return combine_noisy_or([w for w, _ in evidence]), evidence


def _malformed_input_signal(url: str, timeout: float, user_agent: str) -> tuple[float, list[tuple[float, str]]]:
    """Tier 4 (--permission only): append an array-typed query parameter
    to the ORIGINAL target URL. Some PHP apps run a blanket
    sanitization/type check over all of $_GET regardless of parameter
    name; feeding one of those a value typed as an array instead of a
    scalar can make PHP emit a warning carrying a file path and line
    number. Most production sites hide this (display_errors off), so an
    empty result is the common case -- this is a last-resort nudge, not a
    reliable technique, and it's the one check here that isn't just an
    ordinary request."""
    separator = "&" if "?" in url else "?"
    target = f"{url}{separator}phpdetector_probe%5B%5D=1"  # phpdetector_probe[]=1
    try:
        resp = requests.get(target, headers={"User-Agent": user_agent}, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return 0.0, []

    body = resp.text[:MAX_PROBE_BODY_CHARS] if resp.text else ""
    if body and _looks_like_php_error(body):
        description = "an array-typed query parameter triggered a PHP warning/error leak"
        return MALFORMED_INPUT_WEIGHT, [(MALFORMED_INPUT_WEIGHT, description)]
    return 0.0, []


def scan_one(
    url: str,
    cve_db: Optional[list[CVEDefinition]] = None,
    engine_db: Optional[list[EngineFingerprint]] = None,
    timeout: float = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_USER_AGENT,
    permission: bool = False,
) -> ScanResult:
    """Probe a single URL, fingerprint it, and evaluate it against the CVE
    list. See the module docstring for the four escalation tiers;
    `permission=True` (CLI: --permission) is required for tier 4 to ever
    fire, and even then only as a last resort if tiers 1-3 stay ambiguous.
    """
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
    result.url_hint = _url_extension_hint(url)

    def _with_url_hint(php_probability: float) -> float:
        if not result.url_hint:
            return php_probability
        return combine_noisy_or([php_probability, URL_EXTENSION_WEIGHT])

    # Tier 1: cookies/headers/HTML already in hand -- no extra requests.
    engine_matches, php_probability = evaluate_all_engines(engine_db, result.headers, cookie_text, body_text)
    php_probability = _with_url_hint(php_probability)

    token: Optional[str] = None
    baseline_status: Optional[int] = None
    baseline_body = ""

    # Tier 2 (only if ambiguous): probe the known CMS paths for stronger evidence.
    if php_probability < PHP_CONFIDENCE_THRESHOLD:
        result.probed_paths = True

        # A deliberately nonexistent path, to tell a real "this path exists"
        # apart from a WAF/catch-all that answers every path the same way.
        # Its body is folded into the HTML evidence too -- a server that
        # leaks a PHP error/stack-trace for an unknown path (display_errors
        # left on) hands us that signal for free, from a request we're
        # already making. Follows redirects, matching the CMS path probes
        # below -- comparing a redirect-following baseline against
        # redirect-following probes is what makes the dedup valid. (Using
        # a raw, non-following baseline here was a real bug: a site that
        # redirects every nonexistent path, including a random one, to a
        # single "page not found" URL that returns 200 would show 200 for
        # every CMS path probe while the raw baseline stayed at the
        # redirect's own status -- they'd never match, so every CMS
        # engine would look like a hit. Tier 3 fetches its own separate
        # raw baseline for the checks that specifically need that.)
        token = uuid.uuid4().hex[:12]
        baseline_status, baseline_body = _probe_path(
            url, f"/phpdetector-baseline-check-{token}.html", timeout, user_agent
        )
        combined_body_text = f"{body_text}\n{baseline_body}" if baseline_body else body_text

        path_probe_results = {
            sig.pattern: _probe_path(url, sig.pattern, timeout, user_agent)
            for sig in all_path_signals(engine_db)
        }
        engine_matches, php_probability = evaluate_all_engines(
            engine_db, result.headers, cookie_text, combined_body_text, path_probe_results, baseline_status
        )
        php_probability = _with_url_hint(php_probability)

    # Tier 3 (only if STILL ambiguous after tier 2): generic, low-intensity
    # structural probes -- a final fallback, not something every scan pays
    # for. Reuses tier 2's token/baseline rather than re-fetching them.
    if php_probability < PHP_CONFIDENCE_THRESHOLD and token is not None:
        result.structural_probed = True
        structural_weight, structural_evidence = _structural_signals(
            url, token, baseline_status, baseline_body, timeout, user_agent
        )
        if structural_weight:
            php_probability = combine_noisy_or([php_probability, structural_weight])
            result.structural_evidence.extend(structural_evidence)

    # Tier 4 (--permission only, and only if STILL ambiguous): see module
    # docstring -- the one check here that isn't just an ordinary request.
    if permission and php_probability < PHP_CONFIDENCE_THRESHOLD:
        result.permission_probe_used = True
        malformed_weight, malformed_evidence = _malformed_input_signal(url, timeout, user_agent)
        if malformed_weight:
            php_probability = combine_noisy_or([php_probability, malformed_weight])
            result.structural_evidence.extend(malformed_evidence)

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
    permission: bool = False,
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
                scan_one, url, cve_db=cve_db, engine_db=engine_db, timeout=timeout,
                user_agent=user_agent, permission=permission,
            )] = url
            if delay:
                time.sleep(delay)
        for future in as_completed(futures):
            results.append(future.result())

    order = {url: i for i, url in enumerate(urls)}
    results.sort(key=lambda r: order.get(r.url, 0))
    return results
