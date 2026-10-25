from unittest.mock import Mock, patch
from urllib.parse import urlparse

import pytest
import requests

from phpdetector.fingerprints import EngineFingerprint, Signal, SignalKind
from phpdetector.scanner import (
    CUSTOM_ERROR_PAGE_WEIGHT,
    EXTENSION_BEHAVIOR_WEIGHT,
    FRONT_CONTROLLER_200_WEIGHT,
    MALFORMED_INPUT_WEIGHT,
    TRAILING_SLASH_WEIGHT,
    scan_one,
)
from phpdetector.vulnerabilities import CVEDefinition, FixedVersionTable


def _mock_response(status=200, headers=None, cookies=None, body=""):
    resp = Mock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = body
    cookie_mock = Mock()
    cookie_mock.keys.return_value = cookies or []
    resp.cookies = cookie_mock
    resp.raw = Mock()
    resp.raw.headers.get_all.return_value = []
    return resp


def _php_header_engine_db():
    return [EngineFingerprint("PHP", signals=[
        Signal(SignalKind.HEADER, r"PHP/\d", 0.95, "PHP version header", header_name="X-Powered-By"),
    ])]


def test_detects_php_version_from_header_and_matches_cve():
    cve_db = [CVEDefinition("CVE-TEST-0001", "t", "Critical", 9.2, "s", ">=8.1.0,<8.1.30", [])]
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"X-Powered-By": "PHP/8.1.2"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=cve_db, engine_db=engine_db)

    assert result.php_detected
    assert result.php_version == "8.1.2"
    assert result.probed_paths is False  # confident on first pass, no escalation
    assert len(result.cve_assessments) == 1
    assert result.cve_assessments[0].cve_id == "CVE-TEST-0001"
    assert result.cve_assessments[0].label.startswith("vulnerable")


def test_version_outside_known_range_is_low_risk():
    cve_db = [CVEDefinition("CVE-TEST-0002", "t", "Critical", 9.2, "s", ">=8.1.0,<8.1.5", [])]
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"X-Powered-By": "PHP/8.1.9"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=cve_db, engine_db=engine_db)

    assert result.cve_assessments[0].risk_score == 0.0
    assert result.cve_assessments[0].label.startswith("not vulnerable")


def test_unknown_cve_range_needs_follow_up():
    cve_db = [CVEDefinition("CVE-TEST-0003", "t", "Critical", 9.2, "s", "UNKNOWN", [])]
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"X-Powered-By": "PHP/8.1.2"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=cve_db, engine_db=engine_db)

    assert result.cve_assessments[0].label.startswith("needs manual follow-up")
    assert result.cve_assessments[0].risk_score > 0


def _fixed_version_cve_db():
    table = FixedVersionTable(
        fixed_in={"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
        unsupported_branches_affected=True,
    )
    return [CVEDefinition("CVE-TEST-0004", "t", "Critical", 9.2, "s", table, [])]


def test_patched_version_in_branch_is_not_vulnerable():
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"X-Powered-By": "PHP/8.3.36"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=_fixed_version_cve_db(), engine_db=engine_db)
    assert result.cve_assessments[0].risk_score == 0.0
    assert result.cve_assessments[0].label.startswith("not vulnerable")


def test_unpatched_version_in_branch_is_vulnerable():
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"X-Powered-By": "PHP/8.3.10"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=_fixed_version_cve_db(), engine_db=engine_db)
    assert result.cve_assessments[0].risk_score > 0.9
    assert result.cve_assessments[0].label.startswith("vulnerable")
    assert "8.3.36" in result.cve_assessments[0].label


def test_eol_branch_treated_as_vulnerable():
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"X-Powered-By": "PHP/8.1.27"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=_fixed_version_cve_db(), engine_db=engine_db)
    assert result.cve_assessments[0].risk_score > 0.9
    assert result.cve_assessments[0].label.startswith("vulnerable")


def test_newer_branch_assumed_fixed():
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"X-Powered-By": "PHP/9.0.0"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=_fixed_version_cve_db(), engine_db=engine_db)
    assert result.cve_assessments[0].risk_score == 0.0
    assert result.cve_assessments[0].label.startswith("not vulnerable")


def test_ambiguous_first_pass_escalates_to_path_probing():
    engine_db = [EngineFingerprint("WordPress", signals=[
        Signal(SignalKind.PATH, "/wp-login.php", 0.6, "/wp-login.php reachable"),
    ])]
    homepage = _mock_response(headers={}, body="nothing interesting here")
    baseline_404 = _mock_response(status=404, body="not found")
    probe = _mock_response(status=200, body="wp-login page")

    with patch("phpdetector.scanner.requests.get", side_effect=[homepage, baseline_404, probe]) as mock_get:
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert mock_get.call_count == 3  # homepage + baseline probe + one path probe
    assert result.probed_paths is True
    assert result.php_probability > 0
    assert result.engine_matches and result.engine_matches[0].name == "WordPress"


def test_waf_blanket_status_does_not_create_false_positive():
    """If every path (including a nonexistent one) returns the same status,
    that must not be treated as evidence the real paths exist -- in tier 2
    (CMS paths) or tier 3 (structural probes)."""
    engine_db = [EngineFingerprint("WordPress", signals=[
        Signal(SignalKind.PATH, "/wp-login.php", 0.6, "/wp-login.php reachable"),
    ])]
    homepage = _mock_response(headers={}, body="nothing interesting here")
    forbidden = _mock_response(status=403, body="forbidden")

    # homepage, then every probe (baseline, the one CMS path, and tier 3's
    # extension/index.php/trailing-slash checks) gets the same blanket 403.
    with patch("phpdetector.scanner.requests.get", side_effect=[homepage] + [forbidden] * 10):
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert result.php_probability == 0.0
    assert result.engine_matches == []
    assert result.structural_evidence == []


def test_soft_404_via_redirect_does_not_create_false_positive():
    """Real-world case (tescobank.com): every nonexistent path, including
    a genuinely random one, redirects (302, raw) to one fixed "page not
    found" URL, which itself returns 200 when the redirect is followed.
    Comparing a raw baseline against followed CMS-path probes (or vice
    versa) would make every single path look like a hit; comparing
    consistently must not."""
    engine_db = [
        EngineFingerprint("WordPress", signals=[
            Signal(SignalKind.PATH, "/wp-login.php", 0.6, "/wp-login.php reachable"),
        ]),
        EngineFingerprint("Joomla", signals=[
            Signal(SignalKind.PATH, "/administrator/", 0.55, "/administrator/ reachable"),
        ]),
    ]
    homepage = _mock_response(headers={}, body="nothing interesting here")
    not_found_page = _mock_response(status=200, body="Oops, page not found. " + "x" * 200)
    call_count = {"n": 0}

    def side_effect(url, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return homepage
        if kwargs.get("allow_redirects"):
            # Followed: every path resolves to the same fixed 200 page.
            return not_found_page
        # Raw: every path 302s to that same fixed page first.
        resp = _mock_response(status=302, body="")
        resp.headers = {"Location": "/oops/page-not-found/"}
        return resp

    with patch("phpdetector.scanner.requests.get", side_effect=side_effect):
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert result.php_probability == 0.0
    assert result.engine_matches == []
    assert result.structural_evidence == []


def test_confident_first_pass_does_not_probe():
    engine_db = _php_header_engine_db()
    homepage = _mock_response(headers={"X-Powered-By": "PHP/8.3.0"})

    with patch("phpdetector.scanner.requests.get", return_value=homepage) as mock_get:
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert mock_get.call_count == 1
    assert result.probed_paths is False


def test_no_php_detected():
    engine_db = _php_header_engine_db()
    homepage = _mock_response(headers={"Server": "nginx"})
    not_found = _mock_response(status=404, body="Not Found")
    with patch("phpdetector.scanner.requests.get", side_effect=[homepage] + [not_found] * 10):
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)
    assert not result.php_detected
    assert result.cve_assessments == []


def test_unreachable_url():
    with patch("phpdetector.scanner.requests.get", side_effect=requests.ConnectionError("boom")):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])
    assert not result.reachable
    assert result.error


def test_url_extension_hint_boosts_confidence_at_no_extra_cost():
    """Requesting a .php URL directly is a free, strong signal -- no
    engine needs to match anything for this to push php_probability up,
    and it must not trigger the extra path-probing requests on its own."""
    resp = _mock_response(headers={}, body="plain page")
    with patch("phpdetector.scanner.requests.get", return_value=resp) as mock_get:
        result = scan_one("http://example.test/index.php", cve_db=[], engine_db=[])

    assert mock_get.call_count == 1
    assert result.probed_paths is False
    assert result.url_hint == "requested URL itself ends in .php"
    assert result.php_probability >= 0.9


def test_non_php_url_gets_no_hint():
    resp = _mock_response(headers={}, body="plain page")
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test/about", cve_db=[], engine_db=[])
    assert result.url_hint is None


def test_leaked_fatal_error_detected_from_baseline_probe_body():
    """The baseline nonexistent-path probe is already fetched to detect a
    WAF/catch-all; its body should also be scanned for a classic PHP
    error leak, at no extra request cost."""
    engine_db = [EngineFingerprint("PHP", signals=[
        Signal(SignalKind.HTML, r"Fatal error(</b>)?\s*:", 0.9, "PHP fatal error leaked"),
    ])]
    homepage = _mock_response(headers={}, body="nothing interesting here")
    baseline_404 = _mock_response(
        status=404,
        body="<b>Fatal error</b>: Uncaught Error: Call to undefined function in /var/www/html/x.php on line 42",
    )

    with patch("phpdetector.scanner.requests.get", side_effect=[homepage, baseline_404]):
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert result.php_probability == pytest.approx(0.9)
    assert result.engine_matches and result.engine_matches[0].evidence == [(0.9, "PHP fatal error leaked")]


# --- tier 3: structural probes (only fire if tiers 1-2 stay ambiguous) ---

def test_front_controller_200_is_detected():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    not_found = _mock_response(status=404, body="")  # tier2 baseline, tier3 raw baseline, .php ext check
    index_200 = _mock_response(status=200, body="")  # /index.php

    with patch(
        "phpdetector.scanner.requests.get",
        side_effect=[homepage, not_found, not_found, not_found, index_200, not_found],
    ):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])

    assert result.structural_probed is True
    assert result.php_probability == pytest.approx(FRONT_CONTROLLER_200_WEIGHT)
    assert any(d == "/index.php returns 200 directly" for _, d in result.structural_evidence)


def test_extension_behavior_difference_is_detected():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    baseline_404 = _mock_response(status=404, body="")  # tier2 baseline
    raw_baseline_404 = _mock_response(status=404, body="")  # tier3's own fresh raw baseline
    ext_500 = _mock_response(status=500, body="")  # .php gets a different status
    index_404 = _mock_response(status=404, body="")
    slash_404 = _mock_response(status=404, body="")

    with patch(
        "phpdetector.scanner.requests.get",
        side_effect=[homepage, baseline_404, raw_baseline_404, ext_500, index_404, slash_404],
    ):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])

    assert result.php_probability == pytest.approx(EXTENSION_BEHAVIOR_WEIGHT)
    assert any("different raw status" in d for _, d in result.structural_evidence)


def test_custom_error_page_is_detected():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    custom_404_body = "<html><body><h1>Oops, nothing here</h1>" + "x" * 200 + "</body></html>"
    custom_404 = _mock_response(status=404, body=custom_404_body)
    not_found = _mock_response(status=404, body=custom_404_body)  # identical body -> no extension signal

    with patch(
        "phpdetector.scanner.requests.get",
        side_effect=[homepage, custom_404, not_found, not_found, not_found, not_found],
    ):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])

    assert result.php_probability == pytest.approx(CUSTOM_ERROR_PAGE_WEIGHT)
    assert any("isn't a default Apache/nginx template" in d for _, d in result.structural_evidence)


def test_default_apache_404_page_is_not_flagged_as_custom():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    apache_body = (
        "<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>"
        "<hr><address>Apache/2.4.41 (Ubuntu) Server at example.test Port 80</address>" + "x" * 150
        + "</body></html>"
    )
    apache_404 = _mock_response(status=404, body=apache_body)

    with patch(
        "phpdetector.scanner.requests.get",
        side_effect=[homepage, apache_404, apache_404, apache_404, apache_404, apache_404],
    ):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])

    assert result.php_probability == 0.0
    assert result.structural_evidence == []


def test_trailing_slash_redirect_is_detected():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    call_count = {"n": 0}

    def side_effect(url, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return homepage
        path = urlparse(url).path
        if "/phpdetector-slash-check-" in path:
            resp = _mock_response(status=301, body="")
            resp.headers = {"Location": path + "/"}
            return resp
        return _mock_response(status=404, body="")

    with patch("phpdetector.scanner.requests.get", side_effect=side_effect):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])

    assert result.php_probability == pytest.approx(TRAILING_SLASH_WEIGHT)
    assert any("trailing slash" in d for _, d in result.structural_evidence)


def test_structural_probes_do_not_fire_on_a_confident_first_pass():
    engine_db = _php_header_engine_db()
    homepage = _mock_response(headers={"X-Powered-By": "PHP/8.3.0"})

    with patch("phpdetector.scanner.requests.get", return_value=homepage) as mock_get:
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert mock_get.call_count == 1
    assert result.structural_probed is False
    assert result.structural_evidence == []


# --- tier 4: --permission only ---

def test_permission_probe_not_used_without_the_flag():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    not_found = _mock_response(status=404, body="")

    with patch("phpdetector.scanner.requests.get", side_effect=[homepage] + [not_found] * 10) as mock_get:
        result = scan_one("http://example.test", cve_db=[], engine_db=[], permission=False)

    assert result.permission_probe_used is False
    # tiers 1-3 only: homepage + tier2 baseline + tier3's (raw baseline + ext + index.php + trailing-slash).
    assert mock_get.call_count == 6


def test_permission_probe_fires_when_enabled_and_still_ambiguous():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    not_found = _mock_response(status=404, body="")
    warning_leak = _mock_response(
        status=200,
        body="Warning: array_map() expects parameter 2 to be array in /var/www/html/index.php on line 7",
    )

    with patch(
        "phpdetector.scanner.requests.get",
        side_effect=[homepage, not_found, not_found, not_found, not_found, not_found, warning_leak],
    ) as mock_get:
        result = scan_one("http://example.test", cve_db=[], engine_db=[], permission=True)

    assert mock_get.call_count == 7
    assert result.permission_probe_used is True
    assert result.php_probability == pytest.approx(MALFORMED_INPUT_WEIGHT)
    assert any("array-typed query parameter" in d for _, d in result.structural_evidence)


def test_permission_probe_skipped_when_already_confident():
    engine_db = _php_header_engine_db()
    homepage = _mock_response(headers={"X-Powered-By": "PHP/8.3.0"})

    with patch("phpdetector.scanner.requests.get", return_value=homepage) as mock_get:
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db, permission=True)

    assert mock_get.call_count == 1
    assert result.permission_probe_used is False


# --- positive_signals: the unified "why this score" view ---

def test_positive_signals_aggregates_every_tier_sorted_by_weight():
    engine_db = [
        EngineFingerprint("WordPress", signals=[
            Signal(SignalKind.COOKIE, "wordpress_logged_in_", 0.85, "wordpress_logged_in_ cookie"),
        ]),
    ]
    homepage = _mock_response(
        headers={}, cookies=["wordpress_logged_in_abc"], body="nothing interesting here",
    )

    with patch("phpdetector.scanner.requests.get", return_value=homepage):
        result = scan_one("http://example.test/index.php", cve_db=[], engine_db=engine_db)

    signals = result.positive_signals
    # Highest weight first: the URL-extension hint (0.9) beats the cookie match (0.85).
    assert [w for w, _ in signals] == sorted((w for w, _ in signals), reverse=True)
    descriptions = [d for _, d in signals]
    assert any("wordpress_logged_in_ cookie" in d and "WordPress" in d for d in descriptions)
    assert any(d == "requested URL itself ends in .php" for d in descriptions)


def test_positive_signals_empty_when_nothing_matched():
    homepage = _mock_response(headers={}, body="nothing interesting here")
    not_found = _mock_response(status=404, body="")

    with patch("phpdetector.scanner.requests.get", side_effect=[homepage] + [not_found] * 10):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])

    assert result.positive_signals == []
