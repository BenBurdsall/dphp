from unittest.mock import Mock, patch

import requests

from phpdetector.fingerprints import EngineFingerprint, Signal, SignalKind
from phpdetector.scanner import scan_one
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
    that must not be treated as evidence the real paths exist."""
    engine_db = [EngineFingerprint("WordPress", signals=[
        Signal(SignalKind.PATH, "/wp-login.php", 0.6, "/wp-login.php reachable"),
    ])]
    homepage = _mock_response(headers={}, body="nothing interesting here")
    baseline_403 = _mock_response(status=403, body="forbidden")
    probe_403 = _mock_response(status=403, body="forbidden")

    with patch("phpdetector.scanner.requests.get", side_effect=[homepage, baseline_403, probe_403]):
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert result.php_probability == 0.0
    assert result.engine_matches == []


def test_confident_first_pass_does_not_probe():
    engine_db = _php_header_engine_db()
    homepage = _mock_response(headers={"X-Powered-By": "PHP/8.3.0"})

    with patch("phpdetector.scanner.requests.get", return_value=homepage) as mock_get:
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)

    assert mock_get.call_count == 1
    assert result.probed_paths is False


def test_no_php_detected():
    engine_db = _php_header_engine_db()
    resp = _mock_response(headers={"Server": "nginx"})
    with patch("phpdetector.scanner.requests.get", return_value=resp):
        result = scan_one("http://example.test", cve_db=[], engine_db=engine_db)
    assert not result.php_detected
    assert result.cve_assessments == []


def test_unreachable_url():
    with patch("phpdetector.scanner.requests.get", side_effect=requests.ConnectionError("boom")):
        result = scan_one("http://example.test", cve_db=[], engine_db=[])
    assert not result.reachable
    assert result.error
