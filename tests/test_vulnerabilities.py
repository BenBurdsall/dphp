from phpdetector.vulnerabilities import CVEDefinition


def test_unknown_range_returns_none():
    cve = CVEDefinition("CVE-TEST-0001", "t", "Critical", 9.2, "s", "UNKNOWN", [])
    assert cve.matches("8.1.0") is None


def test_known_range_true_and_false():
    cve = CVEDefinition("CVE-TEST-0002", "t", "Critical", 9.2, "s", ">=8.1.0,<8.1.5", [])
    assert cve.matches("8.1.2") is True
    assert cve.matches("8.1.9") is False


def test_unparseable_version_returns_none():
    cve = CVEDefinition("CVE-TEST-0003", "t", "Critical", 9.2, "s", ">=8.1.0", [])
    assert cve.matches("not-a-version") is None
