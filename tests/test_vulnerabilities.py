from phpdetector.vulnerabilities import CVEDefinition, FixedVersionTable, load_cve_db

TABLE = FixedVersionTable(
    fixed_in={"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"},
    unsupported_branches_affected=True,
)


def _cve(affected_versions):
    return CVEDefinition("CVE-TEST-0000", "t", "Critical", 9.2, "s", affected_versions, [])


# --- legacy plain PEP 440 specifier path (kept for backward compatibility) ---

def test_unknown_range_returns_none():
    assert _cve("UNKNOWN").matches("8.1.0") is None


def test_known_range_true_and_false():
    cve = _cve(">=8.1.0,<8.1.5")
    assert cve.matches("8.1.2") is True
    assert cve.matches("8.1.9") is False


def test_unparseable_version_returns_none():
    assert _cve(">=8.1.0").matches("not-a-version") is None


# --- fixed-version-table path ---

def test_version_below_branch_fix_is_vulnerable():
    cve = _cve(TABLE)
    verdict, reason = cve.explain("8.3.10")
    assert verdict is True
    assert "8.3.36" in reason


def test_version_at_or_above_branch_fix_is_not_vulnerable():
    cve = _cve(TABLE)
    assert cve.matches("8.3.36") is False
    assert cve.matches("8.3.99") is False


def test_eol_branch_below_oldest_listed_is_vulnerable():
    cve = _cve(TABLE)
    verdict, reason = cve.explain("8.1.27")
    assert verdict is True
    assert "EOL" in reason or "never" in reason.lower()


def test_eol_branch_can_be_opted_out():
    table = FixedVersionTable(fixed_in=TABLE.fixed_in, unsupported_branches_affected=False)
    cve = _cve(table)
    assert cve.matches("8.1.27") is None


def test_branch_newer_than_newest_listed_is_not_vulnerable():
    cve = _cve(TABLE)
    assert cve.matches("9.0.0") is False
    assert cve.matches("8.6.0") is False


def test_load_real_cve_db_parses_fixed_version_tables():
    cves = load_cve_db()
    ids = {c.cve_id for c in cves}
    assert "CVE-2026-109618" in ids
    assert "CVE-2026-109619" in ids
    for cve in cves:
        assert isinstance(cve.affected_versions, FixedVersionTable)
        assert cve.matches("8.3.36") is False  # patched
        assert cve.matches("8.3.10") is True  # unpatched in a listed branch
