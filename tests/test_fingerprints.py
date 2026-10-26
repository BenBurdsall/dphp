import pytest

from phpdetector.fingerprints import (
    EngineFingerprint,
    Signal,
    SignalKind,
    combine_noisy_or,
    evaluate_all_engines,
    evaluate_engine,
    load_engine_db,
)


def test_combine_noisy_or_empty():
    assert combine_noisy_or([]) == 0.0


def test_combine_noisy_or_increases_with_more_signals():
    one = combine_noisy_or([0.5])
    two = combine_noisy_or([0.5, 0.5])
    assert two > one
    assert 0 < one < 1
    assert 0 < two < 1


def test_evaluate_engine_cookie_signal():
    engine = EngineFingerprint("Moodle", signals=[
        Signal(SignalKind.COOKIE, "MoodleSession", 0.85, "MoodleSession cookie"),
    ])
    score, evidence = evaluate_engine(engine, headers={}, cookie_text="MoodleSession=abc123", body_text="")
    assert score == pytest.approx(0.85)
    assert evidence == [(0.85, "MoodleSession cookie")]


def test_evaluate_engine_no_match():
    engine = EngineFingerprint("Moodle", signals=[
        Signal(SignalKind.COOKIE, "MoodleSession", 0.85, "MoodleSession cookie"),
    ])
    score, evidence = evaluate_engine(engine, headers={}, cookie_text="unrelated=1", body_text="")
    assert score == 0.0
    assert evidence == []


def test_evaluate_engine_path_signal_requires_probe_result():
    engine = EngineFingerprint("WordPress", signals=[
        Signal(SignalKind.PATH, "/wp-login.php", 0.6, "/wp-login.php reachable"),
    ])
    # Not probed at all -> no evidence either way.
    score, _ = evaluate_engine(engine, headers={}, cookie_text="", body_text="", path_probe_results={})
    assert score == 0.0

    # Probed and found.
    score, evidence = evaluate_engine(
        engine, headers={}, cookie_text="", body_text="",
        path_probe_results={"/wp-login.php": (200, "")},
    )
    assert score == pytest.approx(0.6)
    assert evidence

    # Probed and 404.
    score, _ = evaluate_engine(
        engine, headers={}, cookie_text="", body_text="",
        path_probe_results={"/wp-login.php": (404, "")},
    )
    assert score == 0.0


def test_evaluate_engine_path_signal_ignored_when_matches_baseline():
    """A catch-all that answers every path with the same status (e.g.
    200 for everything via an SPA fallback) must not look like the path
    exists."""
    engine = EngineFingerprint("WordPress", signals=[
        Signal(SignalKind.PATH, "/wp-login.php", 0.6, "/wp-login.php reachable"),
    ])
    score, evidence = evaluate_engine(
        engine, headers={}, cookie_text="", body_text="",
        path_probe_results={"/wp-login.php": (200, "")},
        baseline_status=200,
    )
    assert score == 0.0
    assert evidence == []

    # Same status code as a real hit, but baseline differs -> counts.
    score, evidence = evaluate_engine(
        engine, headers={}, cookie_text="", body_text="",
        path_probe_results={"/wp-login.php": (200, "")},
        baseline_status=404,
    )
    assert score == pytest.approx(0.6)
    assert evidence


def test_evaluate_engine_path_signal_never_counts_403():
    """A 403 on a well-known path like /wp-login.php is at least as
    likely to be a WAF/CDN managed ruleset blocking known attack-surface
    paths on every site it protects (regardless of backend) as it is to
    mean the path genuinely exists -- confirmed live against a non-PHP
    site. It must never count as a hit, baseline or no baseline."""
    engine = EngineFingerprint("WordPress", signals=[
        Signal(SignalKind.PATH, "/wp-login.php", 0.6, "/wp-login.php reachable"),
    ])
    score, evidence = evaluate_engine(
        engine, headers={}, cookie_text="", body_text="",
        path_probe_results={"/wp-login.php": (403, "")},
        baseline_status=404,  # differs from baseline -- still must not count
    )
    assert score == 0.0
    assert evidence == []


def test_evaluate_all_engines_combines_php_probability():
    engines = [
        EngineFingerprint("PHP", signals=[
            Signal(SignalKind.HEADER, r"PHP/\d", 0.95, "X-Powered-By PHP version", header_name="X-Powered-By"),
        ]),
        EngineFingerprint("WordPress", signals=[
            Signal(SignalKind.COOKIE, "wordpress_logged_in_", 0.85, "wordpress_logged_in_ cookie"),
        ]),
    ]
    matches, php_probability = evaluate_all_engines(
        engines,
        headers={"X-Powered-By": "PHP/8.2.1"},
        cookie_text="wordpress_logged_in_abc=1",
        body_text="",
    )
    names = {m.name for m in matches}
    assert names == {"PHP", "WordPress"}
    # Two independent signals both implying PHP should combine to something
    # higher than either alone.
    assert php_probability > 0.95


def test_load_engine_db_from_real_data_file():
    engines = load_engine_db()
    names = {e.name for e in engines}
    for expected in (
        "PHP", "WordPress", "WooCommerce", "Drupal", "Joomla", "Laravel", "Moodle",
        "phpMyAdmin", "Nextcloud", "CodeIgniter", "CakePHP", "TYPO3", "Roundcube",
    ):
        assert expected in names
    for engine in engines:
        assert engine.signals, f"{engine.name} has no signals"
        for sig in engine.signals:
            assert 0.0 <= sig.weight <= 1.0


def test_php_engine_detects_leaked_fatal_error_in_html():
    engines = load_engine_db()
    php_engine = next(e for e in engines if e.name == "PHP")
    # Realistic html_errors=On PHP output: tags interposed between words.
    score, evidence = evaluate_engine(
        php_engine, headers={}, cookie_text="",
        body_text=(
            "<b>Fatal error</b>:  Uncaught Error: Call to undefined function foo() "
            "in <b>/var/www/html/index.php</b> on line <b>12</b>"
        ),
    )
    assert score > 0.9
    assert len(evidence) >= 2  # multiple independent error-leak signals fired
