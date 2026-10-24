# phpDetector

A small toolkit for finding PHP backends:

- **`files`** — scan a local file or directory for PHP, by file extension
  or a `<?php` / `<?=` tag in the content.
- **`urls`** — fingerprint a URL, or a list of URLs, for an exposed PHP
  backend and the CMS/framework on top of it (WordPress, WooCommerce,
  Drupal, Joomla, Magento, MediaWiki, phpBB, vBulletin, MyBB, Laravel,
  Symfony, Moodle, ...), then cross-check the detected PHP version
  against a small CVE database.

## ⚠️ Authorization

`urls` mode only sends ordinary GET requests and reads response
headers/cookies/HTML — the same thing a browser does, never an exploit
payload. Even so, **only point it at hosts you own or are explicitly
authorized to test.**

## Usage

```bash
# local files
python main.py files [path]            # default: current directory

# a single URL
python main.py urls https://example.com

# a list of URLs (one per line, '#' comments allowed) -- see urls.example.txt
python main.py urls my_urls.txt

# machine-readable output
python main.py urls my_urls.txt --json
python main.py urls my_urls.txt --csv results.csv
```

That's the whole interface — no scan tuning flags. Every URL gets one
GET request. If the headers/cookies/HTML from that single request are
already a confident PHP/CMS match, the scan stops there. If they're
ambiguous, phpDetector automatically escalates to a second round of GET
requests to a handful of well-known CMS paths (`/wp-login.php`,
`/administrator/`, `/wiki/`, ...) to gather stronger evidence, and
compares them against a baseline nonexistent path so a WAF or catch-all
route that answers every path identically doesn't look like a match.

## How detection works

Fingerprints live in `data/fingerprints.json`, not in code — edit that
file to add a cookie pattern, a header, an HTML snippet, or a path, and
tune any signal's `weight` without touching Python. Each signal is one
observable fact (e.g. a `wordpress_logged_in_` cookie) with a weight in
`[0, 1]`: how confident that signal alone makes us that the fact implies
a PHP backend. Multiple matched signals for an engine combine with a
noisy-OR (`1 - product(1 - w_i)`), and each matched engine's score in
turn contributes to one overall PHP-backend probability the same way.
These weights are hand-set priors based on how unique each artifact is
in practice, not an empirically calibrated model — treat the resulting
score as a triage aid for prioritizing manual review, not ground truth.

## CVE cross-check

`data/vulnerabilities.json` holds the CVEs to check detected PHP
versions against (currently CVE-2026-109618 and CVE-2026-109619). Each
entry's `affected_versions` is a [PEP 440 specifier](https://packaging.pypa.io/en/stable/specifiers.html)
(e.g. `">=8.1.0,<8.1.30"`). **Both entries ship with `affected_versions:
"UNKNOWN"`** — I didn't have a verified version range for either CVE, so
rather than guess, the scanner reports those as "needs manual follow-up"
instead of a real verdict. Fill in the real range from the official PHP
advisory / NVD entry once you have it, and matching starts working
immediately — no code changes needed. A CVE's risk score in the output
reflects *detection confidence* (how sure we are this is a PHP backend,
in or out of the affected range), not a modeled probability of
successful exploitation.

## Development

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest
```
