# Phishing URL Analyzer

[![Tests](https://github.com/evankaparekh/phishing-url-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/evankaparekh/phishing-url-analyzer/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An explainable Python security tool that scores URLs for common phishing indicators **without
opening the URL or making a network request**. Each result includes a 0–100 risk score, a LOW,
MEDIUM, or HIGH rating, and plain-language reasons for the score.

## Why I built it

Phishing links often rely on recognizable tricks: misleading IP addresses, URL shorteners,
lookalike domains, excessive subdomains, encoded characters, and urgent account-related words.
This project turns those signals into a transparent score instead of returning an unexplained
yes-or-no answer.

## Features

- Detects 10 common suspicious URL patterns
- Explains every score contribution
- Analyzes one URL or a file of URLs
- Produces readable text or JSON output
- Never contacts the submitted host
- Includes automated tests and GitHub Actions CI
- Uses only the Python standard library at runtime

## Quick start

```bash
git clone https://github.com/evankaparekh/phishing-url-analyzer.git
cd phishing-url-analyzer
python -m venv .venv
```

Activate the environment:

```bash
# Windows PowerShell
.venv\Scripts\Activate.ps1

# macOS/Linux
source .venv/bin/activate
```

Install the project and run it:

```bash
pip install -e .
phishcheck --url "http://192.0.2.10/login/verify-account"
```

Example output:

```text
URL:   http://192.0.2.10/login/verify-account
Host:  192.0.2.10
Risk:  HIGH (70/100)
Why:
  +15  The URL does not use HTTPS.
  +25  An IP address is used instead of a domain name.
  +30  Sensitive-action words found: account, login, verify.
```

Analyze the included sample file or request JSON:

```bash
phishcheck --file sample_urls.txt
phishcheck --url "https://example.com" --json
```

## Detection rules

| Signal | Points | Why it matters |
|---|---:|---|
| Non-HTTPS URL | 15 | Traffic is not protected by TLS |
| IP address as host | 25 | Can bypass normal domain recognition |
| Punycode hostname | 20 | May imitate familiar characters or brands |
| `@` in authority | 20 | Can visually disguise the actual host |
| URL shortener | 20 | Hides the final destination |
| Long URL | 10 | Can bury misleading details |
| Many subdomains | 10 | Can put a trusted-looking word far from the real domain |
| Many hostname hyphens | 10 | Common in hastily made lookalike domains |
| Percent-encoded text | 10 | Can conceal readable URL content |
| Unusual port | 10 | May indicate a nonstandard service |
| Sensitive-action words | 10 each, max 30 | Often used to create urgency or request credentials |

Scores are capped at 100: **LOW** is 0–19, **MEDIUM** is 20–39, and **HIGH** is 40–100.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

## Project structure

```text
phishing-url-analyzer/
├── .github/workflows/tests.yml
├── phishing_analyzer/
│   ├── __init__.py
│   ├── analyzer.py
│   └── cli.py
├── tests/test_analyzer.py
├── sample_urls.txt
├── pyproject.toml
├── SECURITY.md
└── README.md
```

## Limitations

This is an educational, rule-based analyzer. Attackers can create dangerous links that do not
match these patterns, and legitimate links can trigger them. A LOW score is not proof that a URL
is safe. Production detection should also use reputation data, DNS/WHOIS context, certificate
information, page-content analysis, and trained models.

## Ethics

Use this project only for defensive security, education, and URLs you are authorized to analyze.
Do not open suspicious links while testing.

## License

MIT License. See [LICENSE](LICENSE).
