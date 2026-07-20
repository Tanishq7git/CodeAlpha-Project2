# Task 3: Secure Coding Review

A secure code review of a small Flask application, combining static analysis (Bandit) and manual inspection to find and fix 8 real-world vulnerability classes.

## Files
- `vulnerable_app.py` — the audited application (contains intentional vulnerabilities)
- `secure_app.py` — the remediated, secure version
- `security_review_report.md` — full findings report with severity, CWE mapping, and remediation steps

## Vulnerabilities Found & Fixed
| # | Vulnerability | Severity |
|---|---|---|
| 1 | SQL Injection | Critical |
| 2 | OS Command Injection | Critical |
| 3 | Insecure Deserialization (pickle) | Critical |
| 4 | Hardcoded Secret Key | High |
| 5 | Reflected XSS | High |
| 6 | Weak Password Hashing (MD5) | High |
| 7 | Path Traversal | High |
| 8 | Insecure Debug Configuration | Medium |

## Tools Used
Bandit (static analyzer) + manual line-by-line code review.

## How to Run
```bash
pip install flask
python3 vulnerable_app.py     # vulnerable version, for demonstration
python3 secure_app.py         # remediated version
```

## Screenshot
_Add a screenshot of the Bandit scan output and/or a before/after attack test:_
`![Bandit scan results](screenshots/bandit_scan.png)`

See `security_review_report.md` for the full write-up.
