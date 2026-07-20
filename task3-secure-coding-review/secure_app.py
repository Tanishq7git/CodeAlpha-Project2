"""
VulnBank - Secure Version
--------------------------
Remediated version of vulnerable_app.py addressing every finding
in security_review_report.md (VULN-01 through VULN-08).
"""

import secrets
import subprocess
import sqlite3
from pathlib import Path

from flask import Flask, request, send_from_directory, abort
from markupsafe import escape, Markup
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # FIX (VULN-04): strong, random secret; load from env var in production

DB_PATH = "users.db"
UPLOAD_DIR = Path("uploads").resolve()


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # FIX (VULN-01): parameterized query prevents SQL injection
    conn = get_db()
    cursor = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    # FIX (VULN-06): verify against a salted hash, never plaintext
    if row and check_password_hash(row[0], password):
        return "Welcome " + escape(username)  # FIX (VULN-05): output escaped, prevents XSS
    return "Invalid credentials"


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not username or not password:
        abort(400)

    # FIX (VULN-06): strong, salted password hashing (PBKDF2 via Werkzeug)
    password_hash = generate_password_hash(password)

    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        abort(409)
    return "Registered"


@app.route("/search")
def search():
    name = request.args.get("name", "")
    # FIX (VULN-05): Markup().format() escapes the interpolated value only,
    # leaving the trusted HTML wrapper intact (plain str + Markup would
    # incorrectly escape the wrapper too)
    return Markup("<h1>Results for: {}</h1>").format(name)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # FIX (VULN-02): strict allow-list validation + list-form subprocess call, no shell
    if not host.replace(".", "").isalnum():
        abort(400, "Invalid host")
    try:
        result = subprocess.run(["ping", "-c", "1", host], capture_output=True, timeout=5)
        return "Pinged with return code: " + str(result.returncode)
    except subprocess.TimeoutExpired:
        return "Ping timed out"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # FIX (VULN-07): sanitize filename and confine access to the uploads directory
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(400)
    full_path = (UPLOAD_DIR / safe_name).resolve()
    if UPLOAD_DIR not in full_path.parents and full_path != UPLOAD_DIR:
        abort(403)
    return send_from_directory(UPLOAD_DIR, safe_name)


# FIX (VULN-03): the /load-session pickle endpoint has been removed entirely.
# Untrusted deserialization should never be exposed. If cross-request session
# data is needed, use a signed, structured format (JSON + itsdangerous) instead.


if __name__ == "__main__":
    init_db()
    # FIX (VULN-08): debug mode disabled, bound to localhost only.
    # Use a production WSGI server (gunicorn/uWSGI) behind a reverse proxy.
    app.run(debug=False, host="127.0.0.1", port=5000)
