"""
VulnBank - Simple User Management Web App (Flask)
----------------------------------------------------
This application is the AUDIT TARGET for a secure coding review.
It intentionally contains common real-world vulnerability classes
(OWASP Top 10 style) for training/review purposes.

DO NOT DEPLOY. For educational code-review use only.
"""

import os
import sqlite3
import hashlib
import pickle
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)
app.secret_key = "supersecret123"  # VULN-04: hardcoded secret key

DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # VULN-01: SQL Injection - user input concatenated directly into query
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    conn = get_db()
    cursor = conn.execute(query)
    user = cursor.fetchone()

    if user:
        return "Welcome " + username  # VULN-05: reflected input, unescaped
    return "Invalid credentials"


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username")
    password = request.form.get("password")

    # VULN-06: weak/broken hashing algorithm for stored passwords
    hashed = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
    conn.commit()
    return "Registered"


@app.route("/search")
def search():
    name = request.args.get("name", "")
    # VULN-05: reflected XSS - user input rendered directly into an HTML template
    template = "<h1>Results for: " + name + "</h1>"
    return render_template_string(template)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # VULN-02: OS command injection - unsanitized input passed to a shell
    result = os.system("ping -c 1 " + host)
    return "Pinged with result: " + str(result)


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # VULN-07: path traversal - no sanitization of the requested filename
    return send_file("uploads/" + filename)


@app.route("/load-session", methods=["POST"])
def load_session():
    data = request.data
    # VULN-03: insecure deserialization - untrusted pickle data
    session_obj = pickle.loads(data)
    return "Session loaded for: " + str(session_obj)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0")  # VULN-08: debug mode + bind to all interfaces
