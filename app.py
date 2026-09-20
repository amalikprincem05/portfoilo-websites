"""Ayzaz portfolio backend (Python + Flask + SQLite)."""
import hmac
import os
import re
import sqlite3
import time
from collections import defaultdict, deque
from flask import Flask, jsonify, render_template, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "messages.db")

# Default password 'admin123' set kar diya gaya hai
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "admin123")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024

_hits = defaultdict(lambda: deque(maxlen=5))


def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute(
        """CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, email TEXT NOT NULL,
            subject TEXT NOT NULL, message TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"""
    )
    return con


def rate_limited(ip, window=600, limit=5):
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/admin")
def admin():
    return render_template("admin.html")


@app.post("/api/contact")
def contact():
    if rate_limited(request.remote_addr or "unknown"):
        return jsonify(error="Too many messages. Please try again later."), 429
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:100]
    email = str(data.get("email", "")).strip()[:150]
    subject = str(data.get("subject", "")).strip()[:150]
    message = str(data.get("message", "")).strip()[:3000]
    if not (name and subject and message and EMAIL_RE.match(email)):
        return jsonify(error="Please fill in all fields with a valid email."), 400
    con = get_db()
    with con:
        con.execute(
            "INSERT INTO messages(name,email,subject,message) VALUES(?,?,?,?)",
            (name, email, subject, message),
        )
    con.close()
    return jsonify(ok=True)


@app.get("/api/messages")
def messages():
    token = request.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or not hmac.compare_digest(token, ADMIN_TOKEN):
        return jsonify(error="Not authorised."), 401
    con = get_db()
    rows = [dict(r) for r in con.execute("SELECT * FROM messages ORDER BY id DESC")]
    con.close()
    return jsonify(rows)


@app.delete("/api/messages/<int:msg_id>")
def delete_message(msg_id):
    token = request.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or not hmac.compare_digest(token, ADMIN_TOKEN):
        return jsonify(error="Not authorised."), 401
    con = get_db()
    with con:
        con.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    con.close()
    return jsonify(ok=True)


@app.delete("/api/messages")
def delete_all_messages():
    token = request.headers.get("X-Admin-Token", "")
    if not ADMIN_TOKEN or not hmac.compare_digest(token, ADMIN_TOKEN):
        return jsonify(error="Not authorised."), 401
    con = get_db()
    with con:
        con.execute("DELETE FROM messages")
    con.close()
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=int(os.environ.get("PORT", 5000)))