"""Vulnerable Flask web app — the SENTINEL demo target.

Intentionally vulnerable to: SQL injection (sqlite), weak / reused
credentials, open directory listing, verbose error messages, session
misconfiguration.  Every request is emitted in syslog-style format so
the flow sensor pipeline can ingest and score it.

Port 5000.  Run standalone for development; Docker for the demo stack.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, abort, g, jsonify, redirect, request, session, url_for

# ── Logging — one syslog line per request ────────────────────────────
LOG_PATH = Path("/logs/access.log")


def _log(msg: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, "a") as f:
        print(msg, file=f, flush=True)


def _log_request(status: int = 200) -> None:
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    src = request.remote_addr or "127.0.0.1"
    _log(
        f"{ts} demo-sentinel http src={src} "
        f"dst=127.0.0.1 dport=5000 "
        f"method={request.method} path={request.path} "
        f"status={status}"
    )


# ── Database ────────────────────────────────────────────────────────
DB_PATH = Path("apps/vulnerable/app.db")


def _get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
    return g.db


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH))
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            secret TEXT NOT NULL
        );
        """
    )
    # Seed data
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", hashlib.md5(b"admin").hexdigest()),
        )
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("user", hashlib.md5(b"password").hexdigest()),
        )
        db.commit()
    if db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0:
        for i in range(1, 11):
            db.execute(
                "INSERT INTO items (name, secret) VALUES (?, ?)",
                (f"Item-{i}", f"SECRET-{i}-DATA"),
            )
        db.commit()
    db.close()


# ── Flask app ───────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "weak-secret-key-123")
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = False  # Intentionally weak
app.config["DEBUG"] = True  # Verbose error pages (intentional)

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()


@app.before_request
def before_request():
    g.start = time.time()


@app.after_request
def after_request(response):
    _log_request(response.status_code)
    return response


# ── Routes ──────────────────────────────────────────────────────────
@app.route("/")
def index():
    return """
    <h1>Sentinel Demo App</h1>
    <ul>
        <li><a href="/login">Login</a> (weak: admin / admin)</li>
        <li><a href="/search">Search</a> (SQL injection)</li>
        <li><a href="/comments">Comments</a> (XSS)</li>
        <li><a href="/api/items">API Items</a></li>
        <li><a href="/admin">Admin Panel</a></li>
    </ul>
    <p>Use <a href="http://localhost:5001">Sentinel Dashboard</a> to monitor.</p>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    """Weak login — SQL injection on password field, verbose errors."""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # Intentionally vulnerable: raw string formatting in SQL
        db = _get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            user = db.execute(query).fetchone()
            if user:
                session["user"] = dict(user)
                session["ip"] = request.remote_addr
                return redirect(url_for("dashboard"))
            else:
                return "<h3>Invalid credentials</h3><p><a href='/login'>Try again</a></p>", 401
        except Exception as e:
            # Intentionally verbose error — leaks SQL to attacker
            return f"<h3>SQL Error</h3><pre>{query}\n\n{e}</pre>", 500
    return """
    <h2>Login</h2>
    <form method="post">
        Username: <input name="username" /><br/>
        Password: <input name="password" type="password" /><br/>
        <input type="submit" value="Login" />
    </form>
    <p>Hint: admin / admin (or try SQLi: ' OR 1=1 --)</p>
    """


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    db = _get_db()
    items = db.execute("SELECT * FROM items").fetchall()
    comments = db.execute("SELECT * FROM comments ORDER BY created_at DESC LIMIT 20").fetchall()
    return f"""
    <h2>Welcome {user['username']}!</h2>
    <h3>Items</h3>
    <ul>{''.join(f"<li>{r['name']}: {r['secret']}</li>" for r in items)}</ul>
    <h3>Recent Comments</h3>
    <ul>{''.join(f"<li>{r['content']}</li>" for r in comments)}</ul>
    <p><a href="/search">Search</a> | <a href="/comments">Add Comment</a> | <a href="/api/items">API</a> | <a href="/logout">Logout</a></p>
    """


@app.route("/search")
def search():
    q = request.args.get("q", "")
    if not q:
        return """
        <h2>Search</h2>
        <form method="get">
            <input name="q" placeholder="Search items..." />
            <input type="submit" value="Search" />
        </form>
        """
    db = _get_db()
    # SQL injection: raw string formatting
    query = f"SELECT * FROM items WHERE name LIKE '%{q}%'"
    try:
        results = db.execute(query).fetchall()
        items_html = "".join(f"<li>{r['name']}: {r['secret']}</li>" for r in results)
        return f"<h2>Search Results</h2><p>Query: <code>{q}</code></p><ul>{items_html}</ul>"
    except Exception as e:
        return f"<h2>Search Error</h2><pre>{query}\n\n{e}</pre>", 500


@app.route("/comments", methods=["GET", "POST"])
def comments():
    """Stored XSS — comments are rendered without sanitization."""
    db = _get_db()
    if request.method == "POST":
        content = request.form.get("content", "")
        user = session.get("user")
        db.execute(
            "INSERT INTO comments (user_id, content) VALUES (?, ?)",
            (user["id"] if user else None, content),
        )
        db.commit()
        return redirect(url_for("comments"))
    comments = db.execute("SELECT * FROM comments ORDER BY created_at DESC").fetchall()
    return f"""
    <h2>Comments</h2>
    <form method="post">
        <textarea name="content" rows="3" cols="50"></textarea><br/>
        <input type="submit" value="Post" />
    </form>
    <h3>All Comments</h3>
    <div id="comments">
        {''.join(f'<div class="comment">{r["content"]}</div>' for r in comments)}
    </div>
    <p>Try: &lt;script&gt;alert('xss')&lt;/script&gt;</p>
    """


@app.route("/api/items")
def api_items():
    db = _get_db()
    items = [dict(r) for r in db.execute("SELECT * FROM items").fetchall()]
    return jsonify({"items": items, "count": len(items)})


@app.route("/admin")
def admin():
    """Open admin — no authentication check (intentional vulnerability)."""
    db = _get_db()
    users = db.execute("SELECT id, username FROM users").fetchall()
    comments = db.execute("SELECT * FROM comments").fetchall()
    return f"""
    <h2>Admin Panel (UNSECURED)</h2>
    <h3>Users</h3>
    <ul>{''.join(f"<li>{r['username']} (ID: {r['id']})</li>" for r in users)}</ul>
    <h3>All Comments</h3>
    <ul>{''.join(f"<li>{r['content']}</li>" for r in comments)}</ul>
    <p><a href="/admin/users.json">Export users (JSON)</a></p>
    """


@app.route("/admin/users.json")
def admin_users_json():
    """Leak all users — no auth check."""
    db = _get_db()
    users = [dict(r) for r in db.execute("SELECT * FROM users").fetchall()]
    return jsonify({"users": users})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Entry point ─────────────────────────────────────────────────────
def create_app() -> Flask:
    _init_db()
    return app


if __name__ == "__main__":
    _init_db()
    app.run(host="0.0.0.0", port=5000)
