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
import time
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, g, jsonify, redirect, request, session, url_for

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


# ── Shared CSS ──────────────────────────────────────────────────────
_SHARED_CSS = """
:root {
  --bg: #0f1219;
  --bg2: #161b26;
  --bg3: #1c2333;
  --border: #2a3548;
  --text: #e2e8f0;
  --text2: #94a3b8;
  --text3: #64748b;
  --blue: #3b82f6;
  --blue-dim: #1e3a5f;
  --green: #10b981;
  --green-dim: #064e3b;
  --red: #ef4444;
  --red-dim: #7f1d1d;
  --amber: #f59e0b;
  --purple: #8b5cf6;
  --radius: 10px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',-apple-system,system-ui,sans-serif;
  background:var(--bg);color:var(--text);
  min-height:100vh;line-height:1.6
}
.container{max-width:900px;margin:0 auto;padding:2rem 1.5rem}
a{color:var(--blue);text-decoration:none}
a:hover{text-decoration:underline}
.card{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:var(--radius);padding:1.5rem;margin-bottom:1.5rem
}
.card h2{font-size:1.1rem;font-weight:600;margin-bottom:1rem;color:var(--text)}
.btn{
  display:inline-flex;align-items:center;gap:.5rem;
  padding:.6rem 1.2rem;border-radius:8px;
  font-size:.85rem;font-weight:500;cursor:pointer;
  border:1px solid transparent;transition:all .2s;
  font-family:inherit;text-decoration:none
}
.btn:hover{transform:translateY(-1px);text-decoration:none}
.btn-primary{background:var(--blue);color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-danger{background:var(--red-dim);color:var(--red);border-color:rgba(239,68,68,.3)}
.btn-ghost{background:transparent;color:var(--text2);border-color:var(--border)}
.btn-ghost:hover{background:var(--bg3)}
input[type="text"],input[type="password"],textarea,select{
  width:100%;padding:.6rem .8rem;
  background:var(--bg);border:1px solid var(--border);
  border-radius:8px;color:var(--text);font-size:.9rem;
  font-family:inherit;transition:border .2s
}
input:focus,textarea:focus,select:focus{
  outline:none;border-color:var(--blue)
}
label{display:block;font-size:.8rem;font-weight:500;color:var(--text2);margin-bottom:.4rem}
.form-group{margin-bottom:1rem}
.tag{
  display:inline-block;padding:.2rem .6rem;border-radius:6px;
  font-size:.7rem;font-weight:600;text-transform:uppercase
}
.tag-green{background:var(--green-dim);color:var(--green)}
.tag-red{background:var(--red-dim);color:var(--red)}
.tag-amber{background:rgba(245,158,11,.15);color:var(--amber)}
.tag-blue{background:var(--blue-dim);color:var(--blue)}
.header{
  display:flex;align-items:center;justify-content:space-between;
  padding-bottom:1.5rem;margin-bottom:1.5rem;
  border-bottom:1px solid var(--border)
}
.header h1{font-size:1.3rem;font-weight:600}
.logo{
  width:36px;height:36px;border-radius:8px;
  background:linear-gradient(135deg,var(--green),var(--blue));
  display:flex;align-items:center;justify-content:center;
  font-size:1rem;font-weight:700;color:#fff
}
.nav{display:flex;gap:.5rem;flex-wrap:wrap}
.nav a{padding:.4rem .8rem;border-radius:6px;font-size:.8rem;font-weight:500;transition:all .2s}
.nav a:hover{background:var(--bg3)}
.nav a.active{background:var(--blue-dim);color:var(--blue)}
.alert{
  padding:.8rem 1rem;border-radius:8px;font-size:.85rem;
  margin-bottom:1rem;display:flex;align-items:center;gap:.5rem
}
.alert-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(239,68,68,.2)}
.alert-success{background:var(--green-dim);color:var(--green);border:1px solid rgba(16,185,129,.2)}
.alert-warning{background:rgba(245,158,11,.1);color:var(--amber);border:1px solid rgba(245,158,11,.2)}
pre{
  background:var(--bg);border:1px solid var(--border);
  border-radius:8px;padding:1rem;font-size:.8rem;
  overflow-x:auto;color:var(--text2)
}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:.6rem;font-size:.7rem;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid var(--border)}
td{padding:.6rem;font-size:.85rem;border-bottom:1px solid rgba(42,53,72,.5)}
tr:hover td{background:var(--bg3)}
.vuln-badge{
  position:fixed;bottom:1rem;right:1rem;
  padding:.5rem 1rem;border-radius:20px;
  background:var(--red-dim);color:var(--red);
  font-size:.75rem;font-weight:600;
  border:1px solid rgba(239,68,68,.3);
  z-index:100
}
"""

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
    user = session.get("user")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Demo — Vulnerable App</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_SHARED_CSS}</style></head><body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:.75rem">
      <div class="logo">S</div>
      <div>
        <h1>Sentinel Demo App</h1>
        <div style="font-size:.75rem;color:var(--text3)">Intentionally Vulnerable — SIH26153</div>
      </div>
    </div>
    <div class="nav">
      <a href="/" class="active">Home</a>
      <a href="/login">Login</a>
      <a href="/search">Search</a>
      <a href="/comments">Comments</a>
      <a href="/admin">Admin</a>
      {'<a href="/logout" style="color:var(--red)">Logout</a>' if user else ''}
    </div>
  </div>

  <div class="card">
    <h2>Welcome to the Sentinel Demo App</h2>
    <p style="color:var(--text2);margin-bottom:1.5rem">
      This is an intentionally vulnerable web application used to demonstrate
      SENTINEL's real-time attack detection capabilities. Each page contains
      a different vulnerability class.
    </p>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
      <a href="/login" class="card" style="text-decoration:none;border-color:var(--border)">
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem">
          <span style="font-size:1.5rem">🔑</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">Login</div>
            <div class="tag tag-red" style="margin-top:.25rem">SQL Injection</div>
          </div>
        </div>
        <div style="font-size:.8rem;color:var(--text3)">Weak credentials: admin / admin</div>
      </a>

      <a href="/search" class="card" style="text-decoration:none;border-color:var(--border)">
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem">
          <span style="font-size:1.5rem">🔍</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">Search</div>
            <div class="tag tag-amber" style="margin-top:.25rem">SQL Injection</div>
          </div>
        </div>
        <div style="font-size:.8rem;color:var(--text3)">Search items — vulnerable to SQLi</div>
      </a>

      <a href="/comments" class="card" style="text-decoration:none;border-color:var(--border)">
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem">
          <span style="font-size:1.5rem">💬</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">Comments</div>
            <div class="tag tag-amber" style="margin-top:.25rem">XSS</div>
          </div>
        </div>
        <div style="font-size:.8rem;color:var(--text3)">Post comments — stored XSS</div>
      </a>

      <a href="/api/items" class="card" style="text-decoration:none;border-color:var(--border)">
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem">
          <span style="font-size:1.5rem">📋</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">API Items</div>
            <div class="tag tag-green" style="margin-top:.25rem">JSON API</div>
          </div>
        </div>
        <div style="font-size:.8rem;color:var(--text3)">Public API — leaks item secrets</div>
      </a>

      <a href="/admin" class="card" style="text-decoration:none;border-color:var(--border)">
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem">
          <span style="font-size:1.5rem">👤</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">Admin Panel</div>
            <div class="tag tag-red" style="margin-top:.25rem">No Auth</div>
          </div>
        </div>
        <div style="font-size:.8rem;color:var(--text3)">Open admin — no authentication</div>
      </a>

      <a href="http://localhost:5001" class="card" style="text-decoration:none;border-color:var(--border)">
        <div style="display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem">
          <span style="font-size:1.5rem">🛡️</span>
          <div>
            <div style="font-weight:600;font-size:.9rem">Sentinel Dashboard</div>
            <div class="tag tag-blue" style="margin-top:.25rem">Monitor</div>
          </div>
        </div>
        <div style="font-size:.8rem;color:var(--text3)">View attacks in real-time</div>
      </a>
    </div>
  </div>

  <div class="alert alert-warning">
    <span>⚠</span>
    <span>This app is intentionally vulnerable. Do not deploy in production.</span>
  </div>
</div>
<div class="vuln-badge">INTENTIONALLY VULNERABLE</div>
</body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    """Weak login — SQL injection on password field, verbose errors."""
    error = None
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
                error = "Invalid credentials"
        except Exception as e:
            # Intentionally verbose error — leaks SQL to attacker
            return f"""<!DOCTYPE html>
<html><head><title>SQL Error</title>
<style>{_SHARED_CSS}</style></head><body>
<div class="container">
  <div class="header"><div style="display:flex;align-items:center;gap:.75rem">
    <div class="logo">S</div><h1>SQL Error</h1></div></div>
  <div class="alert alert-danger"><span>SQL injection detected — verbose error exposed</span></div>
  <div class="card"><h2>Database Error</h2><pre>{query}\\n\\n{e}</pre></div>
  <a href="/login" class="btn btn-ghost">← Back to Login</a>
</div></body></html>""", 500

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Sentinel Demo</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_SHARED_CSS}</style></head><body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:.75rem">
      <div class="logo">S</div><h1>Login</h1>
    </div>
    <div class="nav">
      <a href="/">Home</a>
      <a href="/login" class="active">Login</a>
      <a href="/search">Search</a>
      <a href="/comments">Comments</a>
      <a href="/admin">Admin</a>
    </div>
  </div>

  <div class="card" style="max-width:400px">
    <h2>Sign In</h2>
    {f'<div class="alert alert-danger"><span>{error}</span></div>' if error else ''}
    <form method="post">
      <div class="form-group">
        <label>Username</label>
        <input type="text" name="username" placeholder="Enter username" required>
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter password" required>
      </div>
      <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center">Sign In</button>
    </form>
    <div style="margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border)">
      <div style="font-size:.8rem;color:var(--text3)">
        <strong>Vulnerabilities:</strong>
        <div class="tag tag-amber" style="margin-top:.5rem">SQL Injection on username/password</div>
        <div class="tag tag-red" style="margin-top:.25rem">Weak credentials: admin / admin</div>
      </div>
    </div>
  </div>
</div>
<div class="vuln-badge">INTENTIONALLY VULNERABLE</div>
</body></html>"""


@app.route("/dashboard")
def dashboard():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    db = _get_db()
    items = db.execute("SELECT * FROM items").fetchall()
    comments = db.execute(
        "SELECT * FROM comments ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Dashboard — Sentinel Demo</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_SHARED_CSS}</style></head><body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:.75rem">
      <div class="logo">S</div>
      <div>
        <h1>Dashboard</h1>
        <div style="font-size:.75rem;color:var(--text3)">Welcome, {user['username']}</div>
      </div>
    </div>
    <div class="nav">
      <a href="/">Home</a>
      <a href="/search">Search</a>
      <a href="/comments">Comments</a>
      <a href="/logout" style="color:var(--red)">Logout</a>
    </div>
  </div>

  <div class="alert alert-success">
    <span>Logged in as <strong>{user['username']}</strong></span>
  </div>

  <div class="card">
    <h2>Items</h2>
    <table>
      <thead><tr><th>Name</th><th>Secret</th></tr></thead>
      <tbody>
        {"".join(f'<tr><td>{r["name"]}</td><td style="font-family:monospace;color:var(--amber)">{r["secret"]}</td></tr>' for r in items)}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Recent Comments</h2>
    {"".join(f'<div style="padding:.5rem;border-bottom:1px solid var(--border);font-size:.85rem">{r["content"]}</div>' for r in comments) if comments else '<div style="color:var(--text3);text-align:center;padding:1rem">No comments yet</div>'}
  </div>
</div>
<div class="vuln-badge">INTENTIONALLY VULNERABLE</div>
</body></html>"""


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    error = None
    if q:
        db = _get_db()
        # SQL injection: raw string formatting
        query = f"SELECT * FROM items WHERE name LIKE '%{q}%'"
        try:
            results = db.execute(query).fetchall()
        except Exception as e:
            error = (query, e)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Search — Sentinel Demo</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_SHARED_CSS}</style></head><body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:.75rem">
      <div class="logo">S</div><h1>Search</h1>
    </div>
    <div class="nav">
      <a href="/">Home</a>
      <a href="/login">Login</a>
      <a href="/search" class="active">Search</a>
      <a href="/comments">Comments</a>
      <a href="/admin">Admin</a>
    </div>
  </div>

  <div class="card">
    <h2>Search Items</h2>
    <form method="get" style="display:flex;gap:.5rem;margin-bottom:1rem">
      <input type="text" name="q" value="{q}" placeholder="Search items..." style="flex:1">
      <button type="submit" class="btn btn-primary">Search</button>
    </form>

    {"<div class='alert alert-danger'><span>SQL Error — query leaked: " + error[0] + "</span></div>" if error else ""}
    {"<div class='alert alert-warning'><span>Query: <code>" + q + "</code> — " + str(len(results)) + " results</span></div>" if q and not error else ""}

    """ + ('<table><thead><tr><th>Name</th><th>Secret</th></tr></thead><tbody>' + "".join('<tr><td>' + r["name"] + '</td><td style="font-family:monospace;color:var(--amber)">' + r["secret"] + '</td></tr>' for r in results) + '</tbody></table>' if results else '<div style="color:var(--text3);text-align:center;padding:1rem">No results found</div>' if q else '') + """

    <div style="margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border)">
      <div style="font-size:.8rem;color:var(--text3)">
        <strong>Try SQLi:</strong> <code style="color:var(--amber)">' OR 1=1 --</code>
      </div>
    </div>
  </div>
</div>
<div class="vuln-badge">INTENTIONALLY VULNERABLE</div>
</body></html>"""


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
    all_comments = db.execute("SELECT * FROM comments ORDER BY created_at DESC").fetchall()
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Comments — Sentinel Demo</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_SHARED_CSS}</style></head><body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:.75rem">
      <div class="logo">S</div><h1>Comments</h1>
    </div>
    <div class="nav">
      <a href="/">Home</a>
      <a href="/login">Login</a>
      <a href="/search">Search</a>
      <a href="/comments" class="active">Comments</a>
      <a href="/admin">Admin</a>
    </div>
  </div>

  <div class="card">
    <h2>Post a Comment</h2>
    <form method="post">
      <div class="form-group">
        <textarea name="content" rows="3" placeholder="Write something..."></textarea>
      </div>
      <button type="submit" class="btn btn-primary">Post Comment</button>
    </form>
    <div style="margin-top:.75rem;font-size:.8rem;color:var(--text3)">
      <strong>XSS payload:</strong> <code style="color:var(--amber)">&lt;script&gt;alert('xss')&lt;/script&gt;</code>
    </div>
  </div>

  <div class="card">
    <h2>All Comments ({len(all_comments)})</h2>
    {"".join(f'<div style="padding:.75rem;border-bottom:1px solid var(--border)">{r["content"]}</div>' for r in all_comments) if all_comments else '<div style="color:var(--text3);text-align:center;padding:1rem">No comments yet</div>'}
  </div>
</div>
<div class="vuln-badge">INTENTIONALLY VULNERABLE</div>
</body></html>"""


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
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Panel — Sentinel Demo</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>{_SHARED_CSS}
.alert-panel{{
  background:var(--red-dim);border:1px solid rgba(239,68,68,.3);
  border-radius:var(--radius);padding:1rem;margin-bottom:1.5rem
}}
</style></head><body>
<div class="container">
  <div class="header">
    <div style="display:flex;align-items:center;gap:.75rem">
      <div class="logo">S</div><h1>Admin Panel</h1>
    </div>
    <div class="nav">
      <a href="/">Home</a>
      <a href="/admin" class="active">Admin</a>
      <a href="/admin/users.json">Export JSON</a>
    </div>
  </div>

  <div class="alert-panel">
    <div style="display:flex;align-items:center;gap:.5rem;font-weight:600;color:var(--red)">
      <span>⚠</span> UNSECURED — No Authentication Required
    </div>
    <div style="font-size:.8rem;color:var(--text2);margin-top:.5rem">
      This admin panel has no authentication. Anyone can access user data and comments.
    </div>
  </div>

  <div class="card">
    <h2>Users ({len(users)})</h2>
    <table>
      <thead><tr><th>ID</th><th>Username</th></tr></thead>
      <tbody>
        {"".join(f'<tr><td>{r["id"]}</td><td><strong>{r["username"]}</strong></td></tr>' for r in users)}
      </tbody>
    </table>
    <div style="margin-top:.75rem">
      <a href="/admin/users.json" class="btn btn-danger btn-sm">Export All Users (JSON)</a>
    </div>
  </div>

  <div class="card">
    <h2>All Comments ({len(comments)})</h2>
    {"".join(f'<div style="padding:.5rem;border-bottom:1px solid var(--border);font-size:.85rem">{r["content"]}</div>' for r in comments) if comments else '<div style="color:var(--text3);text-align:center;padding:1rem">No comments</div>'}
  </div>
</div>
<div class="vuln-badge">INTENTIONALLY VULNERABLE</div>
</body></html>"""


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
