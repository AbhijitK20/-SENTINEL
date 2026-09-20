"""SENTINEL admin dashboard — live alerts + response.

Reads alerts from SENTINEL's API, shows live events from the scanner log,
and lets the admin block IPs (via the blocklist) or shut down attack
traffic.  Port 5001.

Run: python apps/vulnerable/admin.py
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request

from paths import ACCESS_LOG, BLOCKLIST

app = Flask(__name__)

SENTINEL_API = "http://api:8000"
API_KEY = os.environ.get("SENTINEL_BOOTSTRAP_KEY", "sent_demo_key_2026")
BLOCKLIST_PATH = BLOCKLIST

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL — Security Operations Center</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg-primary: #0a0e17;
  --bg-secondary: #111827;
  --bg-card: #1a2332;
  --bg-card-hover: #1f2b3d;
  --border: #2a3548;
  --border-light: #374357;
  --text-primary: #e2e8f0;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --accent-blue: #3b82f6;
  --accent-blue-dim: #1e40af;
  --accent-green: #10b981;
  --accent-green-dim: #065f46;
  --accent-red: #ef4444;
  --accent-red-dim: #7f1d1d;
  --accent-amber: #f59e0b;
  --accent-amber-dim: #78350f;
  --accent-purple: #8b5cf6;
  --gradient-blue: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
  --gradient-green: linear-gradient(135deg, #10b981 0%, #34d399 100%);
  --gradient-red: linear-gradient(135deg, #ef4444 0%, #f97316 100%);
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.3);
  --shadow-md: 0 4px 6px -1px rgba(0,0,0,0.4);
  --shadow-lg: 0 10px 15px -3px rgba(0,0,0,0.5);
  --radius: 12px;
  --radius-sm: 8px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Inter',-apple-system,system-ui,sans-serif;
  background:var(--bg-primary);color:var(--text-primary);
  min-height:100vh;line-height:1.6;
}
.container{max-width:1400px;margin:0 auto;padding:1.5rem}

/* Header */
.header{
  display:flex;align-items:center;justify-content:space-between;
  padding:1rem 0;margin-bottom:1.5rem;border-bottom:1px solid var(--border)
}
.header-left{display:flex;align-items:center;gap:1rem}
.logo{
  width:40px;height:40px;border-radius:10px;
  background:var(--gradient-blue);display:flex;align-items:center;
  justify-content:center;font-size:1.2rem;font-weight:700;color:#fff
}
.header h1{font-size:1.4rem;font-weight:600;letter-spacing:-0.025em}
.header .subtitle{font-size:.8rem;color:var(--text-muted);font-weight:400}
.header-right{display:flex;align-items:center;gap:1rem}
.status-badge{
  display:flex;align-items:center;gap:.5rem;
  padding:.4rem .8rem;border-radius:20px;font-size:.75rem;font-weight:600;
  text-transform:uppercase;letter-spacing:.05em
}
.status-badge.ok{background:var(--accent-green-dim);color:var(--accent-green)}
.status-badge.alert{background:var(--accent-red-dim);color:var(--accent-red);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.7}}
.last-check{font-size:.75rem;color:var(--text-muted)}

/* Grid */
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem}
.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;margin-bottom:1.5rem}

/* Cards */
.card{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);padding:1.25rem;
  transition:all .2s ease
}
.card:hover{border-color:var(--border-light);box-shadow:var(--shadow-md)}
.card-header{
  display:flex;align-items:center;justify-content:space-between;
  margin-bottom:1rem;padding-bottom:.75rem;border-bottom:1px solid var(--border)
}
.card-title{font-size:.85rem;font-weight:600;color:var(--text-secondary);text-transform:uppercase;letter-spacing:.05em}

/* Stats */
.stat-card{text-align:center;padding:1.5rem}
.stat-icon{
  width:48px;height:48px;border-radius:12px;margin:0 auto .75rem;
  display:flex;align-items:center;justify-content:center;font-size:1.4rem
}
.stat-icon.blue{background:rgba(59,130,246,.15);color:var(--accent-blue)}
.stat-icon.green{background:rgba(16,185,129,.15);color:var(--accent-green)}
.stat-icon.red{background:rgba(239,68,68,.15);color:var(--accent-red)}
.stat-icon.amber{background:rgba(245,158,11,.15);color:var(--accent-amber)}
.stat-value{font-size:2rem;font-weight:700;line-height:1;margin-bottom:.25rem}
.stat-label{font-size:.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em}

/* Alert list */
.alert-list{max-height:400px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--border) transparent}
.alert-item{
  display:flex;align-items:center;gap:.75rem;
  padding:.75rem;border-radius:var(--radius-sm);
  margin-bottom:.5rem;transition:background .2s
}
.alert-item:hover{background:var(--bg-card-hover)}
.alert-item.critical{border-left:3px solid var(--accent-red)}
.alert-item.high{border-left:3px solid var(--accent-amber)}
.alert-item.medium{border-left:3px solid var(--accent-blue)}
.alert-tag{
  padding:.2rem .6rem;border-radius:6px;font-size:.65rem;
  font-weight:600;text-transform:uppercase;letter-spacing:.05em;
  white-space:nowrap
}
.alert-tag.critical{background:var(--accent-red-dim);color:var(--accent-red)}
.alert-tag.high{background:var(--accent-amber-dim);color:var(--accent-amber)}
.alert-tag.medium{background:var(--accent-blue-dim);color:var(--accent-blue)}
.alert-type{font-weight:600;font-size:.85rem;min-width:120px}
.alert-meta{color:var(--text-muted);font-size:.75rem;flex:1}

/* Buttons */
.btn{
  display:inline-flex;align-items:center;gap:.5rem;
  padding:.5rem 1rem;border-radius:var(--radius-sm);
  font-size:.8rem;font-weight:500;cursor:pointer;
  border:1px solid transparent;transition:all .2s;
  font-family:inherit
}
.btn:hover{transform:translateY(-1px);box-shadow:var(--shadow-sm)}
.btn:active{transform:translateY(0)}
.btn-primary{background:var(--accent-blue);color:#fff;border-color:var(--accent-blue)}
.btn-primary:hover{background:#2563eb}
.btn-danger{background:var(--accent-red-dim);color:var(--accent-red);border-color:rgba(239,68,68,.3)}
.btn-danger:hover{background:rgba(239,68,68,.2)}
.btn-success{background:var(--accent-green-dim);color:var(--accent-green);border-color:rgba(16,185,129,.3)}
.btn-success:hover{background:rgba(16,185,129,.2)}
.btn-ghost{background:transparent;color:var(--text-secondary);border-color:var(--border)}
.btn-ghost:hover{background:var(--bg-card-hover);color:var(--text-primary)}
.btn-sm{padding:.35rem .7rem;font-size:.75rem}
.btn-group{display:flex;gap:.5rem;flex-wrap:wrap}

/* Table */
table{width:100%;border-collapse:collapse}
th{
  text-align:left;padding:.6rem .75rem;font-size:.7rem;
  font-weight:600;color:var(--text-muted);text-transform:uppercase;
  letter-spacing:.05em;border-bottom:1px solid var(--border)
}
td{
  padding:.6rem .75rem;font-size:.8rem;
  border-bottom:1px solid rgba(42,53,72,.5)
}
tr:hover td{background:var(--bg-card-hover)}

/* Log */
.log-container{
  background:var(--bg-primary);border:1px solid var(--border);
  border-radius:var(--radius-sm);padding:1rem;
  max-height:250px;overflow-y:auto;
  font-family:'JetBrains Mono',monospace;font-size:.7rem;
  color:var(--text-muted);line-height:1.8;
  scrollbar-width:thin;scrollbar-color:var(--border) transparent
}

/* Attack panel */
.attack-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:.75rem}
.attack-btn{
  display:flex;flex-direction:column;align-items:center;gap:.5rem;
  padding:1rem;border-radius:var(--radius-sm);
  background:var(--bg-primary);border:1px solid var(--border);
  cursor:pointer;transition:all .2s;text-align:center
}
.attack-btn:hover{border-color:var(--accent-red);background:var(--accent-red-dim)}
.attack-btn .icon{font-size:1.5rem}
.attack-btn .label{font-size:.8rem;font-weight:600;color:var(--text-primary)}
.attack-btn .desc{font-size:.65rem;color:var(--text-muted)}
.attack-output{
  margin-top:.75rem;padding:.75rem;
  background:var(--bg-primary);border:1px solid var(--border);
  border-radius:var(--radius-sm);
  font-family:'JetBrains Mono',monospace;font-size:.7rem;
  color:var(--text-muted);max-height:200px;overflow-y:auto;
  display:none
}

/* Responsive */
@media(max-width:1024px){
  .grid{grid-template-columns:repeat(2,1fr)}
  .grid-3{grid-template-columns:1fr}
  .attack-grid{grid-template-columns:repeat(2,1fr)}
}
@media(max-width:640px){
  .grid{grid-template-columns:1fr}
  .grid-2{grid-template-columns:1fr}
  .attack-grid{grid-template-columns:1fr}
  .header{flex-direction:column;gap:1rem;text-align:center}
}
</style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div class="header">
    <div class="header-left">
      <div class="logo">S</div>
      <div>
        <h1>SENTINEL</h1>
        <div class="subtitle">Security Operations Center — SIH26153</div>
      </div>
    </div>
    <div class="header-right">
      <div class="status-badge {{ 'ok' if status_ok else 'alert' }}">
        <span>{{ '●' }}</span>
        {{ status_text }}
      </div>
      <div class="last-check">Last scan: {{ last_check }}</div>
    </div>
  </div>

  <!-- Stats -->
  <div class="grid">
    <div class="card stat-card">
      <div class="stat-icon {{ 'red' if total_incidents > 0 else 'green' }}">
        {{ '⚡' if total_incidents > 0 else '✓' }}
      </div>
      <div class="stat-value" style="color:{{ 'var(--accent-red)' if total_incidents > 0 else 'var(--accent-green)' }}">
        {{ total_incidents }}
      </div>
      <div class="stat-label">Active Incidents</div>
    </div>
    <div class="card stat-card">
      <div class="stat-icon amber">⚠</div>
      <div class="stat-value" style="color:var(--accent-amber)">{{ total_findings }}</div>
      <div class="stat-label">Security Findings</div>
    </div>
    <div class="card stat-card">
      <div class="stat-icon blue">◎</div>
      <div class="stat-value" style="color:var(--accent-blue)">{{ peak_prob }}</div>
      <div class="stat-label">Peak Threat Level</div>
    </div>
    <div class="card stat-card">
      <div class="stat-icon {{ 'red' if blocked_ips else 'green' }}">
        {{ '⛊' if blocked_ips else '⛊' }}
      </div>
      <div class="stat-value">{{ blocked_ips|length }}</div>
      <div class="stat-label">Blocked IPs</div>
    </div>
  </div>

  <!-- Main content -->
  <div class="grid-2">
    <!-- Live Alerts -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Live Threat Alerts</span>
        <span style="font-size:.7rem;color:var(--text-muted)">auto-refresh {{ refresh }}s</span>
      </div>
      <div class="alert-list">
        {% if not alerts %}
        <div style="text-align:center;padding:2rem;color:var(--text-muted)">
          <div style="font-size:2rem;margin-bottom:.5rem">🛡️</div>
          <div>No active threats detected</div>
          <div style="font-size:.7rem;margin-top:.25rem">System is operating normally</div>
        </div>
        {% endif %}
        {% for alert in alerts %}
        <div class="alert-item {{ alert.severity }}">
          <span class="alert-tag {{ alert.severity }}">{{ alert.severity }}</span>
          <span class="alert-type">{{ alert.attack_type }}</span>
          <span class="alert-meta">{{ alert.assets }} · {{ alert.time }}</span>
          {% if alert.ip and alert.ip not in blocked_ips_set %}
          <button onclick="blockIp('{{ alert.ip }}', '{{ alert.attack_type }}')" class="btn btn-danger btn-sm">
            Block
          </button>
          {% endif %}
        </div>
        {% endfor %}
      </div>
    </div>

    <!-- Right column -->
    <div style="display:flex;flex-direction:column;gap:1rem">
      <!-- Force Attack -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Attack Simulation</span>
          <button onclick="resetSystem()" class="btn btn-ghost btn-sm">↺ Reset</button>
        </div>
        <p style="font-size:.75rem;color:var(--text-muted);margin-bottom:1rem">
          Launch attacks against the vulnerable demo app (port 5000). Events are detected by SENTINEL in real-time.
        </p>
        <div class="attack-grid">
          <div class="attack-btn" onclick="triggerAttack('brute_force')">
            <div class="icon">🔑</div>
            <div class="label">Brute Force</div>
            <div class="desc">Credential stuffing</div>
          </div>
          <div class="attack-btn" onclick="triggerAttack('sqli')">
            <div class="icon">💉</div>
            <div class="label">SQL Injection</div>
            <div class="desc">Database extraction</div>
          </div>
          <div class="attack-btn" onclick="triggerAttack('scan')">
            <div class="icon">🔍</div>
            <div class="label">Port Scan</div>
            <div class="desc">Service discovery</div>
          </div>
          <div class="attack-btn" onclick="triggerAttack('xss')">
            <div class="icon">⚠</div>
            <div class="label">XSS Injection</div>
            <div class="desc">Stored XSS attack</div>
          </div>
          <div class="attack-btn" onclick="triggerAttack('traversal')">
            <div class="icon">📁</div>
            <div class="label">Dir Traversal</div>
            <div class="desc">File extraction</div>
          </div>
          <div class="attack-btn" onclick="triggerAttack('enum')">
            <div class="icon">📋</div>
            <div class="label">API Enum</div>
            <div class="desc">Endpoint discovery</div>
          </div>
          <div class="attack-btn" onclick="triggerAttack('credential_stuffing')">
            <div class="icon">🔐</div>
            <div class="label">Cred Stuffing</div>
            <div class="desc">Common passwords</div>
          </div>
          <div class="attack-btn" onclick="triggerAttack('full_chain')">
            <div class="icon">⛓</div>
            <div class="label">Full Chain</div>
            <div class="desc">Combined attack</div>
          </div>
        </div>
        <div id="attack-output" class="attack-output"></div>
      </div>

      <!-- Blocked IPs -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">IP Blocklist</span>
          <div class="btn-group">
            <button onclick="unbanAll()" class="btn btn-ghost btn-sm">Clear All</button>
          </div>
        </div>
        <table>
          <thead>
            <tr><th>IP Address</th><th>Reason</th><th>Time</th><th></th></tr>
          </thead>
          <tbody>
            {% for entry in blocked_ips %}
            <tr>
              <td style="font-family:'JetBrains Mono',monospace;font-size:.75rem">{{ entry.ip }}</td>
              <td>{{ entry.reason }}</td>
              <td style="color:var(--text-muted)">{{ entry.time_str }}</td>
              <td><button onclick="unbanIp('{{ entry.ip }}')" class="btn btn-success btn-sm">Unblock</button></td>
            </tr>
            {% endfor %}
            {% if not blocked_ips %}
            <tr><td colspan="4" style="color:var(--text-muted);text-align:center;padding:1.5rem">No IPs blocked</td></tr>
            {% endif %}
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Bottom row -->
  <div class="grid-2" style="margin-top:0">
    <!-- Quick Actions -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Quick Actions</span>
      </div>
      <div class="btn-group">
        <button onclick="location.reload()" class="btn btn-ghost">↻ Refresh</button>
        <button onclick="blockAll()" class="btn btn-danger">⛊ Block All Attackers</button>
        <button onclick="unbanAll()" class="btn btn-success">🔓 Unblock All</button>
        <button onclick="resetSystem()" class="btn btn-primary">↺ Reset System</button>
      </div>
    </div>

    <!-- Recent Logs -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Recent Activity</span>
        <span style="font-size:.7rem;color:var(--text-muted)">{{ log_lines|length }} entries</span>
      </div>
      <div class="log-container">
        {% for line in log_lines %}
        <div>{{ line }}</div>
        {% endfor %}
        {% if not log_lines %}
        <div style="color:var(--text-muted);text-align:center;padding:1rem">No recent activity</div>
        {% endif %}
      </div>
    </div>
  </div>
</div>

<script>
function blockIp(ip, reason) {
  fetch('/admin/api/block', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip, reason})
  }).then(()=>location.reload());
}
function unbanIp(ip) {
  fetch('/admin/api/unblock', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip})
  }).then(()=>location.reload());
}
function blockAll() {
  if(!confirm('Block ALL attacker IPs?')) return;
  setActionState('Blocking observed attackers...');
  fetch('/admin/api/block_all', {method:'POST'})
    .then(requireOk).then(data=>{
      setActionState('Blocked ' + data.blocked_count + ' observed IP(s).');
      setTimeout(()=>location.reload(), 700);
    }).catch(showActionError);
}
function unbanAll() {
  setActionState('Clearing the blocklist...');
  fetch('/admin/api/unban_all', {method:'POST'})
    .then(requireOk).then(data=>{
      setActionState('Unblocked ' + data.unblocked_count + ' IP(s).');
      setTimeout(()=>location.reload(), 700);
    }).catch(showActionError);
}
function resetSystem() {
  if(!confirm('Reset the detection engine? This clears all incidents and findings.')) return;
  setActionState('Resetting the demo session...');
  fetch('/admin/api/reset', {method:'POST'})
    .then(requireOk).then(()=>{
      setActionState('Demo session reset.');
      setTimeout(()=>location.reload(), 700);
    }).catch(showActionError);
}
function requireOk(response) {
  if(!response.ok) throw new Error('HTTP ' + response.status);
  return response.json();
}
function setActionState(message) {
  var out = document.getElementById('attack-output');
  out.style.display = 'block';
  out.textContent = message;
}
function showActionError(error) {
  setActionState('Action failed: ' + error.message);
}
function triggerAttack(attackType) {
  var out = document.getElementById('attack-output');
  out.style.display = 'block';
  out.textContent = 'Starting ' + attackType + ' attack...';
  fetch('/admin/api/attack', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({attack_type: attackType})
  }).then(r=>r.json()).then(data=>{
    out.textContent = data.output || data.error || 'Attack triggered';
    setTimeout(()=>location.reload(), 3000);
  }).catch(e=>{
    out.textContent = 'Error: ' + e;
  });
}
setTimeout(()=>location.reload(), {{ refresh }}000);
</script>
</body>
</html>"""


def _api_get(path: str) -> dict | None:
    req = urllib.request.Request(f"{SENTINEL_API}{path}", headers={"X-API-Key": API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"[admin] API error {path}: {e}", flush=True)
        return None


def _api_post(path: str, data: dict | None = None) -> dict | None:
    body = json.dumps(data or {}).encode()
    req = urllib.request.Request(
        f"{SENTINEL_API}{path}",
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"[admin] API error POST {path}: {e}", flush=True)
        return None


def _read_blocklist() -> list[dict]:
    if not BLOCKLIST_PATH.exists():
        return []
    entries: dict[str, dict] = {}
    for line in BLOCKLIST_PATH.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("action") == "ban":
            entries[rec["ip"]] = rec
        elif rec.get("action") == "unban":
            entries.pop(rec["ip"], None)
    out = []
    for _, rec in sorted(entries.items()):
        rec = dict(rec)
        rec["time_str"] = time.strftime("%H:%M:%S", time.localtime(rec["ts"]))
        out.append(rec)
    return out


def _read_log_tail(n: int = 20) -> list[str]:
    log_path = ACCESS_LOG
    if not log_path.exists():
        return []
    lines = log_path.read_text().splitlines()
    return lines[-n:]


@app.route("/")
def index():
    live_data = _api_get("/v1/live") or {}
    incidents = live_data.get("incidents", [])
    findings_raw = live_data.get("findings", [])
    findings = []
    for f in findings_raw:
        severity = "critical"
        if f.get("probability", 0) >= 0.65:
            severity = "high"
        elif f.get("probability", 0) >= 0.40:
            severity = "medium"
        findings.append({**f, "severity": severity})

    blocked = _read_blocklist()
    blocked_ips = [e["ip"] for e in blocked]
    peak = live_data.get("peak_probability", 0)
    peak_str = f"{peak:.1%}" if peak is not None else "—"

    status_ok = peak is None or peak < 0.15

    return render_template_string(
        HTML_TEMPLATE,
        status_ok=status_ok,
        status_text="All Clear" if status_ok else "Under Attack",
        api_url=SENTINEL_API,
        last_check=time.strftime("%H:%M:%S"),
        total_incidents=len(incidents),
        total_findings=len(findings),
        peak_prob=peak_str,
        alerts=findings[-50:][::-1],
        blocked_ips=blocked,
        blocked_ips_set=set(blocked_ips),
        refresh=10,
        log_lines=_read_log_tail(25),
    )


@app.route("/admin/api/reset", methods=["POST"])
def api_reset():
    """Reset the SENTINEL detection engine."""
    result = _api_post("/v1/live/reset")
    # Also clear the blocklist
    unblocked_count = len(_read_blocklist())
    if BLOCKLIST_PATH.exists():
        BLOCKLIST_PATH.unlink()
    return jsonify({"ok": True, "result": result, "unblocked_count": unblocked_count})


@app.route("/admin/api/block", methods=["POST"])
def api_block():
    data = request.get_json(force=True)
    ip = data.get("ip", "")
    reason = data.get("reason", "")
    rec = {"ip": ip, "action": "ban", "reason": reason, "source": "admin", "ts": time.time()}
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    _api_get("/admin/keys")
    return jsonify({"ok": True})


@app.route("/admin/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(force=True)
    ip = data.get("ip", "")
    rec = {"ip": ip, "action": "unban", "reason": "admin", "source": "admin", "ts": time.time()}
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    return jsonify({"ok": True})


@app.route("/admin/api/block_all", methods=["POST"])
def api_block_all():
    """Block every IP that has appeared in the access log."""
    log_path = ACCESS_LOG
    blocked: set[str] = set()
    if log_path.exists():
        ips: set[str] = set()
        for line in log_path.read_text().splitlines():
            for part in line.split():
                if part.startswith("src="):
                    ips.add(part.split("=", 1)[1])
        for ip in ips:
            blocked.add(ip)
            rec = {
                "ip": ip,
                "action": "ban",
                "reason": "block-all",
                "source": "admin",
                "ts": time.time(),
            }
            with open(BLOCKLIST_PATH, "a") as f:
                f.write(json.dumps(rec) + "\n")
    return jsonify({"ok": True, "blocked_count": len(blocked)})


@app.route("/admin/api/unban_all", methods=["POST"])
def api_unban_all():
    """Clear the blocklist."""
    unblocked_count = len(_read_blocklist())
    if BLOCKLIST_PATH.exists():
        BLOCKLIST_PATH.unlink()
    return jsonify({"ok": True, "unblocked_count": unblocked_count})


@app.route("/admin/api/attack", methods=["POST"])
def api_trigger_attack():
    """Trigger an attack script against the vulnerable app."""
    import subprocess as _sp

    data = request.get_json(force=True)
    attack_type = data.get("attack_type", "")
    target_url = os.environ.get("ATTACK_TARGET", "http://vulnerable-app:5000")

    # Reset the push engine before starting a new attack
    try:
        _api_post("/v1/live/reset")
    except Exception:
        pass

    cmd_map = {
        "brute_force": [
            "python",
            "-m",
            "attacks.brute_force",
            "--target",
            target_url,
            "--delay",
            "0.1",
            "--attempts",
            "5",
        ],
        "sqli": [
            "python",
            "-m",
            "attacks.sqli",
            "--target",
            target_url,
            "--delay",
            "0.1",
            "--rounds",
            "1",
        ],
        "scan": [
            "python",
            "-m",
            "attacks.scan",
            "--target",
            target_url,
            "--delay",
            "0.05",
            "--rounds",
            "1",
        ],
        "xss": [
            "python",
            "-m",
            "attacks.xss",
            "--target",
            target_url,
            "--delay",
            "0.1",
            "--rounds",
            "1",
        ],
        "traversal": [
            "python",
            "-m",
            "attacks.traversal",
            "--target",
            target_url,
            "--delay",
            "0.1",
            "--rounds",
            "1",
        ],
        "enum": [
            "python",
            "-m",
            "attacks.enum",
            "--target",
            target_url,
            "--delay",
            "0.1",
            "--rounds",
            "1",
        ],
        "credential_stuffing": [
            "python",
            "-m",
            "attacks.credential_stuffing",
            "--target",
            target_url,
            "--delay",
            "0.1",
            "--rounds",
            "1",
        ],
        "full_chain": [
            "python",
            "-m",
            "attacks.full_chain",
            "--target",
            target_url,
            "--delay",
            "0.05",
        ],
    }

    if attack_type not in cmd_map:
        return jsonify({"error": f"Unknown attack type: {attack_type}"}), 400

    try:
        result = _sp.run(
            cmd_map[attack_type],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(Path(__file__).resolve().parent),
        )
        output = (result.stdout + result.stderr)[-3000:]
        return jsonify({"ok": True, "output": output, "returncode": result.returncode})
    except _sp.TimeoutExpired:
        return jsonify({"error": "Attack timed out after 120s"}), 504
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
