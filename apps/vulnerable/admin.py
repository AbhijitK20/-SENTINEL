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

app = Flask(__name__)

SENTINEL_API = "http://api:8000"
API_KEY = os.environ.get("SENTINEL_BOOTSTRAP_KEY", "sent_demo_key_2026")
BLOCKLIST_PATH = Path("apps/vulnerable/blocklist.jsonl")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SENTINEL Admin Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:1rem}
h1{color:#58a6ff;font-size:1.5rem;margin-bottom:.5rem}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem}
.card h2{color:#58a6ff;font-size:1rem;margin-bottom:.5rem}
.stat{font-size:2rem;font-weight:700}
.stat.ok{color:#3fb950}
.stat.alert{color:#f85149}
.alert-list{max-height:300px;overflow-y:auto}
.alert-item{padding:.5rem;border-bottom:1px solid #21262d}
.alert-item.critical{border-left:3px solid #f85149}
.alert-item.high{border-left:3px solid #d29922}
.alert-item.medium{border-left:3px solid #58a6ff}
button{background:#21262d;border:1px solid #30363d;color:#c9d1d9;padding:.4rem .8rem;border-radius:6px;cursor:pointer;font-size:.85rem}
button:hover{background:#30363d}
button.danger{color:#f85149;border-color:#f85149}
button.success{color:#3fb950;border-color:#3fb950}
.tag{display:inline-block;padding:.15rem .4rem;border-radius:4px;font-size:.75rem;font-weight:600}
.tag.critical{background:#3d1313;color:#f85149}
.tag.high{background:#3d2e00;color:#d29922}
.tag.medium{background:#0c2d6b;color:#58a6ff}
table{width:100%;border-collapse:collapse;margin-top:.5rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #21262d;font-size:.85rem}
th{color:#8b949e;font-weight:600}
.refresh{float:right;color:#8b949e;font-size:.8rem}
#log{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.5rem;max-height:200px;overflow-y:auto;font-family:monospace;font-size:.75rem;color:#8b949e}
</style></head><body>
<h1>🛡️ SENTINEL Admin Dashboard</h1>
<div class="grid">
  <div class="card">
    <h2>System Status</h2>
    <div class="stat {{ 'ok' if status_ok else 'alert' }}">{{ status_text }}</div>
    <p style="margin-top:.5rem;color:#8b949e">API: {{ api_url }} · Last check: {{ last_check }}</p>
  </div>
  <div class="card">
    <h2>Attack Summary</h2>
    <div style="display:flex;gap:1.5rem;margin-top:.5rem">
      <div><div class="stat alert">{{ total_incidents }}</div><div style="font-size:.8rem;color:#8b949e">Incidents</div></div>
      <div><div class="stat" style="color:#d29922">{{ total_findings }}</div><div style="font-size:.8rem;color:#8b949e">Findings</div></div>
      <div><div class="stat" style="color:#58a6ff">{{ peak_prob }}</div><div style="font-size:.8rem;color:#8b949e">Peak Prob</div></div>
    </div>
  </div>
</div>
<div class="card" style="margin-bottom:1rem">
  <h2>Live Alerts <span class="refresh">auto-refresh in {{ refresh }}s</span></h2>
  <div class="alert-list">
    {% if not alerts %}
    <p style="color:#8b949e;padding:1rem">No alerts yet — start an attack to see events here.</p>
    {% endif %}
    {% for alert in alerts %}
    <div class="alert-item {{ alert.severity }}">
      <span class="tag {{ alert.severity }}">{{ alert.severity }}</span>
      <strong>{{ alert.attack_type }}</strong>
      <span style="color:#8b949e"> · {{ alert.assets }} · {{ alert.time }}</span>
      {% if alert.ip and alert.ip not in blocked_ips %}
      <button onclick="blockIp('{{ alert.ip }}', '{{ alert.attack_type }}')" class="danger">Block {{ alert.ip }}</button>
      {% endif %}
    </div>
    {% endfor %}
  </div>
</div>
<div class="grid">
  <div class="card">
    <h2>Blocked IPs</h2>
    <table>
      <tr><th>IP</th><th>Reason</th><th>Time</th><th>Action</th></tr>
      {% for entry in blocked_ips %}
      <tr>
        <td>{{ entry.ip }}</td>
        <td>{{ entry.reason }}</td>
        <td>{{ entry.time_str }}</td>
        <td><button onclick="unbanIp('{{ entry.ip }}')" class="success">Unblock</button></td>
      </tr>
      {% endfor %}
      {% if not blocked_ips %}
      <tr><td colspan="4" style="color:#8b949e">No IPs blocked</td></tr>
      {% endif %}
    </table>
  </div>
  <div class="card">
    <h2>Quick Actions</h2>
    <div style="display:flex;flex-direction:column;gap:.5rem">
      <button onclick="location.reload()">🔄 Refresh Now</button>
      <button onclick="if(confirm('Shut down ALL attack traffic? This blocks every attacker IP.')) blockAll()" class="danger">🛑 Shut Down All Attacks</button>
      <button onclick="unbanAll()" class="success">🔓 Unblock All IPs</button>
    </div>
  </div>
</div>
<div class="card" style="margin-top:1rem">
  <h2>Recent Log Lines</h2>
  <div id="log">{% for line in log_lines %}{{ line }}<br>{% endfor %}</div>
</div>
<script>
function blockIp(ip, reason) {
  fetch('/admin/api/block', {method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip, reason})}).then(()=>location.reload());
}
function unbanIp(ip) {
  fetch('/admin/api/unblock', {method:'POST', headers:{'Content-Type':'application/json'},
    body:JSON.stringify({ip})}).then(()=>location.reload());
}
function blockAll() {
  fetch('/admin/api/block_all', {method:'POST'}).then(()=>location.reload());
}
function unbanAll() {
  fetch('/admin/api/unban_all', {method:'POST'}).then(()=>location.reload());
}
setTimeout(()=>location.reload(), {{ refresh }}000);
</script></body></html>"""


def _api_get(path: str) -> dict | None:
    req = urllib.request.Request(f"{SENTINEL_API}{path}", headers={"X-API-Key": API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"[admin] API error {path}: {e}", flush=True)
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
    for ip, rec in sorted(entries.items()):
        rec = dict(rec)
        rec["time_str"] = time.strftime("%H:%M:%S", time.localtime(rec["ts"]))
        out.append(rec)
    return out


def _read_log_tail(n: int = 20) -> list[str]:
    log_path = Path("apps/vulnerable/access.log")
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
    print(f"[admin] findings_raw={len(findings_raw)} processed={len(findings)}", flush=True)

    blocked = _read_blocklist()
    blocked_ips = [e["ip"] for e in blocked]
    peak = live_data.get("peak_probability", 0)
    peak_str = f"{peak:.1%}" if peak is not None else "—"

    status_ok = peak is None or peak < 0.15

    return render_template_string(
        HTML_TEMPLATE,
        status_ok=status_ok,
        status_text="Normal" if status_ok else "Under Attack",
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


@app.route("/admin/api/block", methods=["POST"])
def api_block():
    data = request.get_json(force=True)
    ip = data.get("ip", "")
    reason = data.get("reason", "")
    # Write ban to blocklist.jsonl
    import hashlib as _hl
    import time as _t
    rec = {"ip": ip, "action": "ban", "reason": reason, "source": "admin", "ts": _t.time()}
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BLOCKLIST_PATH, "a") as f:
        f.write(json.dumps(rec) + "\n")
    # Also tell SENTINEL via audit log
    _api_get(f"/admin/keys")
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
    log_path = Path("apps/vulnerable/access.log")
    if log_path.exists():
        ips = set()
        for line in log_path.read_text().splitlines():
            for part in line.split():
                if part.startswith("src="):
                    ips.add(part.split("=", 1)[1])
        for ip in ips:
            rec = {"ip": ip, "action": "ban", "reason": "block-all", "source": "admin", "ts": time.time()}
            with open(BLOCKLIST_PATH, "a") as f:
                f.write(json.dumps(rec) + "\n")
    return jsonify({"ok": True})


@app.route("/admin/api/unban_all", methods=["POST"])
def api_unban_all():
    """Clear the blocklist."""
    if BLOCKLIST_PATH.exists():
        BLOCKLIST_PATH.unlink()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
