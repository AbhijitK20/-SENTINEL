"""Attack-demo target and scripted attack for the live presentation.

Everything is localhost-only and stdlib: a harmless TCP echo target plus a
sensor process that watches the connections and writes JSONL events in the
engine's wire format. The attack is a *simulation* — it opens and closes
sockets with attack-shaped traffic patterns; it never exploits anything,
never sends credentials anywhere, and binds only to 127.0.0.1.

Story (matches DEMO_SCENARIO.md):

    PHASE 1  benign background chatter          → model stays low
    PHASE 2  reconnaissance: many short SYNs    → Reconnaissance fires
    PHASE 3  failed logins                      → stage evidence escalates
    PHASE 4  large internal transfers           → Lateral Movement fires,
                                                 probability crosses the
                                                 threshold → ALERT

Run the target and attack in two terminals:

    uv run python scripts/attack_demo.py target
    uv run python scripts/attack_demo.py attack --speed 1.0

Or let the dashboard spawn both (Live tab → "Run demo attack").
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

BENIGN_CLIENT = "127.0.0.1"
TARGET_HOST = "127.0.0.1"
DEFAULT_PORT = 8347
# Connecting to 1.2.3.4:9 (discard) with a 0.2s timeout is a fast, harmless,
# no-response probe — the same shape a scanner produces.
PROBE_TARGET = ("1.2.3.4", 9)
PROBE_TIMEOUT = 0.2


# ── sensor ────────────────────────────────────────────────────────────
class Sensor:
    """Watches connections and appends JSONL events the engine ingests."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._counter = 0
        self._lock = threading.Lock()

    def record(
        self,
        src: str,
        dst: str,
        *,
        dport: int,
        bytes_sent: float,
        packets: float,
        syn: int = 0,
        ack: int = 0,
        rst: int = 0,
        fin: int = 0,
        failed_auth: float = 0.0,
        event_type: str = "flow",
        kind: str = "connection",
    ) -> None:
        features = {
            "destination_port": float(dport),
            "bytes": bytes_sent,
            "packets": packets,
            "syn_count": float(syn),
            "ack_count": float(ack),
            "rst_count": float(rst),
            "fin_count": float(fin),
            "failed_auth": failed_auth,
            "retransmission": 0.0,
        }
        line = json.dumps(
            {
                "timestamp": datetime.now(tz=UTC).isoformat(),
                "src": src,
                "dst": dst,
                "event_type": event_type,
                "kind": kind,
                "features": features,
            }
        )
        with self._lock:
            self._counter += 1
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


# ── target ────────────────────────────────────────────────────────────
def run_target(port: int, stop: threading.Event) -> None:
    """Echo server: accepts, reads up to 64 KiB, echoes, closes."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((TARGET_HOST, port))
        server.listen(16)
        server.settimeout(0.5)
        print(f"[target] listening on 127.0.0.1:{port}", flush=True)
        while not stop.is_set():
            try:
                conn, addr = server.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    data = conn.recv(65536)
                    if data:
                        conn.sendall(b"ack:" + data[:64])
                except OSError:
                    pass


# ── attack phases ─────────────────────────────────────────────────────
def _benign_chatter(sensor: Sensor, seconds: float) -> None:
    """Phase 1: modest internal chatter against the echo target."""
    deadline = time.monotonic() + seconds
    sequence = 0
    while time.monotonic() < deadline:
        sequence += 1
        try:
            with socket.create_connection((TARGET_HOST, DEFAULT_PORT), timeout=1.0) as sock:
                sock.sendall(b"healthcheck")
                sock.recv(64)
            sensor.record(
                BENIGN_CLIENT,
                "demo-target",
                dport=DEFAULT_PORT,
                bytes_sent=64.0,
                packets=6.0,
                syn=1,
                ack=5,
            )
        except OSError:
            pass
        time.sleep(2.5)


def _reconnaissance(sensor: Sensor, seconds: float, rate: float = 25.0) -> None:
    """Phase 2: scan-shaped bursts — many SYNs, RST/timeout, no payload."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for _ in range(int(rate)):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).close()  # socket-shape only
            sensor.record(
                BENIGN_CLIENT,
                PROBE_TARGET[0],
                dport=PROBE_TARGET[1],
                bytes_sent=0.0,
                packets=1.0,
                syn=1,
                rst=1,
                kind="scan-probe",
            )
        time.sleep(1.0)


def _failed_logins(sensor: Sensor, seconds: float, rate: float = 4.0) -> None:
    """Phase 3: repeated failed authentications (simulated, never sent)."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for _ in range(int(rate)):
            sensor.record(
                BENIGN_CLIENT,
                "demo-target",
                dport=22,
                bytes_sent=96.0,
                packets=4.0,
                syn=1,
                ack=3,
                failed_auth=1.0,
                event_type="authentication",
                kind="failed-login",
            )
        time.sleep(1.0)


def _lateral_transfer(sensor: Sensor, seconds: float) -> None:
    """Phase 4: bulk internal transfers — the exfil/lateral shape."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        payload = b"x" * 48000  # moved locally through the socket pair only
        try:
            with socket.create_connection((TARGET_HOST, DEFAULT_PORT), timeout=1.0) as sock:
                sock.sendall(payload)
                sock.recv(64)
            sensor.record(
                BENIGN_CLIENT,
                "demo-target",
                dport=DEFAULT_PORT,
                bytes_sent=48000.0,
                packets=40.0,
                syn=1,
                ack=39,
                kind="bulk-transfer",
            )
        except OSError:
            pass
        time.sleep(0.8)


PHASES = (
    ("benign", _benign_chatter, 40.0),
    ("recon", _reconnaissance, 30.0),
    ("failed-logins", _failed_logins, 30.0),
    ("lateral", _lateral_transfer, 40.0),
)


def run_attack(sensor_path: Path, speed: float) -> None:
    """Run the scripted attack, compressing phase durations by ``speed``."""
    sensor = Sensor(sensor_path)
    print(f"[attack] writing events to {sensor_path}", flush=True)
    for name, phase, seconds in PHASES:
        if speed != 1.0:
            seconds = max(5.0, seconds / speed)
        print(f"[attack] phase: {name} ({seconds:.0f}s)", flush=True)
        phase(sensor, seconds)
    print("[attack] complete", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("target", "attack"))
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--events", default="reports/live/events.jsonl")
    parser.add_argument("--speed", type=float, default=1.0, help="compress phase durations")
    args = parser.parse_args()

    if args.mode == "target":
        stop = threading.Event()
        try:
            run_target(args.port, stop)
        except KeyboardInterrupt:
            stop.set()
    else:
        path = Path(args.events)
        path.parent.mkdir(parents=True, exist_ok=True)
        run_attack(path, args.speed)


if __name__ == "__main__":
    main()
