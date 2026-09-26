"""Render a synthetic capture in the CIC-IDS2017 TrafficLabelling schema.

    uv run python scripts/make_cic_fixture.py --output data/raw/fixture-lab

This is **not** CIC-IDS2017. It is a small synthetic file that carries the real
schema — the columns the adapter requires, the flag counts it reads, the label
vocabulary, and the documented 12-hour timestamp defect — so the real-data path
(``run_real_benchmark.py``, the CIC adapter, the dashboard's real-data mode)
can be exercised end to end without the licensed dataset.

It proves the pipeline handles the real format. It produces no performance
numbers: anything measured on it is a plumbing check. Point ``--data-dir`` at
real CSVs for results.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Exactly the columns the adapter requires, with the real file's quirks: the
# leading spaces, the truncated "Packet"/"Packet" spellings, and the ' Label'
# column that carries the leading space.
COLUMNS = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Flow IAT Mean",
    " Label",
]

# Attack labels the adapter recognises; the fixture uses exactly these so the
# strict label mapping is exercised rather than bypassed.
ATTACK_LABELS = ("FTP-Patator", "Web Attack - Brute Force", "Infiltration")


def _rows(
    rng: random.Random,
    scenario: str,
    count: int,
    start: datetime,
    attack_label: str,
    *,
    attack_rate: float,
) -> list[dict]:
    hosts = [f"192.168.10.{index}" for index in range(2, 14)]
    server = "192.168.10.100"
    rows: list[dict] = []
    # The real benchmark protocol trains on Tuesday and tests on Thursday
    # Infiltration, so the training day must carry infiltration positives too.
    # Real CICFlowMeter days are ~287k flows; a few thousand is enough to build
    # the windows the protocol needs without a large fixture.
    for index in range(count):
        # Attacks arrive in bursts, the way a real capture does, so windows see a
        # mix of classes. A uniform spread makes every window identical and the
        # split degenerate.
        phase = (index / count) * 8 * math.pi
        in_burst = math.sin(phase) > 0.82
        attack = in_burst and rng.random() < attack_rate
        # CICFlowMeter's documented defect: the time-of-day column sits 12 hours
        # behind UTC. The adapter corrects for it, so the fixture must reproduce
        # the defect or the correction is never tested.
        stamp = start + timedelta(seconds=index * 0.9) - timedelta(hours=12)
        syn = 1.0
        ack = 1.0 if attack else float(rng.randint(0, 3))
        rows.append(
            {
                "Flow ID": f"{scenario}-{index}",
                "Source IP": rng.choice(hosts),
                "Source Port": rng.randint(1025, 65535),
                "Destination IP": rng.choice(hosts) if attack else server,
                "Destination Port": rng.choice([21, 3389, 445]) if attack else 443,
                "Protocol": 6.0,
                "Timestamp": stamp.strftime("%d/%m/%Y %H:%M:%S"),
                "Flow Duration": rng.randint(1000, 900000),
                "Total Fwd Packet": float(rng.randint(2, 60)),
                "Total Bwd packets": float(rng.randint(0, 20)),
                "Total Length of Fwd Packet": float(rng.randint(60, 6000)),
                "Total Length of Bwd Packet": float(rng.randint(0, 8000)),
                "FIN Flag Count": 0.0,
                "SYN Flag Count": syn,
                "RST Flag Count": 1.0 if attack else 0.0,
                "PSH Flag Count": 1.0 if attack else 0.0,
                "ACK Flag Count": ack,
                "Flow IAT Mean": float(rng.randint(1000, 90000)),
                " Label": attack_label if attack else "BENIGN",
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/raw/fixture-lab")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rows", type=int, default=1200)
    args = parser.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    start = datetime(2017, 7, 4, 8, tzinfo=UTC)
    days = (
        ("Tuesday-WorkingHours.pcap_ISCX.csv", "ftp-patator", start, ATTACK_LABELS[0], 0.05),
        (
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "web-attacks",
            start + timedelta(days=2),
            ATTACK_LABELS[1],
            0.05,
        ),
        (
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
            "infiltration",
            start + timedelta(days=2, hours=5),
            ATTACK_LABELS[2],
            0.02,
        ),
    )
    for filename, scenario, day_start, label, rate in days:
        rng = random.Random(f"{scenario}:{args.seed}")
        rows = _rows(rng, scenario, args.rows, day_start, label, attack_rate=rate)
        path = out / filename
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        attacks = sum(1 for row in rows if row[" Label"] != "BENIGN")
        print(f"wrote={path} rows={len(rows)} attack_rows={attacks} label={label}")


if __name__ == "__main__":
    main()
