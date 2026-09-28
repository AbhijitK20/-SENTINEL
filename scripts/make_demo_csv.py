"""Render a synthetic attack scenario as a canonical flow CSV demo fixture.

    uv run python scripts/make_demo_csv.py --output data/fixtures/attack_replay.csv

The dashboard uploader and ``scripts/predict_file.py`` both need a file with
enough windows to score; a two-row sample is not a demo. This writes one full
recon -> lateral scenario in the canonical flow-CSV schema so the demo path can
be exercised without capturing traffic first. The file is generated, not
committed by hand, so it stays in step with the generator.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from sentinel.synthetic import generate_scenario_events

COLUMNS = (
    "timestamp",
    "source_entity",
    "destination_entity",
    "source_port",
    "destination_port",
    "protocol",
    "bytes",
    "packets",
    "duration",
    "tcp_flags",
    "syn_count",
    "ack_count",
    "iat_mean",
    "bidirectional_ratio",
    "failed_auth",
)
FLAG_NAMES = ((2, "SYN"), (16, "ACK"), (8, "PSH"), (4, "RST"), (1, "FIN"), (32, "URG"))


def _flag_text(mask: float) -> str:
    value = int(mask)
    names = [name for bit, name in FLAG_NAMES if value & bit]
    return " ".join(names) if names else "NONE"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="data/fixtures/attack_replay.csv")
    parser.add_argument("--scenario", default="scenario-01")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--packet-events",
        action="store_true",
        help="Include packet-derived columns (TTL, window, fragmentation) too",
    )
    args = parser.parse_args()

    events, boundaries = generate_scenario_events(args.scenario, seed=args.seed)
    flows = [event for event in events if event.event_type == "flow"]
    packets = {
        event.event_id.rstrip("p"): event for event in events if event.event_type == "packet"
    }

    columns = list(COLUMNS)
    if args.packet_events:
        columns += ["ttl", "tcp_window_size", "fragment_flags", "retransmission"]

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for event in flows:
            features = event.features
            row = {
                "timestamp": event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "source_entity": event.source_entity,
                "destination_entity": event.destination_entity,
                "source_port": int(features["source_port"]),
                "destination_port": int(features["destination_port"]),
                "protocol": int(features["protocol"]),
                "bytes": int(features["bytes"]),
                "packets": int(features["packets"]),
                "duration": round(float(features["duration"]), 3),
                "tcp_flags": _flag_text(features["tcp_flags"]),
                "syn_count": int(features["syn_count"]),
                "ack_count": int(features["ack_count"]),
                "iat_mean": round(float(features["iat_mean"]), 4),
                "bidirectional_ratio": round(float(features["bidirectional_ratio"]), 3),
                "failed_auth": int(features["failed_auth"]),
            }
            if args.packet_events:
                packet = packets.get(event.event_id)
                row.update(
                    {
                        "ttl": int(packet.features["ttl"]) if packet else 0,
                        "tcp_window_size": int(packet.features["tcp_window_size"]) if packet else 0,
                        "fragment_flags": int(packet.features["fragment_flags"]) if packet else 0,
                        "retransmission": int(packet.features["retransmission"]) if packet else 0,
                    }
                )
            writer.writerow(row)

    print(f"wrote={out} rows={len(flows)}")
    print(f"recon_start={boundaries['recon_start'].isoformat()}")
    print(f"lateral_start={boundaries['lateral_start'].isoformat()}")


if __name__ == "__main__":
    main()
