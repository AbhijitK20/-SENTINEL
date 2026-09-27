"""How much does this actually process per second, and is that going to hold?

    uv run python scripts/run_perf_profile.py

Times the two stages the existing performance budgets cover - CSV ingestion and
windowing - across a range of sizes, and reports throughput, the log-log slope,
and the largest size that fits each budget on the machine that ran it.

The budgets themselves are unchanged. The point is to attach a unit and a machine
to them, because a wall-clock limit with neither is a specification that only
fails on other people's hardware.

Timings are from one machine and one run. Extrapolating past the largest size
measured is arithmetic on a fitted slope, and the report says so rather than
presenting a projected capacity as a measurement.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from sentinel.ingestion import read_flow_csv
from sentinel.perf_profile import (
    DEFAULT_SIZES,
    PERF_PROFILE_VERSION,
    machine,
    measure,
    render,
    report,
)
from sentinel.state_builder import build_network_states

# The budgets tests/test_performance.py asserts, so the two can be compared
# directly instead of living in different places with no relationship.
CSV_BUDGET_SECONDS = 10.0
WINDOW_BUDGET_SECONDS = 5.0

START = "2026-01-01T00:00:00Z"
HEADER = (
    "timestamp,source_entity,destination_entity,source_port,"
    "destination_port,protocol,bytes,packets,duration"
)


def _build_csv(tmp: Path, n: int) -> Path:
    lines = [HEADER]
    step = 9 * 3600 / n
    for i in range(n):
        minutes = int(i * step // 60)
        seconds = int(i * step % 60)
        lines.append(
            f"2026-01-01T{minutes // 60 % 24:02d}:{minutes % 60:02d}:{seconds:02d}Z,"
            f"host-{i % 50},server-{i % 20},443,80,6,{i % 1000},{i % 100},0.1"
        )
    path = tmp / f"perf_{n}.csv"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _build_events(n: int) -> list:
    from datetime import datetime, timedelta

    from sentinel.schemas import UnifiedEvent

    start = datetime(2026, 1, 1, tzinfo=UTC)
    span = timedelta(hours=9)
    step = span / max(n, 1)
    return [
        UnifiedEvent(
            event_id=f"evt-{i}",
            timestamp=start + step * i,
            source_entity=f"host-{i % 50}",
            destination_entity=f"server-{i % 20}",
            event_type="flow",
            features={"bytes": float(i % 1000), "packets": float(i % 100)},
            source_format="replay",
            provenance=f"perf:{i}",
        )
        for i in range(n)
    ]


def run(sizes: tuple[int, ...] = DEFAULT_SIZES) -> dict:
    import tempfile

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        csv_profile = measure(
            "read_flow_csv",
            sizes,
            lambda n: _build_csv(tmp, n),
            lambda path: read_flow_csv(path),
            budget_seconds=CSV_BUDGET_SECONDS,
        )
        window_profile = measure(
            "build_network_states",
            sizes,
            _build_events,
            lambda events: build_network_states(events, window_seconds=60, stride_seconds=30),
            budget_seconds=WINDOW_BUDGET_SECONDS,
        )
    payload = report([csv_profile, window_profile], machine())
    payload["dataset_id"] = "synthetic"
    payload["generated_at"] = datetime.now(UTC).isoformat()
    payload["budgets"] = {
        "read_flow_csv_seconds": CSV_BUDGET_SECONDS,
        "build_network_states_seconds": WINDOW_BUDGET_SECONDS,
        "source": "tests/test_performance.py",
    }
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=list(DEFAULT_SIZES))
    parser.add_argument("--output", default="reports/generated/perf-profile")
    args = parser.parse_args()

    payload = run(tuple(sorted(args.sizes)))
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "perf_profile.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out / "perf_profile.md").write_text(render(payload), encoding="utf-8")

    print(
        f"version={PERF_PROFILE_VERSION}  machine={payload['machine']['platform']}  "
        f"cpus={payload['machine']['cpu_count']}"
    )
    for profile in payload["profiles"]:
        print()
        print(f"{profile['stage']}:")
        for m in profile["measurements"]:
            print(
                f"  {m['n_items']:>9,}  {m['seconds']:>8.3f}s  "
                f"{m['items_per_second']:>12,.0f} items/s  {m['microseconds_per_item']:.2f} us/item"
            )
        slope = profile["exponent"]
        print(
            f"  slope {slope:.2f} ({profile['shape'].upper()})  "
            f"largest within {profile['budget_seconds']:g}s: "
            f"{profile['largest_measured_size_within_budget']:,}"
        )
    print()
    for warning in payload["warnings"]:
        print(f"warning: {warning}")
    print(f"perf_profile_json={out / 'perf_profile.json'}")
    print(f"perf_profile_md={out / 'perf_profile.md'}")


if __name__ == "__main__":
    main()
