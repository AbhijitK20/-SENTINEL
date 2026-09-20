"""Validate the rule detectors against real lab-generated attack traffic.

Drives the vulnerable demo app's real attack modules (plain HTTP requests from
the standard library) through the live path:

    attack script -> vulnerable app access.log -> apps/vulnerable/scanner.py
        -> POST /v1/events -> LiveEngine -> detectors -> /v1/live findings

and records, per scenario, which detectors actually fired versus the detector
each attack claims to trigger.

Honest scope: single-host lab, known attack tools, and the event features are
derived from the application access log rather than packet capture. This
validates the detector plumbing against real traffic; it is not a field
benchmark and its numbers must not be presented as one.

Prerequisites — demo stack running:

    docker compose --profile demo up -d --no-deps api vulnerable-app demo-sentinel

Usage:

    uv run python scripts/validate_real_detectors.py
    uv run python scripts/validate_real_detectors.py --scenario scan --scenario brute_force
    uv run python scripts/validate_real_detectors.py --start --settle-seconds 60
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "reports" / "generated" / "real-detector-validation"


@dataclass(frozen=True)
class Scenario:
    name: str
    module: str
    expected: tuple[str, ...]
    claim: str


# `expected` is the detector each attack's own docstring claims to trigger,
# restated as a hypothesis to test — not ground truth. An empty tuple means the
# attack makes no detector claim (web-layer attacks have no network detector).
SCENARIOS: tuple[Scenario, ...] = (
    Scenario("scan", "attacks.scan", ("reconnaissance",), "recon detector"),
    Scenario(
        "traversal",
        "attacks.traversal",
        ("reconnaissance",),
        "recon detector",
    ),
    Scenario("enum", "attacks.enum", ("reconnaissance", "exfiltration"), "recon + exfil"),
    Scenario(
        "brute_force",
        "attacks.brute_force",
        ("credential_abuse",),
        "credential detector",
    ),
    Scenario(
        "credential_stuffing",
        "attacks.credential_stuffing",
        ("credential_abuse",),
        "credential detector",
    ),
    Scenario(
        "full_chain",
        "attacks.full_chain",
        ("reconnaissance", "credential_abuse", "exfiltration"),
        "chain: recon -> credential -> exfil",
    ),
    Scenario("sqli", "attacks.sqli", (), "no detector claim"),
    Scenario("xss", "attacks.xss", (), "docstring claims web detector (does not exist)"),
)


def _http_json(url: str, method: str = "GET", timeout: float = 10.0) -> dict:
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - localhost only
        return json.loads(resp.read().decode("utf-8"))


def _live_status(base_url: str) -> dict:
    return _http_json(f"{base_url}/v1/live")


def _reset(base_url: str) -> None:
    _http_json(f"{base_url}/v1/live/reset", method="POST")


def _wait_for_quiet(base_url: str, timeout: float, poll_seconds: float = 2.0) -> None:
    """Wait until the engine has no alerting findings for two consecutive polls.

    The scanner replays any pre-existing access.log on startup; without this
    wait those stale findings would be attributed to the first scenario.
    """
    deadline = time.monotonic() + timeout
    quiet = 0
    while time.monotonic() < deadline:
        status = _live_status(base_url)
        alerts = [f for f in status.get("findings", []) if f.get("is_alert")]
        quiet = quiet + 1 if not alerts else 0
        if quiet >= 2:
            return
        time.sleep(poll_seconds)
    print(f"  warning: engine did not go quiet within {timeout:.0f}s", file=sys.stderr)


def _run_attack(scenario: Scenario, target: str) -> tuple[int, float]:
    cmd = [sys.executable, "-m", scenario.module, "--target", target]
    t0 = time.monotonic()
    # The attack modules import each other as `attacks.*`; run from apps/vulnerable.
    proc = subprocess.run(
        cmd, cwd=ROOT / "apps" / "vulnerable", capture_output=True, text=True, timeout=600
    )
    elapsed = time.monotonic() - t0
    if proc.returncode != 0:
        print(f"  attack exited {proc.returncode}: {proc.stderr[-400:]}", file=sys.stderr)
    return proc.returncode, round(elapsed, 2)


def _observe(base_url: str, settle_seconds: float, poll_seconds: float = 2.0) -> dict:
    """Poll /v1/live for `settle_seconds`; record first-seen latency."""
    t0 = time.monotonic()
    deadline = t0 + settle_seconds
    first_alert_at: float | None = None
    first_poll_had_alerts = False
    first_poll = True
    status: dict = {}
    while time.monotonic() < deadline:
        status = _live_status(base_url)
        alerts = [f for f in status.get("findings", []) if f.get("is_alert")]
        if alerts and first_alert_at is None:
            first_alert_at = time.monotonic() - t0
            first_poll_had_alerts = first_poll
        first_poll = False
        time.sleep(poll_seconds)
    status = _live_status(base_url)
    findings = status.get("findings", [])
    alerts = [f for f in findings if f.get("is_alert")]
    return {
        "findings": findings,
        "alerts": alerts,
        "observed_attack_types": sorted({f["attack_type"] for f in alerts}),
        "incidents": status.get("incidents", []),
        "events_seen": status.get("events_seen", 0),
        "windows_emitted": status.get("windows_emitted", 0),
        "peak_probability": status.get("peak_probability"),
        "alert_status": status.get("alert_status"),
        "first_poll_had_alerts": first_poll_had_alerts,
        "first_alert_seconds_after_attack": (
            round(first_alert_at, 2) if first_alert_at is not None else None
        ),
    }


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _start_stack() -> None:
    subprocess.run(
        [
            "docker",
            "compose",
            "--profile",
            "demo",
            "up",
            "-d",
            "--no-deps",
            "api",
            "vulnerable-app",
            "demo-sentinel",
        ],
        cwd=ROOT,
        check=True,
    )


def _wait_healthy(base_url: str, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            _http_json(f"{base_url}/health", timeout=3.0)
            return
        except (urllib.error.URLError, OSError):
            time.sleep(2.0)
    raise SystemExit(f"SENTINEL API not reachable at {base_url}/health after {timeout:.0f}s")


def _verdict(expected: set[str], missed: set[str]) -> str:
    if not expected:
        return "NO-CLAIM"
    return "HIT" if not missed else "MISS"


def _run_scenario(scenario: Scenario, args: argparse.Namespace) -> dict:
    print(f"[{scenario.name}] reset -> attack -> observe {args.settle_seconds:.0f}s")
    _reset(args.base_url)
    _wait_for_quiet(args.base_url, timeout=args.quiet_timeout)
    _reset(args.base_url)

    t0 = time.monotonic()
    returncode, attack_seconds = _run_attack(scenario, args.target)
    observed = _observe(args.base_url, args.settle_seconds)

    expected = set(scenario.expected)
    seen = set(observed["observed_attack_types"])
    # Alerts already present when the attack process exited could have fired at
    # any point during the attack; we can only bound them, not time them.
    within_attack = observed["first_poll_had_alerts"]
    first_alert = (
        attack_seconds
        if within_attack
        else (
            round(attack_seconds + observed["first_alert_seconds_after_attack"], 2)
            if observed["first_alert_seconds_after_attack"] is not None
            else None
        )
    )
    result = {
        "scenario": scenario.name,
        "module": scenario.module,
        "claim": scenario.claim,
        "expected_attack_types": sorted(expected),
        "observed_attack_types": sorted(seen),
        "attack_returncode": returncode,
        "attack_seconds": attack_seconds,
        "seconds_total": round(time.monotonic() - t0, 2),
        "findings_emitted": len(observed["findings"]),
        "alerts_total": len(observed["alerts"]),
        "incidents_total": len(observed["incidents"]),
        "hit": sorted(expected & seen),
        "missed": sorted(expected - seen),
        "unexpected": sorted(seen - expected),
        "first_alert_seconds": first_alert,
        "first_alert_within_attack": within_attack,
        "peak_probability": observed["peak_probability"],
        "alert_status": observed["alert_status"],
        "events_seen": observed["events_seen"],
        "windows_emitted": observed["windows_emitted"],
        "alert_details": [
            {
                "attack_type": f["attack_type"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "probability": f["probability"],
                "window_start": f.get("window_start"),
            }
            for f in observed["alerts"]
        ],
        "incident_details": [
            {
                "incident_id": i["incident_id"],
                "risk_level": i.get("risk", {}).get("level"),
                "progression": i.get("progression", []),
                "finding_attack_types": i.get("finding_attack_types", []),
            }
            for i in observed["incidents"]
        ],
    }
    verdict = _verdict(expected, set(result["missed"]))
    print(
        f"  rc={returncode} seen={result['observed_attack_types'] or 'none'} "
        f"alerts={result['alerts_total']} incidents={result['incidents_total']} -> {verdict}"
    )
    return result


def _write_markdown(results: list[dict], meta: dict, out_path: Path) -> None:
    lines = [
        "# Real-Traffic Detector Validation",
        "",
        f"- Generated: {meta['generated_at']}",
        f"- Commit: `{meta['commit']}`",
        f"- Attack target: `{meta['target']}`",
        f"- Observation window per scenario: {meta['settle_seconds']:.0f}s",
        "",
        "> **Scope.** Real HTTP attack traffic from the repo's demo attack modules, fed "
        "through the live path (access log -> scanner -> `/v1/events` -> LiveEngine). "
        "Single-host lab, known tools, log-derived event features. This is detector "
        "plumbing validation against real traffic, **not** a field benchmark.",
        "",
        "## Detector matrix",
        "",
        "| Scenario | Claim | Expected | Observed | Alerts | Incidents | First | Verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        expected = ", ".join(r["expected_attack_types"]) or "—"
        seen_all = sorted({f["attack_type"] for f in r["alert_details"]})
        observed = ", ".join(seen_all) or "none"
        verdict = _verdict(set(r["expected_attack_types"]), set(r["missed"]))
        if r["first_alert_seconds"] is None:
            first = "—"
        elif r["first_alert_within_attack"]:
            first = "during attack"
        else:
            first = f"{r['first_alert_seconds']}s"
        lines.append(
            f"| `{r['scenario']}` | {r['claim']} | {expected} | {observed} | "
            f"{r['alerts_total']} | {r['incidents_total']} | {first} | {verdict} |"
        )
    lines += [
        "",
        "## Findings",
        "",
        "- `HIT`: every detector the attack claims to trigger fired.",
        "- `MISS`: at least one claimed detector did not fire on this run.",
        "- `NO-CLAIM`: the attack makes no detector claim; results are informational.",
        "",
        "Claimed-but-missed detectors and unexpected firings are recorded per scenario in "
        "`real_detector_validation.json` (`missed`, `unexpected`).",
        "",
        "## Caveats",
        "",
        "- Detectors consume events derived from the application access log, not packet "
        "capture; the recon detector's packet-level path is validated separately by the "
        "`realtime` compose profile.",
        "- A single run per scenario, one host, fixed attack tools and parameters; this "
        "does not measure false positives or detection on unseen attack variants.",
        "- Absence of a finding is not proof the detector is broken; window boundaries "
        "and the observation window can miss low-volume attacks.",
    ]
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--base-url", default="http://127.0.0.1:8100")
    parser.add_argument("--target", default="http://127.0.0.1:5000")
    parser.add_argument("--scenario", action="append", choices=[s.name for s in SCENARIOS])
    parser.add_argument("--settle-seconds", type=float, default=60.0)
    parser.add_argument("--quiet-timeout", type=float, default=90.0)
    parser.add_argument(
        "--start", action="store_true", help="docker compose up the demo services first"
    )
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    args = parser.parse_args()

    if args.start:
        _start_stack()
    _wait_healthy(args.base_url)

    selected = [s for s in SCENARIOS if not args.scenario or s.name in args.scenario]
    meta = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "commit": _git_commit(),
        "target": args.target,
        "base_url": args.base_url,
        "settle_seconds": args.settle_seconds,
    }

    _wait_for_quiet(args.base_url, timeout=args.quiet_timeout)
    results = [_run_scenario(scenario, args) for scenario in selected]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "real_detector_validation.json").write_text(
        json.dumps({"meta": meta, "results": results}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    _write_markdown(results, meta, out_dir / "README.md")

    hits = sum(1 for r in results if r["expected_attack_types"] and not r["missed"])
    claimed = sum(1 for r in results if r["expected_attack_types"])
    print(f"\nClaimed-detector scenarios: {hits}/{claimed} hit. Wrote {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
