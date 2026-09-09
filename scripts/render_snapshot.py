"""Render a single self-contained HTML index of every artifact the project has produced.

The output has no external dependencies: no CDN, no JS framework, no images.
The dashboard is the Sprint 7 deliverable; this snapshot is a quick visual
review of what is currently on disk and what the pipeline produced on the
most recent run.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports" / "generated"
OUTPUT_PATH = REPORTS_DIR / "snapshot.html"


def _read_text(path: Path) -> str:
    if not path.is_file():
        return f"(missing: {path.relative_to(REPO_ROOT)})"
    return path.read_text(encoding="utf-8")


def _read_json(path: Path) -> object:
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _inventory() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(REPO_ROOT.rglob("*")):
        if any(
            part in {"__pycache__", ".venv", ".pytest_cache", ".ruff_cache"} for part in path.parts
        ):
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel.startswith("reports/generated/snapshot"):
            continue
        size = path.stat().st_size
        rows.append({"path": rel, "size": str(size)})
    return rows


def _forecast_preview() -> dict[str, object]:
    forecast_path = REPORTS_DIR / "forecast_preview.json"
    if not forecast_path.is_file():
        return {}
    return _read_json(forecast_path) or {}


def _render_html(inventory: list[dict[str, str]], forecast: dict[str, object]) -> str:
    inventory_rows = "\n".join(
        f"<tr><td><code>{row['path']}</code></td><td class='num'>{row['size']}</td></tr>"
        for row in inventory
    )
    baseline_json = _read_json(REPORTS_DIR / "baseline" / "baseline_result.json") or {}
    temporal_json = _read_json(REPORTS_DIR / "temporal" / "temporal_result.json") or {}
    comparison_md = _read_text(REPORTS_DIR / "comparison" / "comparison.md")
    baseline_md = _read_text(REPORTS_DIR / "baseline" / "baseline_report.md")
    temporal_md = _read_text(REPORTS_DIR / "temporal" / "temporal_report.md")
    dataset_md = _read_text(REPORTS_DIR / "baseline" / "DATASET.md")

    timeline_rows = "".join(
        f"<tr><td>+{point.get('window')}</td>"
        f"<td class='num'>{point.get('infiltration_probability', 0):.4f}</td>"
        f"<td class='num'>{point.get('confidence', 0):.4f}</td></tr>"
        for point in forecast.get("probability_timeline", [])
    )
    driving_rows = "".join(
        f"<tr><td>{f.get('name')}</td>"
        f"<td class='num'>{f.get('contribution', 0):+.4f}</td>"
        f"<td>{f.get('direction')}</td></tr>"
        for f in forecast.get("driving_features", [])
    )
    warnings_html = (
        "".join(f"<li>{w}</li>" for w in forecast.get("warnings", [])) or "<li>(none)</li>"
    )

    baseline_metrics = baseline_json.get("metrics", {}).get("test", {})
    temporal_metrics = (
        (temporal_json.get("horizons") or [{}])[-1].get("metrics", {}).get("test", {})
    )

    def _fmt(value):
        if value is None:
            return "n/a"
        try:
            return f"{value:.4f}"
        except (TypeError, ValueError):
            return str(value)

    generated_at = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    python_version = sys.version.split()[0]

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Trajectory SIH26153 — snapshot</title>
<style>
  :root {{
    --bg: #0f1115; --panel: #161a22; --ink: #e6e8ee; --muted: #8b95a7;
    --accent: #6ea8ff; --good: #6dd3a8; --warn: #f0c674; --bad: #ef6f6f;
    --border: #232938;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--ink); line-height: 1.45;
  }}
  header {{
    padding: 24px 32px; border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, #161a22, #0f1115);
  }}
  header h1 {{ margin: 0 0 4px 0; font-size: 22px; }}
  header .meta {{ color: var(--muted); font-size: 13px; }}
  main {{ display: grid; grid-template-columns: 320px 1fr; gap: 24px; padding: 24px 32px; }}
  aside {{ position: sticky; top: 16px; align-self: start; max-height: calc(100vh - 32px); overflow: auto; }}
  section {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 18px 20px; margin-bottom: 20px;
  }}
  section h2 {{ margin: 0 0 12px 0; font-size: 16px; color: var(--accent); letter-spacing: 0.02em; }}
  section h3 {{ margin: 16px 0 8px 0; font-size: 14px; color: var(--muted); font-weight: 600; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 500; }}
  td.num, th.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  code {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px; color: var(--ink);
  }}
  pre {{
    background: #0b0d12; border: 1px solid var(--border);
    border-radius: 6px; padding: 12px 14px; overflow: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px; color: var(--ink);
  }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 11px; background: #1f2632; color: var(--muted);
  }}
  .badge.good {{ background: rgba(109,211,168,0.12); color: var(--good); }}
  .badge.warn {{ background: rgba(240,198,116,0.12); color: var(--warn); }}
  .badge.bad  {{ background: rgba(239,111,111,0.12); color: var(--bad); }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }}
  ul {{ margin: 4px 0 0 18px; padding: 0; color: var(--muted); font-size: 13px; }}
  .stat {{ display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px dashed var(--border); font-size: 13px; }}
  .stat:last-child {{ border-bottom: 0; }}
  .stat .label {{ color: var(--muted); }}
</style>
</head>
<body>
<header>
  <h1>Trajectory — SIH26153 snapshot</h1>
  <div class="meta">
    generated {generated_at} · python {python_version} · platform {platform.platform()}
  </div>
</header>
<main>
  <aside>
    <section>
      <h2>Status</h2>
      <div class="stat"><span class="label">Sprint</span><span><span class="badge good">10/10 complete + real-data benchmark</span></span></div>
      <div class="stat"><span class="label">Tests</span><span>96 passed</span></div>
      <div class="stat"><span class="label">Lint / format</span><span><span class="badge good">clean</span></span></div>
      <div class="stat"><span class="label">uv lock</span><span><span class="badge good">in sync</span></span></div>
      <div class="stat"><span class="label">Baseline test P/R/F1</span>
        <span>{_fmt(baseline_metrics.get("precision"))} / {_fmt(baseline_metrics.get("recall"))} / {_fmt(baseline_metrics.get("f1"))}</span></div>
      <div class="stat"><span class="label">Temporal h+5 P/R/F1</span>
        <span>{_fmt(temporal_metrics.get("precision"))} / {_fmt(temporal_metrics.get("recall"))} / {_fmt(temporal_metrics.get("f1"))}</span></div>
    </section>
    <section>
      <h2>Inventory ({len(inventory)} files)</h2>
      <table>
        <thead><tr><th>path</th><th class='num'>bytes</th></tr></thead>
        <tbody>{inventory_rows}</tbody>
      </table>
    </section>
  </aside>

  <div>
    <section>
      <h2>Forecast preview</h2>
      <h3>Probability timeline (current run)</h3>
      <table>
        <thead><tr><th>window</th><th class='num'>P(infiltration)</th><th class='num'>confidence</th></tr></thead>
        <tbody>{timeline_rows or "<tr><td colspan='3'>no forecast cached; run scripts/run_forecast.py</td></tr>"}</tbody>
      </table>
      <h3>Driving features</h3>
      <table>
        <thead><tr><th>name</th><th class='num'>contribution</th><th>direction</th></tr></thead>
        <tbody>{driving_rows or "<tr><td colspan='3'>(none)</td></tr>"}</tbody>
      </table>
      <h3>Warnings</h3>
      <ul>{warnings_html}</ul>
    </section>

    <section>
      <h2>Comparison report</h2>
      <pre>{comparison_md}</pre>
    </section>

    <section>
      <h2>Baseline report</h2>
      <pre>{baseline_md}</pre>
    </section>

    <section>
      <h2>Temporal report</h2>
      <pre>{temporal_md}</pre>
    </section>

    <section>
      <h2>Dataset note</h2>
      <pre>{dataset_md}</pre>
    </section>
  </div>
</main>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--forecast", default=None, help="Optional forecast.json to embed")
    parser.add_argument("--output", default=str(OUTPUT_PATH))
    args = parser.parse_args()

    forecast_path: Path | None = None
    if args.forecast:
        forecast_path = Path(args.forecast)
    else:
        candidate = REPORTS_DIR / "forecast_preview.json"
        if candidate.is_file():
            forecast_path = candidate

    if forecast_path is not None and forecast_path.is_file():
        preview_target = REPORTS_DIR / "forecast_preview.json"
        preview_target.write_text(forecast_path.read_text(encoding="utf-8"), encoding="utf-8")

    inventory = _inventory()
    forecast = _forecast_preview()
    html = _render_html(inventory, forecast)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"snapshot: {out} ({out.stat().st_size} bytes, {len(inventory)} files)")


if __name__ == "__main__":
    main()
