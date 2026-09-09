"""Render burndown charts as a self-contained HTML page.

Shows:
  1. Sprint burndown (points remaining vs ideal line)
  2. Feature completion status
  3. Test count growth over sprints
  4. Code volume by module
  5. Sprint milestone timeline
"""

from __future__ import annotations

import platform
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT = REPO_ROOT / "reports" / "generated" / "burndown.html"

# ── Data ──────────────────────────────────────────────────────────────
SPRINTS = [
    {"id": 0, "name": "Foundation", "points": 13, "done": True, "tests": 2, "files": 9},
    {"id": 1, "name": "Ingestion & Features", "points": 21, "done": True, "tests": 7, "files": 14},
    {"id": 2, "name": "Labels & Targets", "points": 18, "done": True, "tests": 11, "files": 18},
    {"id": 3, "name": "Baseline Model", "points": 21, "done": True, "tests": 25, "files": 24},
    {"id": 4, "name": "Temporal Model", "points": 26, "done": True, "tests": 33, "files": 32},
    {"id": 5, "name": "Forecast Inference", "points": 18, "done": True, "tests": 41, "files": 41},
    {
        "id": 6,
        "name": "Explainability & Stages",
        "points": 18,
        "done": True,
        "tests": 52,
        "files": 45,
    },
    {
        "id": 7,
        "name": "Replay Eval & Reports",
        "points": 18,
        "done": True,
        "tests": 84,
        "files": 53,
    },
    {
        "id": 8,
        "name": "Dataset Adapter & Demo",
        "points": 21,
        "done": True,
        "tests": 92,
        "files": 57,
    },
    {
        "id": 9,
        "name": "Submission Package",
        "points": 8,
        "done": True,
        "tests": 92,
        "files": 57,
    },
    {
        "id": 10,
        "name": "Real-Data Benchmark",
        "points": 13,
        "done": True,
        "tests": 96,
        "files": 53,
    },
    {
        "id": 11,
        "name": "Live Demo",
        "points": 13,
        "done": True,
        "tests": 103,
        "files": 53,
    },
]

TOTAL_POINTS = sum(s["points"] for s in SPRINTS)
COMPLETED_POINTS = sum(s["points"] for s in SPRINTS if s["done"])
REMAINING_POINTS = TOTAL_POINTS - COMPLETED_POINTS
SPRINTS_DONE = sum(1 for s in SPRINTS if s["done"])
SPRINTS_TOTAL = len(SPRINTS)
FILES_TOTAL = 53  # python files on disk (src + scripts + tests)
TESTS_TOTAL = 103  # actual count

# ── SVG helpers ───────────────────────────────────────────────────────
W, H = 900, 520
MX, MY, MR, MB = 80, 40, 40, 80


def svg_bar_chart() -> str:
    """Sprint burndown: stacked done/remaining bars + ideal line."""
    bar_w = 64
    gap = 20
    chart_w = SPRINTS_TOTAL * (bar_w + gap)
    chart_h = 300
    max_y = TOTAL_POINTS + 10
    scale = chart_h / max_y

    bars = []
    for i, s in enumerate(SPRINTS):
        x = i * (bar_w + gap)
        done_h = s["points"] * scale if s["done"] else 0
        remaining_h = s["points"] * scale if not s["done"] else 0
        y_done = chart_h - done_h
        y_remain = y_done - remaining_h

        color_done = "#6dd3a8" if s["done"] else "#2a3340"
        color_remain = "#f0c674" if not s["done"] else "none"
        border = "#6dd3a8" if s["done"] else "#3a4456"

        bars.append(
            f'<rect x="{x}" y="{y_done - remaining_h}" width="{bar_w}" '
            f'height="{done_h}" rx="4" fill="{color_done}" opacity="0.85"/>'
        )
        if not s["done"]:
            bars.append(
                f'<rect x="{x}" y="{y_remain}" width="{bar_w}" '
                f'height="{remaining_h}" rx="4" fill="{color_remain}" '
                f'stroke="{color_remain}" stroke-width="0" opacity="0.5"/>'
            )
            # dashed box for remaining
            bars.append(
                f'<rect x="{x}" y="{y_remain}" width="{bar_w}" '
                f'height="{remaining_h}" rx="4" fill="none" '
                f'stroke="{border}" stroke-width="2" stroke-dasharray="6,4" opacity="0.7"/>'
            )
        # label
        bars.append(
            f'<text x="{x + bar_w // 2}" y="{chart_h + 18}" '
            f'text-anchor="middle" fill="#8b95a7" font-size="11">S{s["id"]}</text>'
        )
        bars.append(
            f'<text x="{x + bar_w // 2}" y="{chart_h + 32}" '
            f'text-anchor="middle" fill="#e6e8ee" font-size="10" font-weight="600">'
            f"{s['points']}pt</text>"
        )

    # ideal burndown line
    ideal_points = []
    for i in range(SPRINTS_TOTAL + 1):
        x = i * (bar_w + gap) + bar_w // 2
        y = chart_h - (TOTAL_POINTS - i * (TOTAL_POINTS / SPRINTS_TOTAL)) * scale
        ideal_points.append(f"{x},{y}")

    # actual burndown line
    actual_points = []
    cumulative = TOTAL_POINTS
    for i in range(SPRINTS_DONE + 1):
        x = i * (bar_w + gap) + bar_w // 2
        if i > 0:
            cumulative -= SPRINTS[i - 1]["points"]
        y = chart_h - cumulative * scale
        actual_points.append(f"{x},{y}")

    svg = f"""<svg width="{chart_w + 20}" height="{chart_h + 60}" viewBox="0 0 {chart_w + 20} {chart_h + 60}">
  <text x="{chart_w // 2 + 10}" y="-10" text-anchor="middle" fill="#e6e8ee" font-size="14" font-weight="700">
    Sprint Burndown ({COMPLETED_POINTS}/{TOTAL_POINTS} points completed)
  </text>
  <polyline points="{" ".join(ideal_points)}" fill="none" stroke="#8b95a7" stroke-width="2" stroke-dasharray="8,6" opacity="0.5"/>
  <text x="{chart_w - 10}" y="{chart_h - 5}" text-anchor="end" fill="#8b95a7" font-size="9">ideal</text>
  <polyline points="{" ".join(actual_points)}" fill="none" stroke="#6ea8ff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
  <text x="{chart_w // 2 + bar_w // 2}" y="{chart_h - actual_points[-1].split(",")[1].split('"')[0] if '"' in actual_points[-1] else 10 - 12}" text-anchor="middle" fill="#6dd3a8" font-size="10" font-weight="600">{REMAINING_POINTS}pt remaining</text>
  {"".join(bars)}
</svg>"""
    return svg


def svg_sprint_status() -> str:
    """Horizontal bar chart of sprint completion."""
    bar_w = 700
    row_h = 44
    svg_rows = []
    for i, s in enumerate(SPRINTS):
        y = i * row_h
        fill = "#6dd3a8" if s["done"] else "#1a2230"
        border = "#6dd3a8" if s["done"] else "#3a4456"
        status = "COMPLETE" if s["done"] else "PENDING"
        color = "#6dd3a8" if s["done"] else "#8b95a7"

        svg_rows.append(
            f'<text x="0" y="{y + 24}" fill="{color}" font-size="13" font-weight="600">S{s["id"]}</text>'
            f'<text x="32" y="{y + 24}" fill="#e6e8ee" font-size="12">{s["name"]}</text>'
            f'<text x="320" y="{y + 24}" fill="#8b95a7" font-size="12">{s["points"]} points</text>'
            f'<rect x="460" y="{y + 8}" width="{bar_w - 460}" height="24" rx="4" fill="{fill}" opacity="0.3" stroke="{border}" stroke-width="1"/>'
        )
        if s["done"]:
            svg_rows.append(
                f'<rect x="460" y="{y + 8}" width="{bar_w - 460}" height="24" rx="4" fill="{fill}" opacity="0.85"/>'
            )
        svg_rows.append(
            f'<text x="{460 + (bar_w - 460) // 2}" y="{y + 24}" text-anchor="middle" '
            f'fill="{color}" font-size="11" font-weight="700">{status}</text>'
        )

    h = SPRINTS_TOTAL * row_h
    return f"""<svg width="{bar_w}" height="{h}">
  {"".join(svg_rows)}
</svg>"""


def svg_test_growth() -> str:
    """Line chart of test count growth across sprints."""
    chart_w, chart_h = 700, 250
    max_tests = 50
    gap = 20
    bar_w = 60
    scale = chart_h / max_tests

    points = []
    labels = []
    for i, s in enumerate(SPRINTS):
        x = i * (bar_w + gap) + bar_w // 2
        y = chart_h - s["tests"] * scale
        points.append(f"{x},{y}")
        labels.append(
            f'<text x="{x}" y="{y - 8}" text-anchor="middle" fill="#6dd3a8" font-size="10" font-weight="600">'
            f"{s['tests']}</text>"
        )
        labels.append(
            f'<text x="{x}" y="{chart_h + 18}" text-anchor="middle" fill="#8b95a7" font-size="10">S{s["id"]}</text>'
        )

    return f"""<svg width="{chart_w}" height="{chart_h + 40}" viewBox="0 0 {chart_w} {chart_h + 40}">
  <text x="{chart_w // 2}" y="-5" text-anchor="middle" fill="#e6e8ee" font-size="13" font-weight="700">
    Test Growth ({TESTS_TOTAL} tests across {SPRINTS_DONE} completed sprints)
  </text>
  <polyline points="{" ".join(points)}" fill="none" stroke="#6dd3a8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="{points[-1].split(",")[0]}" cy="{points[-1].split(",")[1]}" r="5" fill="#6dd3a8"/>
  {"".join(labels)}
</svg>"""


def svg_code_volume() -> str:
    """Horizontal bar chart of code lines by module."""
    modules = [
        ("baseline.py", 403),
        ("predict.py", 360),
        ("temporal.py", 352),
        ("synthetic.py", 194),
        ("ingestion.py", 144),
        ("pcap_ingestion.py", 150),
        ("state_builder.py", 113),
        ("targets.py", 132),
        ("schemas.py", 127),
        ("config.py", 87),
        ("features.py", 83),
        ("metrics.py", 87),
    ]
    modules.sort(key=lambda m: m[1], reverse=True)
    max_lines = modules[0][1]
    bar_max_w = 500
    row_h = 28
    svg_rows = []
    for i, (name, lines) in enumerate(modules):
        y = i * row_h
        w = int(lines / max_lines * bar_max_w)
        svg_rows.append(
            f'<text x="180" y="{y + 16}" text-anchor="end" fill="#8b95a7" font-size="11">{name}</text>'
            f'<rect x="190" y="{y + 4}" width="{w}" height="18" rx="4" fill="#6ea8ff" opacity="0.7"/>'
            f'<text x="{190 + w + 6}" y="{y + 16}" fill="#e6e8ee" font-size="10">{lines} lines</text>'
        )

    h = len(modules) * row_h + 10
    return f"""<svg width="750" height="{h}" viewBox="0 0 750 {h}">
  <text x="375" y="0" text-anchor="middle" fill="#e6e8ee" font-size="13" font-weight="700">
    Source Code Volume by Module
  </text>
  {"".join(svg_rows)}
</svg>"""


def svg_metric_comparison() -> str:
    """Baseline vs temporal comparison bars."""
    metrics = [
        ("Precision", 0.775, 0.857),
        ("Recall", 0.861, 1.000),
        ("F1", 0.816, 0.923),
        ("False-positive rate", 0.107, 0.071),
    ]
    row_h = 52
    bar_max_w = 320
    svg_rows = []
    for i, (label, baseline, temporal) in enumerate(metrics):
        y = i * row_h
        bw = int(baseline * bar_max_w)
        tw = int(temporal * bar_max_w)
        svg_rows.append(
            f'<text x="160" y="{y + 14}" text-anchor="end" fill="#8b95a7" font-size="12">{label}</text>'
            f'<rect x="170" y="{y + 2}" width="{bw}" height="16" rx="4" fill="#f0c674" opacity="0.7"/>'
            f'<text x="{170 + bw + 6}" y="{y + 14}" fill="#f0c674" font-size="10">{baseline:.3f}</text>'
            f'<rect x="170" y="{y + 22}" width="{tw}" height="16" rx="4" fill="#6dd3a8" opacity="0.7"/>'
            f'<text x="{170 + tw + 6}" y="{y + 34}" fill="#6dd3a8" font-size="10">{temporal:.3f}</text>'
        )
    h = len(metrics) * row_h + 10
    legend = (
        f'<rect x="170" y="{h - 10}" width="12" height="12" rx="3" fill="#f0c674" opacity="0.7"/>'
        f'<text x="188" y="{h}" fill="#8b95a7" font-size="10">Baseline</text>'
        f'<rect x="270" y="{h - 10}" width="12" height="12" rx="3" fill="#6dd3a8" opacity="0.7"/>'
        f'<text x="288" y="{h}" fill="#8b95a7" font-size="10">Temporal h+5</text>'
    )
    return f"""<svg width="620" height="{h + 20}" viewBox="0 0 620 {h + 20}">
  <text x="310" y="0" text-anchor="middle" fill="#e6e8ee" font-size="13" font-weight="700">
    Baseline vs Temporal (Test Split, 10 Scenarios, Seed 42)
  </text>
  {"".join(svg_rows)}
  {legend}
</svg>"""


# ── Full HTML ─────────────────────────────────────────────────────────
def build() -> str:
    now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    py = sys.version.split()[0]
    plat = platform.platform()

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Trajectory — Burndown &amp; Progress</title>
<style>
  :root {{
    --bg: #0b0d12; --panel: #141820; --ink: #e6e8ee; --muted: #8b95a7;
    --accent: #6ea8ff; --good: #6dd3a8; --warn: #f0c674; --border: #1e2636;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--ink);
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    line-height: 1.5;
  }}
  header {{
    padding: 28px 40px 20px; border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, #141820, var(--bg));
  }}
  header h1 {{ font-size: 22px; margin-bottom: 4px; }}
  header .sub {{ color: var(--muted); font-size: 13px; }}
  main {{ padding: 28px 40px; display: flex; flex-direction: column; gap: 28px; }}
  section {{
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px; padding: 22px 26px;
  }}
  section h2 {{
    font-size: 15px; color: var(--accent); letter-spacing: 0.03em;
    margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid var(--border);
  }}
  .kpi-grid {{
    display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px;
    margin-bottom: 8px;
  }}
  .kpi {{
    text-align: center; padding: 14px 8px;
    background: #0b0d12; border: 1px solid var(--border); border-radius: 8px;
  }}
  .kpi .value {{ font-size: 28px; font-weight: 700; color: var(--good); }}
  .kpi .label {{ font-size: 11px; color: var(--muted); margin-top: 4px; }}
  .kpi .sub-value {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
  .chart-row {{
    display: flex; justify-content: center; overflow-x: auto;
  }}
  .legend {{
    display: flex; gap: 24px; justify-content: center;
    margin-top: 12px; color: var(--muted); font-size: 12px;
  }}
  .legend span::before {{
    content: ""; display: inline-block; width: 12px; height: 12px;
    border-radius: 3px; margin-right: 6px; vertical-align: middle;
  }}
  .legend .done::before {{ background: #6dd3a8; }}
  .legend .pending::before {{ background: #3a4456; border: 2px dashed #3a4456; }}
  .legend .baseline::before {{ background: #f0c674; }}
  .legend .temporal::before {{ background: #6dd3a8; }}
  .legend .ideal::before {{ background: transparent; border: 2px dashed #8b95a7; }}
  .legend .actual::before {{ background: transparent; border: 2px solid #6ea8ff; }}
  .footer {{
    padding: 16px 40px; color: var(--muted); font-size: 11px;
    border-top: 1px solid var(--border); text-align: center;
  }}
</style>
</head>
<body>
<header>
  <h1>Trajectory — Burndown &amp; Progress Dashboard</h1>
  <div class="sub">SIH26153 — AI Based Network Attack Forecasting from Network Traffic Data &middot; generated {now}</div>
</header>
<main>

  <!-- KPI row -->
  <div class="kpi-grid">
    <div class="kpi">
      <div class="value">{SPRINTS_DONE}/{SPRINTS_TOTAL}</div>
      <div class="label">Sprints Complete</div>
      <div class="sub-value">{SPRINTS_TOTAL - SPRINTS_DONE} remaining</div>
    </div>
    <div class="kpi">
      <div class="value">{COMPLETED_POINTS}</div>
      <div class="label">Points Completed</div>
      <div class="sub-value">of {TOTAL_POINTS} total</div>
    </div>
    <div class="kpi">
      <div class="value" style="color: #f0c674;">{REMAINING_POINTS}</div>
      <div class="label">Points Remaining</div>
      <div class="sub-value">{REMAINING_POINTS / TOTAL_POINTS * 100:.0f}% of total</div>
    </div>
    <div class="kpi">
      <div class="value">{TESTS_TOTAL}</div>
      <div class="label">Tests Passing</div>
      <div class="sub-value">41 source + forecast</div>
    </div>
    <div class="kpi">
      <div class="value">{FILES_TOTAL}</div>
      <div class="label">Project Files</div>
      <div class="sub-value">src + tests + reports + scripts</div>
    </div>
  </div>

  <!-- Sprint Burndown -->
  <section>
    <h2>Sprint Burndown — Points Remaining</h2>
    <div class="chart-row">{svg_bar_chart()}</div>
    <div class="legend">
      <span class="done">Completed sprints</span>
      <span class="pending">Remaining work</span>
      <span class="ideal">Ideal burndown</span>
      <span class="actual">Actual burndown</span>
    </div>
  </section>

  <!-- Sprint Status -->
  <section>
    <h2>Sprint Status</h2>
    <div class="chart-row">{svg_sprint_status()}</div>
  </section>

  <!-- Metric Comparison -->
  <section>
    <h2>Baseline vs Temporal — Test Split Metrics</h2>
    <div class="chart-row">{svg_metric_comparison()}</div>
  </section>

  <!-- Test Growth -->
  <section>
    <h2>Test Growth Over Sprints</h2>
    <div class="chart-row">{svg_test_growth()}</div>
  </section>

  <!-- Code Volume -->
  <section>
    <h2>Source Code Volume by Module</h2>
    <div class="chart-row">{svg_code_volume()}</div>
  </section>

  <!-- Summary -->
  <section>
    <h2>What Has Been Built (Sprints 0-5)</h2>
    <table style="width:100%; border-collapse:collapse; font-size:13px;">
      <thead>
        <tr>
          <th style="text-align:left;padding:8px;border-bottom:1px solid #1e2636;color:#8b95a7;">Sprint</th>
          <th style="text-align:left;padding:8px;border-bottom:1px solid #1e2636;color:#8b95a7;">Module</th>
          <th style="text-align:left;padding:8px;border-bottom:1px solid #1e2636;color:#8b95a7;">What It Does</th>
          <th style="text-align:left;padding:8px;border-bottom:1px solid #1e2636;color:#8b95a7;">Status</th>
        </tr>
      </thead>
      <tbody>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S0</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">config, schemas</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">Strict YAML config and typed data contracts for events, states, forecasts</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">Done</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S1</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">ingestion, pcap_ingestion</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">Reads CSV flows and PCAP captures into unified events with validation</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">Done</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S2</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">targets</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">Builds scenario-safe labels, future targets, sequence samples, and split manifests</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">Done</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S3</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">baseline, features, metrics</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">Logistic regression on current window; leakage-safe feature fitting and metrics</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">Done</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S4</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">temporal</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">GRU encoder for multi-horizon infiltration prediction; early stopping</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">Done</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S5</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">predict</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">Loads saved models and emits a Forecast with timeline, stage, features, warnings</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#6dd3a8;">Done</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S6</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#f0c674;">real dataset adapter</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">CIC-IDS2017 / CTU-13 adapter; real-traffic evaluation</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#8b95a7;">Pending</td></tr>
        <tr><td style="padding:8px;border-bottom:1px solid #1e2636;">S7</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#f0c674;">dashboard, demo</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;">Streamlit dashboard; interactive forecast viewer; replay</td>
            <td style="padding:8px;border-bottom:1px solid #1e2636;color:#8b95a7;">Pending</td></tr>
        <tr><td style="padding:8px;">S8</td>
            <td style="padding:8px;color:#f0c674;">submission</td>
            <td style="padding:8px;">README, architecture doc, PPT, demo video, final benchmark</td>
            <td style="padding:8px;color:#8b95a7;">Pending</td></tr>
      </tbody>
    </table>
  </section>

</main>
<div class="footer">
  Generated by render_burndown.py &middot; python {py} &middot; {plat}
</div>
</body>
</html>"""


def main() -> None:
    html = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(html, encoding="utf-8")
    print(f"burndown: {OUT} ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
