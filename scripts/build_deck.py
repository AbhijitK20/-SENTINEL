"""Build the six-slide SIH idea deck for Trajectory (SIH26153).

The content mirrors PRESENTATION_OUTLINE.md. Unverified values (team ID, market
figures, metrics, links) are emitted as visible [ADD ...] placeholders so they
are never mistaken for facts. Run with:

    uv run --group presentation python scripts/build_deck.py
    # optional PDF export (requires LibreOffice):
    uv run --group presentation python scripts/build_deck.py --pdf
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "deliverables"
OUT_FILE = OUT_DIR / "Trajectory_SIH26153_Idea_Deck.pptx"

# Palette: dark security background with a single accent.
BG = RGBColor(0x0B, 0x12, 0x20)
PANEL = RGBColor(0x14, 0x1E, 0x33)
PANEL_ALT = RGBColor(0x1B, 0x28, 0x44)
ACCENT = RGBColor(0x2E, 0xD3, 0xB7)
WARN = RGBColor(0xF4, 0xB8, 0x60)
TEXT = RGBColor(0xEE, 0xF2, 0xF8)
MUTED = RGBColor(0x9F, 0xAC, 0xC2)
PLACEHOLDER = RGBColor(0xFF, 0xD1, 0x66)

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)
MARGIN = Inches(0.45)


# --------------------------------------------------------------------------- helpers
def add_bg(slide) -> None:
    bg = slide.background.fill
    bg.solid()
    bg.fore_color.rgb = BG


def add_rect(slide, x, y, w, h, fill=PANEL, line=None, radius=True):
    shape_type = MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE
    shp = slide.shapes.add_shape(shape_type, x, y, w, h)
    shp.fill.solid()
    shp.fill.fore_color.rgb = fill
    if line is None:
        shp.line.fill.background()
    else:
        shp.line.color.rgb = line
        shp.line.width = Pt(1)
    if radius:
        shp.adjustments[0] = 0.06
    shp.shadow.inherit = False
    return shp


def add_text(
    slide,
    x,
    y,
    w,
    h,
    text: str | list,
    size: int = 12,
    bold: bool = False,
    color=TEXT,
    align=PP_ALIGN.LEFT,
    anchor=MSO_ANCHOR.TOP,
    font: str = "Calibri",
    bullets: bool = False,
    line_spacing: float = 1.05,
):
    """Add a textbox. `text` may be a string or list of strings/(string, opts) tuples."""
    tb = slide.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = tf.margin_right = Inches(0.08)
    tf.margin_top = tf.margin_bottom = Inches(0.04)
    lines = text if isinstance(text, list) else [text]
    for i, item in enumerate(lines):
        opts: dict = {}
        if isinstance(item, tuple):
            item, opts = item
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = opts.get("align", align)
        p.line_spacing = line_spacing
        p.space_after = Pt(opts.get("space_after", 2))
        prefix = "\u2022 " if (bullets and not opts.get("no_bullet")) else ""
        run = p.add_run()
        run.text = prefix + item
        f = run.font
        f.name = opts.get("font", font)
        f.size = Pt(opts.get("size", size))
        f.bold = opts.get("bold", bold)
        f.color.rgb = opts.get("color", PLACEHOLDER if "[ADD" in item else color)
    return tb


def header(slide, title: str, subtitle: str | None, slide_no: int) -> None:
    add_rect(slide, 0, 0, SLIDE_W, Inches(0.08), fill=ACCENT, radius=False)
    add_text(slide, MARGIN, Inches(0.18), Inches(10.5), Inches(0.6), title, size=26, bold=True)
    if subtitle:
        add_text(
            slide, MARGIN, Inches(0.72), Inches(11), Inches(0.4), subtitle, size=13, color=MUTED
        )
    add_text(
        slide,
        SLIDE_W - Inches(3.2),
        Inches(0.2),
        Inches(2.8),
        Inches(0.4),
        f"TRAJECTORY  |  SIH26153  |  {slide_no}/6",
        size=10,
        color=MUTED,
        align=PP_ALIGN.RIGHT,
    )


def footer(slide, note: str) -> None:
    add_text(
        slide,
        MARGIN,
        SLIDE_H - Inches(0.4),
        SLIDE_W - 2 * MARGIN,
        Inches(0.3),
        note,
        size=9,
        color=MUTED,
    )


def card(slide, x, y, w, h, title: str, lines: list, fill=PANEL, title_color=ACCENT, size=11):
    add_rect(slide, x, y, w, h, fill=fill)
    add_text(
        slide,
        x + Inches(0.1),
        y + Inches(0.08),
        w - Inches(0.2),
        Inches(0.4),
        title,
        size=13,
        bold=True,
        color=title_color,
    )
    add_text(
        slide,
        x + Inches(0.1),
        y + Inches(0.48),
        w - Inches(0.2),
        h - Inches(0.55),
        lines,
        size=size,
        bullets=True,
    )


FLOW_GAP = Inches(0.28)


def flow(slide, x, y, w, h, steps: list[str], fill=PANEL_ALT, size=11, gap=FLOW_GAP):
    """Horizontal chevron-style flow of boxes with arrows."""
    n = len(steps)
    box_w = (w - gap * (n - 1)) / n
    boxes = []
    for i, label in enumerate(steps):
        bx = x + i * (box_w + gap)
        shp = add_rect(slide, bx, y, box_w, h, fill=fill, line=ACCENT)
        shp.text_frame.word_wrap = True
        shp.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = shp.text_frame.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        r = p.add_run()
        r.text = label
        r.font.size = Pt(size)
        r.font.bold = True
        r.font.color.rgb = TEXT
        boxes.append(shp)
    for a, b in zip(boxes, boxes[1:], strict=False):
        conn = slide.shapes.add_connector(
            MSO_CONNECTOR.STRAIGHT,
            a.left + a.width,
            a.top + a.height // 2,
            b.left,
            b.top + b.height // 2,
        )
        conn.line.color.rgb = ACCENT
        conn.line.width = Pt(2)
    return boxes


def table(
    slide,
    x,
    y,
    w,
    h,
    rows: list[list[str]],
    col_widths: list[float] | None = None,
    size=10,
    header_fill=PANEL_ALT,
):
    shape = slide.shapes.add_table(len(rows), len(rows[0]), x, y, w, h)
    tbl = shape.table
    if col_widths:
        total = sum(col_widths)
        for i, cw in enumerate(col_widths):
            tbl.columns[i].width = Emu(int(w * cw / total))
    for r, row in enumerate(rows):
        for c, val in enumerate(row):
            cell = tbl.cell(r, c)
            cell.fill.solid()
            cell.fill.fore_color.rgb = header_fill if r == 0 else (PANEL if r % 2 else BG)
            cell.margin_left = cell.margin_right = Inches(0.06)
            cell.margin_top = cell.margin_bottom = Inches(0.03)
            tf = cell.text_frame
            tf.word_wrap = True
            p = tf.paragraphs[0]
            run = p.add_run()
            run.text = val
            run.font.size = Pt(size)
            run.font.bold = r == 0
            run.font.color.rgb = ACCENT if r == 0 else (PLACEHOLDER if "[ADD" in val else TEXT)
    return tbl


def bar_chart(slide, x, y, w, h, labels: list[str], heights: list[float]):
    """Simple placeholder bar chart drawn with shapes (values are illustrative)."""
    add_rect(slide, x, y, w, h, fill=PANEL)
    base_y = y + h - Inches(0.55)
    usable_h = h - Inches(1.0)
    n = len(labels)
    slot = w / n
    bar_w = slot * 0.55
    mx = max(heights)
    for i, (lab, val) in enumerate(zip(labels, heights, strict=True)):
        bh = int(usable_h * val / mx)
        bx = x + int(slot * i + (slot - bar_w) / 2)
        add_rect(slide, bx, base_y - bh, int(bar_w), bh, fill=ACCENT, radius=False)
        add_text(
            slide,
            x + int(slot * i),
            base_y + Inches(0.02),
            int(slot),
            Inches(0.3),
            lab,
            size=9,
            color=MUTED,
            align=PP_ALIGN.CENTER,
        )
    add_text(
        slide,
        x,
        y + Inches(0.05),
        w,
        Inches(0.35),
        "Market growth (illustrative shape)",
        size=10,
        bold=True,
        color=ACCENT,
        align=PP_ALIGN.CENTER,
    )


# --------------------------------------------------------------------------- slides
def slide_1(prs: Presentation) -> None:
    s = prs.slides.add_slide(prs.slide_layouts[6])
    add_bg(s)
    add_rect(s, 0, 0, SLIDE_W, Inches(0.08), fill=ACCENT, radius=False)

    add_text(
        s,
        MARGIN,
        Inches(0.5),
        Inches(8),
        Inches(0.4),
        "SMART INDIA HACKATHON 2026",
        size=14,
        bold=True,
        color=ACCENT,
    )
    add_text(s, MARGIN, Inches(1.1), Inches(8), Inches(1.2), "TRAJECTORY", size=60, bold=True)
    add_text(
        s,
        MARGIN,
        Inches(2.3),
        Inches(7.8),
        Inches(0.9),
        "AI-Based Network Attack Forecasting from Network Traffic Data",
        size=22,
        color=TEXT,
    )
    add_text(
        s,
        MARGIN,
        Inches(3.2),
        Inches(7.6),
        Inches(0.9),
        "An offline, explainable temporal cyber-defence system that forecasts likely attack "
        "progression before compromise is complete.",
        size=14,
        color=MUTED,
    )
    flow(
        s,
        MARGIN,
        Inches(4.4),
        Inches(7.6),
        Inches(0.8),
        ["Network Telemetry", "Current State", "Future Forecast", "Earlier Response"],
        size=11,
    )

    # Registration panel
    px, py, pw, ph = Inches(8.7), Inches(1.0), Inches(4.2), Inches(5.1)
    add_rect(s, px, py, pw, ph, fill=PANEL)
    rows = [
        ["Problem Statement ID", "SIH26153"],
        [
            "Problem Statement Title",
            "AI based Network Attack Forecasting from Network Traffic Data",
        ],
        ["Organization", "National Technical Research Organisation (NTRO)"],
        ["Theme", "Blockchain & Cybersecurity"],
        ["PS Category", "Software"],
        ["Team ID", "[ADD OFFICIAL TEAM ID]"],
        ["Team Name", "[ADD OFFICIAL TEAM NAME]"],
        ["Institute", "[ADD OFFICIAL INSTITUTE NAME]"],
    ]
    yy = py + Inches(0.12)
    for k, v in rows:
        two_lines = len(v) > 42
        val_h = Inches(0.5) if two_lines else Inches(0.3)
        add_text(
            s,
            px + Inches(0.15),
            yy,
            pw - Inches(0.3),
            Inches(0.22),
            k.upper(),
            size=9,
            bold=True,
            color=ACCENT,
        )
        add_text(s, px + Inches(0.15), yy + Inches(0.2), pw - Inches(0.3), val_h, v, size=10.5)
        yy += Inches(0.2) + val_h + Inches(0.04)

    footer(
        s,
        "Forecasts are probabilities with evidence; Trajectory supports analyst decisions and does not block traffic.",
    )


def slide_2(prs: Presentation) -> None:
    s = prs.slides.add_slide(prs.slide_layouts[6])
    add_bg(s)
    header(
        s,
        "Solution Overview & Prototype",
        "From static alerts to predictive attack intelligence",
        2,
    )

    add_text(
        s,
        MARGIN,
        Inches(1.15),
        Inches(7.9),
        Inches(0.9),
        "Trajectory ingests flow CSV and PCAP-derived packet data, converts them into ordered network "
        "states, and forecasts likely attack progression over K future windows: risk, predicted stage, "
        "affected assets, confidence and supporting evidence in an offline analyst dashboard (Web/desktop).",
        size=11.5,
        color=TEXT,
    )

    cw = Inches(2.55)
    y = Inches(2.1)
    h = Inches(2.35)
    card(
        s,
        MARGIN,
        y,
        cw,
        h,
        "SOC Analyst",
        [
            "Load CSV flows / PCAP captures",
            "Risk timeline over time windows",
            "Next likely stage + affected assets",
            "Evidence behind every forecast",
            "Predicted vs actual replay",
        ],
        size=10,
    )
    card(
        s,
        MARGIN + cw + Inches(0.12),
        y,
        cw,
        h,
        "Incident Responder",
        [
            "Prioritize hosts/segments at risk",
            "Confidence + insufficient-evidence flags",
            "Decision support, not auto-blocking",
            "Export reproducible forecast record",
        ],
        size=10,
    )
    card(
        s,
        MARGIN + 2 * (cw + Inches(0.12)),
        y,
        cw,
        h,
        "Security Lead / Evaluator",
        [
            "Temporal model vs logistic baseline",
            "Precision, recall, F1, FPR, calibration",
            "Forecast lead time",
            "Deterministic, seed-fixed replay",
            "Fully local; no cloud AI",
        ],
        size=10,
    )

    # Status + differentiators
    card(
        s,
        MARGIN,
        Inches(4.6),
        Inches(3.9),
        Inches(2.3),
        "Project Status",
        [
            "Phase: ingestion + temporal-data foundation done",
            "CSV & PCAP ingestion, flow + packet features",
            "Timestamped overlapping state windows",
            "Transition targets, leakage-safe splits",
            "15 tests passing; baseline model is next",
        ],
        title_color=WARN,
        size=10,
    )
    card(
        s,
        MARGIN + Inches(4.02),
        Inches(4.6),
        Inches(3.9),
        Inches(2.3),
        "Why We Stand Out",
        [
            "Predictive, not retrospective",
            "K-step future-state simulation",
            "Temporal context instead of per-flow labels",
            "Evidence + assets with every forecast",
            "Offline-first; honest baseline comparison",
        ],
        size=10,
    )

    # Prototype visuals (right column)
    px = Inches(8.6)
    pw = Inches(4.3)
    add_text(
        s, px, Inches(1.1), pw, Inches(0.35), "PROTOTYPE VISUALS", size=11, bold=True, color=ACCENT
    )
    panels = [
        (
            "1. Data Workspace",
            "CSV/PCAP input  |  event count, time range  |  feature-coverage indicators",
        ),
        (
            "2. Forecast Dashboard",
            "Risk over K windows  |  Current / Forecast / Actual replay  |  stage + confidence",
        ),
        (
            "3. Evidence View",
            "Driving features  |  Server-03, failed-auth burst, destination diversity  |  source events",
        ),
    ]
    yy = Inches(1.5)
    for t, d in panels:
        add_rect(s, px, yy, pw, Inches(1.05), fill=PANEL_ALT, line=ACCENT)
        add_text(s, px + Inches(0.1), yy + Inches(0.05), pw, Inches(0.3), t, size=11, bold=True)
        add_text(
            s,
            px + Inches(0.1),
            yy + Inches(0.38),
            pw - Inches(0.2),
            Inches(0.65),
            d,
            size=9.5,
            color=MUTED,
        )
        yy += Inches(1.15)

    add_rect(s, px, Inches(5.0), pw, Inches(1.9), fill=PANEL)
    add_text(
        s,
        px + Inches(0.1),
        Inches(5.05),
        pw,
        Inches(0.3),
        "ILLUSTRATIVE OUTPUT",
        size=9,
        bold=True,
        color=WARN,
    )
    add_text(
        s,
        px + Inches(0.1),
        Inches(5.35),
        pw - Inches(0.2),
        Inches(1.55),
        [
            "Current state: Suspicious reconnaissance",
            "Predicted stage: Lateral movement  (+3 windows)",
            "Likely asset: Server-03      Confidence: 0.72",
            "Evidence: failed-auth burst, new internal connections, rising destination diversity",
        ],
        size=9.5,
        font="Consolas",
    )

    footer(
        s,
        "Replace mockup panels with screenshots and the illustrative output with model output before submission.",
    )


def slide_3(prs: Presentation) -> None:
    s = prs.slides.add_slide(prs.slide_layouts[6])
    add_bg(s)
    header(
        s,
        "Backend Architecture & Technical Approach",
        "Local, reproducible, evidence-first forecasting pipeline",
        3,
    )

    # Layered architecture (left)
    lx, lw = MARGIN, Inches(6.2)
    layers = [
        ("INPUT", "Flow CSV  |  PCAP captures  ->  normalization + packet feature extraction"),
        (
            "DATA",
            "Unified events -> timestamped windows -> state store  |  labels, transition targets, split manifests",
        ),
        (
            "MODEL",
            "Logistic Regression baseline (current window)  |  GRU/LSTM temporal model + K-step rollout",
        ),
        (
            "OUTPUT",
            "Risk timeline  |  attack stage  |  assets  |  evidence  |  confidence + warnings",
        ),
        ("UI", "Offline analyst dashboard (Streamlit/Flask + Plotly)"),
    ]
    yy = Inches(1.2)
    for name, desc in layers:
        add_rect(s, lx, yy, lw, Inches(0.72), fill=PANEL_ALT, line=ACCENT)
        add_text(
            s,
            lx + Inches(0.1),
            yy + Inches(0.05),
            Inches(1.1),
            Inches(0.6),
            name,
            size=11,
            bold=True,
            color=ACCENT,
            anchor=MSO_ANCHOR.MIDDLE,
        )
        add_text(
            s,
            lx + Inches(1.2),
            yy + Inches(0.05),
            lw - Inches(1.3),
            Inches(0.62),
            desc,
            size=10,
            anchor=MSO_ANCHOR.MIDDLE,
        )
        yy += Inches(0.8)

    # Security + fallback under architecture
    card(
        s,
        lx,
        Inches(5.3),
        Inches(3.0),
        Inches(1.75),
        "Security & Privacy",
        [
            "Local-first; no external AI service",
            "Anonymized identifiers in demos",
            "No secrets/captures committed",
            "Provenance, versions, checksums",
            "Human-in-the-loop; no auto-blocking",
        ],
        size=9.5,
    )
    card(
        s,
        lx + Inches(3.15),
        Inches(5.3),
        Inches(3.05),
        Inches(1.75),
        "Input Fallback Logic",
        [
            "PCAP -> flow + packet features",
            "CSV only -> flow features + packet-coverage warning",
            "Data missing -> validation error, no fabricated forecast",
            "All paths run offline",
        ],
        size=9.5,
    )

    # Right: process flow + AI table
    rx = Inches(6.9)
    rw = SLIDE_W - rx - MARGIN
    add_text(
        s,
        rx,
        Inches(1.1),
        rw,
        Inches(0.3),
        "TECHNICAL APPROACH FLOW",
        size=11,
        bold=True,
        color=ACCENT,
    )
    flow(
        s,
        rx,
        Inches(1.45),
        rw,
        Inches(0.6),
        ["Ingest", "Normalize", "Window", "Prepare"],
        size=10,
        gap=Inches(0.2),
    )
    flow(
        s,
        rx,
        Inches(2.2),
        rw,
        Inches(0.6),
        ["Learn", "Simulate", "Explain", "Display"],
        size=10,
        gap=Inches(0.2),
    )
    add_text(
        s,
        rx,
        Inches(2.85),
        rw,
        Inches(0.5),
        "Security lead configures scenario & evaluation  ->  Analyst loads telemetry & inspects forecast  ->  Responder validates evidence & acts",
        size=9,
        color=MUTED,
    )

    add_text(s, rx, Inches(3.4), rw, Inches(0.3), "AI COMPONENTS", size=11, bold=True, color=ACCENT)
    table(
        s,
        rx,
        Inches(3.75),
        rw,
        Inches(3.2),
        [
            ["Component", "Technique", "Function"],
            ["Static baseline", "Logistic Regression", "Fair reference from the current window"],
            [
                "Temporal forecaster",
                "GRU / LSTM (proposed)",
                "Learn dependencies across ordered states",
            ],
            [
                "Future simulation",
                "Recursive K-step rollout",
                "Likely future states, risk trajectory",
            ],
            ["Stage mapping", "Documented rules / classifier", "MITRE ATT&CK-oriented stage label"],
            [
                "Explanation",
                "Attribution + event retrieval",
                "Driving features and traffic evidence",
            ],
            ["Calibration", "Reliability analysis", "Useful confidence values"],
        ],
        col_widths=[1.2, 1.5, 2.1],
        size=9,
    )

    footer(
        s,
        "No Kafka/cloud gateway/microservices are claimed: the prototype runs on local files and model artifacts. Docker only if packaged before submission.",
    )


def slide_4(prs: Presentation) -> None:
    s = prs.slides.add_slide(prs.slide_layouts[6])
    add_bg(s)
    header(
        s,
        "Feasibility, Viability & Challenges",
        "Feasible with open data, local compute and controlled deployment",
        4,
    )

    gw, gh = Inches(3.05), Inches(2.0)
    gx, gy = MARGIN, Inches(1.2)
    card(
        s,
        gx,
        gy,
        gw,
        gh,
        "Technical",
        [
            "Public flow & PCAP datasets available",
            "Open-source parsers + ML frameworks",
            "GRU/LSTM practical on dev hardware",
            "Scenario-safe splits, baseline defined",
        ],
        size=9.5,
    )
    card(
        s,
        gx + gw + Inches(0.12),
        gy,
        gw,
        gh,
        "Operational",
        [
            "Runs beside IDS / SIEM / EDR",
            "Analyst owns response decisions",
            "Deterministic replay for demos & audit",
            "Local processing for sensitive sites",
        ],
        size=9.5,
    )
    card(
        s,
        gx,
        gy + gh + Inches(0.12),
        gw,
        gh,
        "Economic",
        [
            "Open-source stack, low prototype cost",
            "Software-only MVP, no custom hardware",
            "Augments existing tools",
            "Pilot-first phased adoption",
        ],
        size=9.5,
    )
    card(
        s,
        gx + gw + Inches(0.12),
        gy + gh + Inches(0.12),
        gw,
        gh,
        "Regulatory & Privacy",
        [
            "Synthetic / public / anonymized demo data",
            "Licences & access restrictions recorded",
            "Captures and model artifacts stay local",
            "Human approval; no autonomous enforcement",
        ],
        size=9.5,
    )

    # Market chart (illustrative)
    mx = gx
    my = gy + 2 * gh + Inches(0.3)
    bar_chart(
        s,
        mx,
        my,
        2 * gw + Inches(0.12),
        Inches(1.55),
        ["Base", "Y+1", "Y+2", "Y+3", "Y+4"],
        [1.0, 1.12, 1.25, 1.4, 1.57],
    )
    add_text(
        s,
        mx,
        my + Inches(1.55),
        2 * gw + Inches(0.12),
        Inches(0.3),
        "CAGR: [ADD VERIFIED VALUE]%   Source: [ADD REPORT, PUBLISHER, YEAR, URL]",
        size=9,
    )

    # Challenges table (right)
    rx = Inches(6.9)
    rw = SLIDE_W - rx - MARGIN
    add_text(
        s,
        rx,
        Inches(1.1),
        rw,
        Inches(0.3),
        "CHALLENGES  ->  TECHNICAL RESPONSES",
        size=11,
        bold=True,
        color=ACCENT,
    )
    table(
        s,
        rx,
        Inches(1.45),
        rw,
        Inches(4.6),
        [
            ["Challenge", "Technical response"],
            ["Rare, imbalanced attacks", "Class weighting, per-class metrics, PR analysis"],
            ["Temporal leakage", "Scenario / campaign / time-held-out evaluation"],
            ["Dataset shift", "Secondary-dataset tests, per-site recalibration"],
            ["Missing packet features", "Coverage report + reduced-context warning"],
            ["Recursive forecast drift", "Short K horizon, calibration, uncertainty display"],
            ["Ambiguous stage labels", "Documented mapping; insufficient-evidence state"],
            ["False-positive fatigue", "Baseline comparison, threshold tuning, FPR reporting"],
            ["Black-box predictions", "Attribution, source-event evidence, asset context"],
            ["Sensitive telemetry", "Local processing, anonymization, restricted artifacts"],
            ["Enterprise integration", "File-based MVP first; adapters/APIs later"],
        ],
        col_widths=[1.4, 2.6],
        size=9,
    )
    add_rect(s, rx, Inches(6.15), rw, Inches(0.8), fill=PANEL)
    add_text(
        s,
        rx + Inches(0.1),
        Inches(6.18),
        rw - Inches(0.2),
        Inches(0.75),
        "Viability: feasible as an offline prototype on public datasets and open-source tools. Production use needs "
        "environment-specific validation, integration, calibration, access control and security review.",
        size=9.5,
        color=MUTED,
    )

    footer(
        s,
        "Chart shape is illustrative until a verified market source is inserted; state geography and product scope with the figure.",
    )


def slide_5(prs: Presentation) -> None:
    s = prs.slides.add_slide(prs.slide_layouts[6])
    add_bg(s)
    header(
        s,
        "Impacts, Benefits & Stakeholder Scenario",
        "Earlier, evidence-backed decisions can reduce attack impact",
        5,
    )

    cw, ch = Inches(2.0), Inches(2.25)
    y = Inches(1.2)
    card(
        s,
        MARGIN,
        y,
        cw,
        ch,
        "Economic",
        [
            "Analyst time on likely paths",
            "Less manual correlation",
            "Earlier intervention, lower downtime cost",
            "No stack replacement",
        ],
        size=9,
    )
    card(
        s,
        MARGIN + (cw + Inches(0.1)),
        y,
        cw,
        ch,
        "Social",
        [
            "Resilient public services & CII",
            "Clearer incident context",
            "Humans keep the decision",
            "Accountable AI use",
        ],
        size=9,
    )
    card(
        s,
        MARGIN + 2 * (cw + Inches(0.1)),
        y,
        cw,
        ch,
        "Environmental",
        [
            "Runs on ordinary hardware",
            "Reuses existing telemetry",
            "No mandatory cloud transfer",
            "Software-only, no devices",
        ],
        size=9,
    )
    card(
        s,
        MARGIN + 3 * (cw + Inches(0.1)),
        y,
        cw,
        ch,
        "Operational",
        [
            "Forecast before next stage",
            "Stage + asset + horizon + evidence",
            "Repeatable replay for audit",
            "Layer on existing controls",
        ],
        size=9,
    )

    # Scenario flow
    add_text(
        s,
        MARGIN,
        Inches(3.6),
        Inches(8.3),
        Inches(0.3),
        "SAMPLE SCENARIO: RECONNAISSANCE -> LATERAL MOVEMENT",
        size=11,
        bold=True,
        color=ACCENT,
    )
    flow(
        s,
        MARGIN,
        Inches(3.95),
        Inches(8.3),
        Inches(1.1),
        [
            "Workstation-17 contacts many new destinations",
            "Trajectory correlates recon + failed-auth burst",
            "SOC analyst: early forecast toward Server-03",
            "Responder validates evidence, acts",
            "Security lead audits forecast vs outcome",
        ],
        size=9,
        gap=Inches(0.18),
    )
    add_text(
        s,
        MARGIN,
        Inches(5.1),
        Inches(8.3),
        Inches(0.5),
        "Success criteria: forecast appears before the target stage is observable; evidence names real patterns and "
        "entities; predicted vs actual are visually distinct; replay is reproducible from the same configuration.",
        size=9,
        color=MUTED,
    )

    # SDGs
    sx = Inches(9.0)
    sw = SLIDE_W - sx - MARGIN
    add_text(
        s,
        sx,
        Inches(1.1),
        sw,
        Inches(0.3),
        "SUSTAINABLE DEVELOPMENT GOALS",
        size=11,
        bold=True,
        color=ACCENT,
    )
    for i, (num, name, why) in enumerate(
        [
            (
                "9",
                "Industry, Innovation & Infrastructure",
                "Resilience of digital and critical infrastructure via predictive security analytics",
            ),
            (
                "16",
                "Peace, Justice & Strong Institutions",
                "Safer digital public systems; accountable, evidence-backed security operations",
            ),
        ]
    ):
        yy = Inches(1.45) + i * Inches(1.1)
        badge = add_rect(s, sx, yy, Inches(0.9), Inches(0.9), fill=ACCENT)
        badge.text_frame.paragraphs[0].alignment = PP_ALIGN.CENTER
        badge.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
        r = badge.text_frame.paragraphs[0].add_run()
        r.text = f"SDG {num}"
        r.font.bold = True
        r.font.size = Pt(12)
        r.font.color.rgb = BG
        add_text(s, sx + Inches(1.0), yy, sw - Inches(1.0), Inches(0.3), name, size=10.5, bold=True)
        add_text(
            s,
            sx + Inches(1.0),
            yy + Inches(0.3),
            sw - Inches(1.0),
            Inches(0.6),
            why,
            size=9,
            color=MUTED,
        )
    add_text(
        s,
        sx,
        Inches(3.65),
        sw,
        Inches(0.3),
        "Use official icons only where template/UN guidance permits.",
        size=8,
        color=MUTED,
    )

    # Quantitative impact
    qx, qy, qw, qh = MARGIN, Inches(5.65), SLIDE_W - 2 * MARGIN, Inches(1.35)
    add_rect(s, qx, qy, qw, qh, fill=PANEL)
    add_text(
        s,
        qx + Inches(0.1),
        qy + Inches(0.05),
        Inches(4),
        Inches(0.3),
        "QUANTITATIVE TARGET IMPACT",
        size=11,
        bold=True,
        color=ACCENT,
    )
    add_text(
        s,
        qx + Inches(0.1),
        qy + Inches(0.38),
        Inches(6.2),
        Inches(0.95),
        [
            "Forecast lead time = t(target stage observable) - t(warning threshold crossed)",
            "Time saved / incident = mean investigation time (current) - mean time with evidence panel",
            "Analyst-hours recovered / year = valid incidents per year x time saved per incident",
        ],
        size=9,
        font="Consolas",
    )
    add_text(
        s,
        qx + Inches(6.5),
        qy + Inches(0.38),
        qw - Inches(6.6),
        Inches(0.95),
        [
            "[ADD X] min median forecast lead time",
            "[ADD Y]% investigation-time reduction (controlled user test)",
            "[ADD Z] analyst-hours recovered / year  |  basis: [ADD DATASET / SCENARIOS / METHOD]",
        ],
        size=9.5,
    )

    footer(
        s,
        "Do not convert model accuracy into financial savings without an explicit operational assumption.",
    )


def slide_6(prs: Presentation) -> None:
    s = prs.slides.add_slide(prs.slide_layouts[6])
    add_bg(s)
    header(
        s,
        "Research, Market Sizing & Business Model",
        "Research-backed; scalable from offline pilot to enterprise integration",
        6,
    )

    # References (left)
    rw = Inches(4.5)
    card(
        s,
        MARGIN,
        Inches(1.2),
        rw,
        Inches(1.55),
        "Official & Domain",
        [
            "SIH 2026 PS: sih.gov.in/sih2026PS",
            "MITRE ATT&CK: attack.mitre.org  |  CAPEC: capec.mitre.org",
            "NVD: nvd.nist.gov  |  NCIIPC: nciipc.gov.in",
        ],
        size=9,
    )
    card(
        s,
        MARGIN,
        Inches(2.85),
        rw,
        Inches(1.45),
        "Datasets",
        [
            "CIC-IDS2017/2018, UNSW-NB15, CTU-13, CICIoT2023, LANL auth",
            "URLs: [ADD VERIFIED DATASET URLS]",
            "Only with documented licence, access, checksums",
        ],
        size=9,
    )
    card(
        s,
        MARGIN,
        Inches(4.4),
        rw,
        Inches(1.3),
        "AI / ML Research",
        [
            "GRU/LSTM sequence forecasting; recursive multi-step + uncertainty",
            "Calibration; feature attribution / XAI; scenario-held-out IDS evaluation",
            "Papers: [ADD 2-4 AUTHOR, TITLE, VENUE, YEAR, DOI]",
        ],
        size=9,
    )
    card(
        s,
        MARGIN,
        Inches(5.8),
        rw,
        Inches(1.1),
        "Software",
        [
            "PyTorch  |  scikit-learn  |  Scapy  |  NetworkX  |  Plotly  |  Streamlit",
        ],
        size=9,
    )

    # Market sizing (middle)
    mx = MARGIN + rw + Inches(0.15)
    mw = Inches(3.9)
    add_text(
        s,
        mx,
        Inches(1.1),
        mw,
        Inches(0.3),
        "MARKET SIZING (BOTTOM-UP)",
        size=11,
        bold=True,
        color=ACCENT,
    )
    table(
        s,
        mx,
        Inches(1.45),
        mw,
        Inches(2.1),
        [
            ["Tier", "Definition", "Estimate"],
            [
                "TAM",
                "Orgs with network-security teams in target geography x annual value",
                "[ADD N1 x A = TAM]",
            ],
            [
                "SAM",
                "Reachable with offline product + supported integrations",
                "[ADD N2 x A = SAM]",
            ],
            ["SOM", "Realistic customers in first 3 years", "[ADD N3 x A = SOM]"],
        ],
        col_widths=[0.6, 2.2, 1.3],
        size=8.5,
    )
    add_text(
        s,
        mx,
        Inches(3.6),
        mw,
        Inches(0.7),
        "State: geography & sectors, org-count source, scope of annual value, adoption rationale, tax/support inclusion.",
        size=8.5,
        color=MUTED,
    )

    add_text(
        s, mx, Inches(4.3), mw, Inches(0.3), "REVENUE & HARDWARE", size=11, bold=True, color=ACCENT
    )
    table(
        s,
        mx,
        Inches(4.65),
        mw,
        Inches(2.25),
        [
            ["Component", "Unit", "Pricing basis"],
            ["Platform licence", "Per org / env / year", "[ADD VALIDATED PRICE]"],
            ["Deployment & integration", "One-time per env", "Data sources + SIEM effort"],
            ["Model calibration", "Per env / telemetry change", "Data prep + threshold tuning"],
            ["Support & updates", "Annual", "% of licence or tier"],
            ["Hardware", "Not required for MVP", "Customer workstation/server"],
        ],
        col_widths=[1.3, 1.2, 1.4],
        size=8.5,
    )

    # First-year revenue + proof (right)
    px = mx + mw + Inches(0.15)
    pw = SLIDE_W - px - MARGIN
    add_rect(s, px, Inches(1.2), pw, Inches(2.35), fill=PANEL)
    add_text(
        s,
        px + Inches(0.1),
        Inches(1.25),
        pw,
        Inches(0.3),
        "FIRST-YEAR REVENUE (ESTIMATE)",
        size=11,
        bold=True,
        color=ACCENT,
    )
    add_text(
        s,
        px + Inches(0.1),
        Inches(1.6),
        pw - Inches(0.2),
        Inches(1.9),
        [
            "Licences   [ADD L] x Rs[licence]   = Rs[R1]",
            "Deploys    [ADD D] x Rs[deploy]    = Rs[R2]",
            "Support    [ADD S] x Rs[support]   = Rs[R3]",
            "Training   [ADD T] x Rs[training]  = Rs[R4]",
            "--------------------------------------",
            "Total (business estimate) = Rs[ADD TOTAL]",
        ],
        size=9,
        font="Consolas",
    )

    add_rect(s, px, Inches(3.7), pw, Inches(3.2), fill=PANEL)
    add_text(
        s,
        px + Inches(0.1),
        Inches(3.75),
        pw,
        Inches(0.3),
        "PROOF DOCUMENTS",
        size=11,
        bold=True,
        color=ACCENT,
    )
    add_text(
        s,
        px + Inches(0.1),
        Inches(4.1),
        pw - Inches(0.2),
        Inches(2.75),
        [
            "Source repo: [ADD GITHUB URL]",
            "Architecture: ARCHITECTURE.md",
            "Status: IMPLEMENTATION_STATUS.md",
            "Evaluation report: [ADD LINK AFTER BENCHMARKS]",
            "Demo video: [ADD FINAL VIDEO LINK]",
            "Consolidated research: [ADD FOLDER LINK]",
            "Reproducibility: README.md + uv.lock",
        ],
        size=9.5,
        bullets=True,
    )

    footer(
        s,
        "Trajectory adds a predictive layer to existing cyber defence: what may happen next, where, and why the analyst should look.",
    )


def slide_7(prs: Presentation) -> None:
    """Live demo slide: narrated storyline with measured beats and backup frames."""
    s = prs.slides.add_slide(prs.slide_layouts[6])
    add_bg(s)
    header(
        s,
        "Live Demo — Watch the AI Detect an Attack",
        "Real-time detection on a localhost attack simulation; deterministic and rehearsed",
        7,
    )

    # Left: the narrated storyline with measured timings.
    card(
        s,
        MARGIN,
        Inches(1.2),
        Inches(5.9),
        Inches(4.6),
        "Stage Storyline (measured in rehearsal)",
        [
            "0:00 — Train the models live (~4 seconds, deterministic seed)",
            "0:10 — Press Start: benign chatter begins",
            "0:30 — Quiet window: P(infiltration) = 0.12, no false alarms",
            "0:33 — ALERT: scan burst detected at P = 0.97",
            "         Stage: Initial Access — MITRE ATT&CK TA0001",
            "0:48 — Failed logins: P = 1.00, evidence panel grows",
            "1:03 — ESCALATION: Lateral Movement — MITRE TA0008",
            "Same trained artifacts as the offline benchmark",
            "Sources: demo attack, CIC-IDS2017 replay, live capture",
        ],
        size=11,
    )

    # Right: the three backup-demo frames (t0, alert, escalation).
    frames_dir = ROOT / "deliverables" / "backup_demo"
    frame_files = (
        ("frame_0_t0s.png", "t=0 — benign, P=0.12"),
        ("frame_1_t33s.png", "t=33s — ALERT, P=0.97"),
        ("frame_3_t63s.png", "t=63s — Lateral Movement"),
    )
    for index, (filename, caption) in enumerate(frame_files):
        path = frames_dir / filename
        if not path.is_file():
            continue
        x = MARGIN + Inches(6.1)
        y = Inches(1.25 + index * 1.55)
        s.shapes.add_picture(str(path), x, y, width=Inches(2.6))
        add_text(
            s,
            x + Inches(2.7),
            y + Inches(0.55),
            Inches(3.6),
            Inches(0.4),
            caption,
            size=10,
            color=ACCENT,
        )

    footer(
        s,
        "Backup if live infra fails: deliverables/backup_demo/backup_demo.gif (animated) — same numbers as the live run.",
    )


# --------------------------------------------------------------------------- main
def build(pdf: bool = False) -> Path:
    prs = Presentation()
    prs.slide_width = SLIDE_W
    prs.slide_height = SLIDE_H
    for fn in (slide_1, slide_2, slide_3, slide_4, slide_5, slide_6, slide_7):
        fn(prs)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    prs.save(OUT_FILE)
    print(f"Wrote {OUT_FILE.relative_to(ROOT)} ({len(prs.slides)} slides)")

    if pdf:
        soffice = shutil.which("soffice") or shutil.which("libreoffice")
        if not soffice:
            raise SystemExit("LibreOffice not found; cannot export PDF.")
        subprocess.run(
            [soffice, "--headless", "--convert-to", "pdf", "--outdir", str(OUT_DIR), str(OUT_FILE)],
            check=True,
            capture_output=True,
        )
        print(f"Wrote {OUT_FILE.with_suffix('.pdf').relative_to(ROOT)}")
    return OUT_FILE


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--pdf", action="store_true", help="also export PDF via LibreOffice")
    build(pdf=ap.parse_args().pdf)
