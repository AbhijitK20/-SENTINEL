"""Capture demo frames from the deployed SENTINEL console into docs/shots/.

Run:  uv run --with playwright python scripts/capture_demo_frames.py core
      uv run --with playwright python scripts/capture_demo_frames.py live
      uv run --with playwright python scripts/capture_demo_frames.py deck

Two capture modes because one long-lived browser was OOM-killed waiting out the
live replay. `deck` builds the captioned contact sheet from whatever PNGs exist.

Streamlit notes, both learned the hard way and both worth not rediscovering:
  * The slider thumb is a visually hidden <input type="range">. fill() moves the
    thumb and triggers NO server rerun; focus() + Arrow keys does.
  * Forecast and world-model metrics live in the same DOM (every tab renders),
    so [data-testid="stMetricValue"] is not a per-tab read. Assert on the
    caption line instead.
"""

from __future__ import annotations

import base64
import html
import sys
import time
from pathlib import Path

URL = "https://sentinel-console-nine.vercel.app"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "shots"
OUT.mkdir(parents=True, exist_ok=True)

TABS = [
    "Overview",
    "Forecast",
    "World model",
    "Replay",
    "States",
    "Comparison",
    "Live",
    "Metrics",
    "Demo",
    "Attack story",
]

# Captions say what the frame is evidence *of*, not what screen it is.
# Ordered as an argument, and the fired/unknown stage pair is the hinge.
FRAMES: list[tuple[str, str, str]] = [
    (
        "01-header-provenance",
        "header-provenance",
        "It states what it was given, before you ask. The header names the corpus, "
        "the window count, the schema width and the seed &mdash; and opens with "
        "SYNTHETIC, generated not captured. Everything downstream is a real "
        "measurement of a synthetic dataset, and the console never lets you forget "
        "which.",
    ),
    (
        "02-split-composition",
        "split-composition",
        "The split is the argument. Whole scenarios are assigned to train, "
        "validation or test <em>before a single window is built</em>, so no window "
        "from a held-out scenario can reach the model under test. Train on a split "
        "and measure on the same attack, and you have measured your own memory.",
    ),
    (
        "03-forecast-window-40",
        "forecast-window-40",
        "A probability with its provenance attached. The cut is 40 of 72 windows; "
        "observed history stops there and everything to the right of the spine is "
        "simulated. Observed and forecast never share a colour, and a legend says "
        "which one you are looking at.",
    ),
    (
        "04-stage-mapping-fired",
        "stage-mapping-fired",
        "It can discriminate. Three documented rules fire, the strongest at 0.90, "
        "and the panel names the winning one &mdash; then adds the caveat that "
        "evidence is an observed association, <em>not proof of attacker "
        "technique</em>. The confidence figure and the disclaimer ship together.",
    ),
    (
        "05-driving-features",
        "driving-features",
        "The why, as arithmetic. Each feature's standardised distance from normal "
        "and the direction it pushed &mdash; and the panel names its own method: "
        "exact local attribution for a linear model, <em>not SHAP</em>. Not a story "
        "written after the fact.",
    ),
    (
        "07-stage-mapping-unknown",
        "stage-mapping-unknown",
        "And it can decline. Same screen, final window, no rule fires. The panel "
        "refuses to name a stage and says so in plain words: &ldquo;This is not a "
        "low-risk reading.&rdquo; Every tool on the market will answer here. The "
        "three-way split &mdash; high, low, unknown &mdash; is the product.",
    ),
    (
        "06-caveats",
        "caveats",
        "The model names its own blind spot. This release bundle carries no "
        "temporal artifacts, so the panel says the probability timeline is a "
        "baseline-only decay estimate. The forecast refuses to be read as better "
        "than the thing it actually is.",
    ),
    (
        "09-ledger-verified",
        "ledger-verified",
        "Alerts are chained, and the chain is checked on read. Each record commits "
        "to its predecessor by hash; no raw traffic is written. A local hash chain, "
        "not a blockchain &mdash; the panel says so, because that is the kind of "
        "word that gets stretched.",
    ),
    (
        "L-02-live-risk-grid",
        "live-risk-grid",
        "Nine rules, one grid, every attack type at once &mdash; DDoS 0.61 and recon "
        "0.66, each with its MITRE technique underneath. C2 reads 0.00 and says "
        "why: DNS/TLS metadata is absent, so the rule is disabled rather than "
        "guessed at.",
    ),
    (
        "L-03-live-correlated-incidents",
        "live-correlated-incidents",
        "Nineteen alerts collapse into incidents. An analyst is not handed a stream "
        "of findings &mdash; they get one intrusion, its likely progression, and the "
        "assets in scope.",
    ),
    (
        "L-04-force-attack",
        "force-attack",
        "Nine buttons, one per phase, each labelled with the technique it targets "
        "(T1498, T1046, T1110, T1021, T1048, T1071, T1059). They fire real HTTP "
        "requests at a deliberately vulnerable target bound to loopback inside the "
        "console's own container.",
    ),
    (
        "10-world-model",
        "world-model",
        "It imagines forward with no observations &mdash; and reports the unflattering "
        "number. Open-loop skill is near zero and turns negative at longer "
        "horizons: the model does not reliably beat repeating the last window. "
        "Tuned away? No. Shown.",
    ),
    (
        "11-split-audit",
        "split-audit",
        "The mechanical check that the holdout is a holdout. Disjoint scenarios: "
        "yes. Disjoint state keys: yes. The claim most published results never "
        "bother to verify, rendered as a panel instead of a promise.",
    ),
    (
        "12-comparison-models",
        "comparison-models",
        "Same windows, same schema, same held-out scenarios &mdash; the only "
        "variable is whether the model sees the sequence or just the current "
        "window. It does: F1 0.892 &rarr; 0.941, false-positive rate 0.060 "
        "&rarr; 0.000, PR-AUC 0.978 &rarr; 0.995. Below it every horizon "
        "separately, because these are five independent models, not one model "
        "five ways.",
    ),
]

_c: list = []


def note(m: str) -> None:
    print(m, flush=True)
    _c.append(m)


def snap(page, name: str, n: list) -> None:
    fn = OUT / f"{len(n) + 1:02d}-{name}.png"
    try:
        page.screenshot(path=str(fn))
        n.append(fn)
        note(f"  shot {fn.name}")
    except Exception as e:  # noqa: BLE001
        note(f"  SHOT FAILED {name}: {e}")


def tab(page, name: str) -> None:
    page.locator('[data-testid="stTab"]').nth(TABS.index(name)).click(timeout=25000)
    time.sleep(7)


def to(page, text: str, wait: float = 4.5) -> None:
    try:
        page.locator(f"text={text}").first.scroll_into_view_if_needed(timeout=12000)
    except Exception as e:  # noqa: BLE001
        note(f"  scroll {text!r}: {e}")
    time.sleep(wait)


def walk_slider(page, label: str, target: float) -> float:
    """Streamlit only reruns on real input events. fill() moves the thumb and
    does nothing else; focus() plus arrow keys does."""
    rng = page.locator(f'input[type="range"][aria-label="{label}"]').first
    rng.scroll_into_view_if_needed()
    time.sleep(1)
    val = lambda: float(rng.get_attribute("value"))  # noqa: E731
    cur = val()
    rng.focus()
    key = "ArrowLeft" if target < cur else "ArrowRight"
    if abs(target - cur) <= 60:
        for _ in range(int(abs(target - cur))):
            rng.press(key)
    else:
        rng.press("End")
    for _ in range(30):
        time.sleep(4)
        if abs(val() - target) < 1:
            break
    note(f"  {label}: {cur} -> {val()}")
    return val()


def caption_line(page) -> str:
    try:
        for line in page.inner_text("body").splitlines():
            if "windows visible to the model" in line:
                return line.strip()
    except Exception:  # noqa: BLE001
        pass
    return "<none>"


def capture(mode: str) -> None:
    # Imported here, not at module scope: `deck` only reads PNGs off disk and
    # must not require playwright to be installed.
    from playwright.sync_api import sync_playwright

    shots: list = []
    shell = (
        Path.home()
        / ".cache/ms-playwright/chromium_headless_shell-1243"
        / "chrome-headless-shell-linux64/chrome-headless-shell"
    )
    with sync_playwright() as p:
        b = p.chromium.launch(
            executable_path=str(shell),
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        page = b.new_page(viewport={"width": 1500, "height": 1000}, device_scale_factor=2)
        page.goto(URL, wait_until="commit", timeout=120000)
        page.wait_for_selector("text=NETWORK ATTACK FORECASTING", timeout=300000)
        note("painted")
        time.sleep(10)

        if mode == "core":
            snap(page, "header-provenance", shots)
            tab(page, "Overview")
            to(page, "Split composition")
            snap(page, "split-composition", shots)

            tab(page, "Forecast")
            for w in (40,):
                walk_slider(page, "Forecast from window", w)
                note(f"    {caption_line(page)}")
                to(page, "PEAK PROBABILITY")
                snap(page, f"forecast-window-{w}", shots)
            to(page, "Stage mapping")
            snap(page, "stage-mapping-fired", shots)
            to(page, "Driving features")
            snap(page, "driving-features", shots)
            to(page, "Caveats carried by this forecast")
            snap(page, "caveats", shots)

            # The other half of the argument: at the final window no rule fires,
            # and the panel refuses to name a stage. Captured with the fired
            # state above because the pair is the actual thesis — it can fire,
            # and it can decline to.
            walk_slider(page, "Forecast from window", 72)
            note(f"    {caption_line(page)}")
            to(page, "Stage mapping")
            snap(page, "stage-mapping-unknown", shots)
            walk_slider(page, "Forecast from window", 40)
            note(f"    {caption_line(page)}")

            to(page, "Trust ledger")
            snap(page, "ledger-empty", shots)
            for label in ("Record alert", "Verify"):
                try:
                    page.get_by_role("button", name=label).first.click(timeout=15000)
                    time.sleep(6)
                    note(f"  pressed {label}")
                except Exception as e:  # noqa: BLE001
                    note(f"  {label}: {e}")
            snap(page, "ledger-verified", shots)

            tab(page, "World model")
            to(page, "World Model — imagined futures")
            snap(page, "world-model", shots)

            tab(page, "Metrics")
            to(page, "Split audit")
            snap(page, "split-audit", shots)

        else:
            tab(page, "Live")
            walk_slider(page, "Replay speed (simulated seconds / real second)", 600)
            to(page, "Replay speed")
            snap(page, "live-controls", shots)
            page.get_by_role("button", name="Start").first.click(timeout=25000)
            note("  pressed Start")
            for i in range(8):
                time.sleep(18)
                try:
                    txt = page.inner_text("body", timeout=15000)
                except Exception:  # noqa: BLE001
                    break
                note(f"  wait {i}: incidents={'Correlated incidents' in txt}")
                if "Correlated incidents" in txt:
                    break
            to(page, "Attack-type risk grid")
            snap(page, "live-risk-grid", shots)
            to(page, "Correlated incidents")
            snap(page, "live-correlated-incidents", shots)
            to(page, "Force Attack")
            snap(page, "force-attack", shots)

        b.close()
    note(f"DONE[{mode}] — {len(shots)} frames")


DECK = """<!doctype html>
<meta charset="utf-8">
<title>SENTINEL — demo frames</title>
<style>
  :root {{
    --bg:#0b0e11; --panel:#11151a; --ink:#e6edf3; --dim:#8b949e;
    --line:#1d232b; --accent:#58a6ff;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font:15px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace; }}
  header {{ padding:56px 40px 32px; border-bottom:1px solid var(--line); }}
  h1 {{ margin:0 0 8px; font-size:26px; letter-spacing:.14em; font-weight:600; }}
  header p {{ margin:0; color:var(--dim); max-width:70ch; }}
  section {{ padding:40px; border-bottom:1px solid var(--line); }}
  figure {{ margin:0; }}
  img {{ width:100%; display:block; border:1px solid var(--line); border-radius:6px; }}
  figcaption {{ margin-top:14px; max-width:88ch; color:var(--dim); }}
  figcaption b {{ color:var(--accent); font-weight:600; }}
  figcaption em {{ color:var(--ink); font-style:normal;
    border-bottom:1px solid var(--accent); }}
  .missing {{ color:#f85149; }}
</style>
<header>
  <h1>SENTINEL</h1>
  <p>Frames captured from the deployed console. Every caption describes what the
  frame is <em>evidence of</em>, not which screen it came from.</p>
</header>
{body}
"""


def build_deck() -> None:
    have = {p.name for p in OUT.glob("*.png")}
    chunks = []
    missing = []
    for fname, slug, cap in FRAMES:
        if f"{fname}.png" not in have:
            missing.append(fname)
            continue
        b64 = base64.b64encode((OUT / f"{fname}.png").read_bytes()).decode()
        chunks.append(
            f'<section><figure><img src="data:image/png;base64,{b64}" alt="{slug}">'
            f"<figcaption><b>{html.escape(slug)}</b> — {cap}</figcaption>"
            "</figure></section>"
        )
    out = OUT / "index.html"
    out.write_text(DECK.format(body="\n".join(chunks)), encoding="utf-8")
    note(f"wrote {out} — {len(chunks)} frames")
    if missing:
        note("MISSING (no PNG on disk): " + ", ".join(missing))
        note("run `core` and `live` to capture them")


if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else "core"
    if m == "deck":
        build_deck()
    else:
        capture(m)
