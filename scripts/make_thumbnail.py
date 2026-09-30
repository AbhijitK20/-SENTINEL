"""Render the YouTube thumbnail. Run: uv run --with playwright python scripts/make_thumbnail.py

Renders 1280x720 with chrome-headless-shell. The screenshot strip is a real crop
of docs/shots/07-stage-mapping-unknown.png, not a mock-up — the words on the
thumbnail are the words the console prints.
"""

from __future__ import annotations

import base64
import io
from pathlib import Path

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
SHOTS = ROOT / "docs" / "shots"
SOURCE = SHOTS / "07-stage-mapping-unknown.png"
OUT = SHOTS / "thumbnail.png"
SHELL = (
    Path.home()
    / ".cache/ms-playwright/chromium_headless_shell-1243"
    / "chrome-headless-shell-linux64/chrome-headless-shell"
)

# The callout box, in SOURCE's 3000x2000 space.
CROP = (660, 1080, 2920, 1290)

HTML = """<!doctype html><meta charset="utf-8">
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  html,body {{ width:1280px; height:720px; overflow:hidden; }}
  body {{
    background:#07090c; color:#e6edf3;
    font-family:"DejaVu Sans Mono",ui-monospace,monospace;
    display:flex; flex-direction:column; position:relative;
  }}
  .accent {{ position:absolute; left:0; top:0; width:14px; height:100%;
             background:#e3b341; z-index:3; }}
  .top {{ flex:1; padding:34px 56px 0 62px; display:flex;
          flex-direction:column; justify-content:center; }}
  .kick {{ font-size:20px; letter-spacing:.19em; color:#7d8590;
           text-transform:uppercase; margin-bottom:12px; }}
  .kick span {{ color:#e3b341; }}
  .big {{ font-size:74px; font-weight:700; letter-spacing:-.02em; line-height:1.02; }}
  /* inline-block so the strike hugs the text instead of the full-width block */
  .strike {{ display:inline-block; position:relative; color:#767e8a; }}
  .strike::after {{ content:""; position:absolute; left:-8px; right:-8px; top:50%;
                    height:7px; background:#f85149; transform:rotate(-1.2deg); }}
  .gap {{ height:18px; }}
  .know {{ color:#e3b341; letter-spacing:-.025em; }}
  .strip {{ height:214px; border-top:1px solid #262e38; position:relative;
            display:flex; align-items:center; overflow:hidden; }}
  .strip img {{ width:100%; display:block; }}
  .tag {{ position:absolute; left:62px; bottom:20px; font-size:17px;
          letter-spacing:.15em; color:#7d8590; }}
  .tag b {{ color:#e6edf3; font-weight:700; }}
</style>
<div class="accent"></div>
<div class="top">
  <div class="kick">most intrusion detection answers</div>
  <div class="big"><span class="strike">HIGH&nbsp;&nbsp;&nbsp;LOW</span></div>
  <div class="gap"></div>
  <div class="kick"><span>&#9656;</span> SENTINEL answers</div>
  <div class="big know">I&nbsp;DON'T&nbsp;KNOW</div>
</div>
<div class="strip"><img src="data:image/png;base64,{b64}"></div>
<div class="tag">SIH26153 &nbsp;&middot;&nbsp; <b>network attack forecasting</b></div>
"""


def main() -> None:
    strip = Image.open(SOURCE).crop(CROP)
    buf = io.BytesIO()
    strip.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode()

    with sync_playwright() as p:
        b = p.chromium.launch(
            executable_path=str(SHELL),
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        page = b.new_page(viewport={"width": 1280, "height": 720})
        page.set_content(HTML.format(b64=b64), wait_until="load")
        page.wait_for_timeout(700)
        page.screenshot(path=str(OUT))
        b.close()

    kb = OUT.stat().st_size / 1024
    print(f"wrote {OUT} — 1280x720, {kb:.0f} KB")
    if kb > 2048:
        print("WARNING: over YouTube's 2 MB limit")


if __name__ == "__main__":
    main()
