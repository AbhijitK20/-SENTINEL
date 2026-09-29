# Streamlit Community Cloud entry point.
#
# Streamlit Cloud looks for `streamlit_app.py` / `app.py` / `main.py` at the
# repository root and serves it directly. It does not run `uv run`, and it does
# not `pip install` the project itself, so this shim puts `src/` on the path and
# then hands over to the real console.
#
# The console is the same file judges run locally - one entry point, no forked
# "cloud version" that can drift from the local one.
from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"

if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Cloud provides no data/raw/, so the licensed CSVs are absent by design. The
# console already hides the raw-CSV option when no CSV is present, and the
# committed pre-windowed aggregate is what the real-data path uses. Setting this
# makes the same assumption explicit and lets the console skip the search.
os.environ.setdefault("SENTINEL_CLOUD", "1")

# Held-out Cloud instances may serve a different user, so per-session mutable
# state must not leak between them.
os.environ.setdefault("SENTINEL_READONLY", "1")

# The console is a module-level Streamlit script, not a function, so importing
# it is what renders it. There is deliberately no cloud-only code path here: the
# shim only fixes the two things Cloud does differently (sys.path, env).
import sentinel.dashboard.app  # noqa: E402,F401
