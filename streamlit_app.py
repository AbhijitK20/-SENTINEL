# Streamlit Community Cloud entry point.
#
# Streamlit Cloud looks for `streamlit_app.py` / `app.py` / `main.py` at the
# repository root and serves it directly. It does not run `uv run`, and it does
# not `pip install` the project itself, so this shim puts `src/` on the path and
# then executes the real console. There is deliberately no cloud-only variant of
# the console, so the deployed app cannot drift from the local one.
#
# The console must be executed with runpy, not imported. Streamlit re-runs the
# entry script on every widget interaction; a plain `import sentinel.dashboard.app`
# is a no-op from the second run onwards because the module is already in
# sys.modules, so every `st.*` call is skipped and the page renders blank while
# the server sits idle. That failure is silent - no exception, no log line - and
# it looks exactly like the app hanging.
from __future__ import annotations

import os
import runpy
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
_CONSOLE = _SRC / "sentinel" / "dashboard" / "app.py"

if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Cloud has no data/raw/, so the licensed CSVs are absent by design. The console
# hides the raw-CSV dataset option when this is set rather than offering one that
# would fail after a 15-20 minute windowing attempt. Declared explicitly so the
# assumption is visible rather than inferred.
os.environ.setdefault("SENTINEL_CLOUD", "1")

# The committed release bundle is the model on Cloud. One repository serves every
# visitor, so a hosted session cannot swap the bundle for one it trained itself;
# the console disables the retrain control and says so instead of leaving a button
# that silently does nothing.
os.environ.setdefault("SENTINEL_READONLY", "1")

# The Live tab starts a local target/attacker pair and polls the API. Neither
# exists on Cloud, so the demo cannot run there; the tab says so rather than
# hanging on an unreachable host.
os.environ.setdefault("SENTINEL_API_URL", "http://127.0.0.1:8100")
os.environ.setdefault("SENTINEL_DEMO_TARGET", "http://127.0.0.1:8888")

runpy.run_path(str(_CONSOLE), run_name="__main__")
