FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

# Install dependencies in a cache-friendly layer. The all extra includes the
# dashboard and CPU PyTorch dependencies required by the demo.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --extra all --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --extra all --no-dev
# The demo target (apps/vulnerable) is a standalone Flask app with its own
# requirements.txt. Installing it here lets the "Force Attack" phases make real
# HTTP requests against a process inside this container, so a deliberately
# vulnerable app is never exposed to the internet.
RUN uv pip install --no-cache --python /app/.venv/bin/python -r apps/vulnerable/requirements.txt

EXPOSE 8501

# A hosted container serves every visitor from one bundle, and the licensed
# source CSVs are not in the image, so the console hides the raw-CSV dataset
# option and disables in-session retraining. Retraining on a shared 2-vCPU box
# would be slow enough to look broken; the committed bundle is the model.
ENV SENTINEL_CLOUD=1 \
    SENTINEL_READONLY=1

# Vercel injects $PORT; fall back to 8501 so the local Compose stack is unchanged.
# ENV cannot expand at build time, so the port is passed as a runtime flag.
# The demo target starts first on loopback (it binds 5000) so the attack phases
# have something to hit; Streamlit stays the foreground process Vercel routes to.
CMD ["sh", "-c", "(python apps/vulnerable/app.py >/tmp/demo-target.log 2>&1 &) ; exec uv run --no-sync streamlit run streamlit_app.py --server.address=0.0.0.0 --server.port=${PORT:-8501} --server.headless=true"]
