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

EXPOSE 8501

CMD ["uv", "run", "--no-sync", "streamlit", "run", "src/trajectory/dashboard/app.py"]
