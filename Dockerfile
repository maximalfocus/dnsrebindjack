FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Install dependencies first for a cached layer, then install the project itself.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project
COPY src ./src
COPY tests ./tests
COPY scripts ./scripts
RUN uv sync --frozen

# Overridden per service in docker-compose.yml.
CMD ["python", "-c", "print('dnsrebindjack image')"]
