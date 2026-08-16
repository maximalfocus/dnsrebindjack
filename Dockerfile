FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Install dependencies first for a cached layer, then install the project itself.
# LICENSE is required at build time: pyproject.toml declares it via `license-files`.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-install-project
COPY src ./src
COPY tests ./tests
COPY scripts ./scripts
RUN uv sync --frozen

# Overridden per service in docker-compose.yml.
CMD ["python", "-c", "print('dnsrebindjack image')"]
