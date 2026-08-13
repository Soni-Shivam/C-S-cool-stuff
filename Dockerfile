# Core install only. The `lab` extra (frida, mitmproxy) is deliberately absent:
# this image serves the API and must not be able to instrument a sample.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# androguard needs a compiler for some transitive wheels on slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /app

# Dependency layer first so code edits don't reinstall the world.
COPY pyproject.toml uv.lock* README.md ./
RUN uv sync --no-dev --no-install-project

COPY drishti/ ./drishti/
COPY data/kb/ ./data/kb/
RUN uv sync --no-dev

RUN useradd --create-home --uid 10001 drishti \
    && mkdir -p /data && chown -R drishti:drishti /data /app
USER drishti

EXPOSE 8080
CMD ["uv", "run", "--no-dev", "uvicorn", "drishti.api.main:app", \
     "--host", "0.0.0.0", "--port", "8080"]
