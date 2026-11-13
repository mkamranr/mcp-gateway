# syntax=docker/dockerfile:1
# MCP-Gateway backend image (API and worker share it). Pin base images by digest in your registry for production.
ARG PYTHON_IMAGE=python:3.12.13-slim-bookworm

FROM ${PYTHON_IMAGE} AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PIP_NO_CACHE_DIR=1
RUN pip install --no-cache-dir uv==0.11.22
WORKDIR /app
COPY pyproject.toml uv.lock ./
# Locked, production-only dependencies; fails if uv.lock is out of date.
RUN uv sync --frozen --no-dev --no-install-project
COPY app ./app
RUN uv sync --frozen --no-dev

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="mcp-gateway" org.opencontainers.image.description="Secure MCP gateway API and worker"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PATH="/app/.venv/bin:$PATH" APP_ENV=production
RUN groupadd --system --gid 10001 mgw && useradd --system --uid 10001 --gid mgw --no-create-home --shell /usr/sbin/nologin mgw
WORKDIR /app
COPY --from=build --chown=root:root /app /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health/live', timeout=3).status == 200 else 1)"]
# --proxy-headers is only safe behind the bundled reverse proxy; restrict --forwarded-allow-ips accordingly.
CMD ["uvicorn", "--factory", "app.main:create_app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
