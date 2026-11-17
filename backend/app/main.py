"""FastAPI application: REST management API under /api/v1 and the gateway MCP endpoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.middleware import CorrelationMiddleware, install_error_handlers
from app.api.v1 import (
    agent_oauth,
    approvals,
    auth,
    health,
    identity,
    ldap,
    observability,
    policies,
    registry,
    siem,
    sso,
)
from app.config import Settings, get_settings
from app.container import Container
from app.core.logging import configure_logging, get_logger
from app.mcp.gateway_server import GatewayASGI, build_gateway
from app.migrations.indexes import ensure_indexes

log = get_logger(__name__)


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, json_output=not settings.is_dev)
    c = container or Container(settings)
    _, manager = build_gateway(c)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await ensure_indexes(c.db)
        await c.identity.bootstrap()
        log.info("gateway.started", env=settings.app_env, version=settings.app_version)
        async with manager.run():
            yield
        if container is None:
            await c.close()

    app = FastAPI(
        title="MCP-Gateway",
        version=settings.app_version,
        lifespan=lifespan,
        docs_url="/api/docs" if settings.is_dev else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.is_dev else None,
    )
    app.state.container = c
    install_error_handlers(app)

    api = APIRouter(prefix="/api/v1")
    for r in (auth.router, sso.router, ldap.router, agent_oauth.router, siem.router, identity.router, registry.router, policies.router, approvals.router,
              observability.router):
        api.include_router(r)
    app.include_router(api)
    app.include_router(health.router)
    # Exact routes (not a Mount) so clients never receive a 307 redirect from /mcp to /mcp/.
    gateway = GatewayASGI(c, manager)
    path = settings.mcp_endpoint_path.rstrip("/")
    for p in (path, path + "/"):
        app.router.add_route(p, gateway, methods=["GET", "POST", "DELETE"], include_in_schema=False)  # type: ignore[arg-type]

    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware, allow_origins=settings.cors_allowed_origins, allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token",
                                                                            "X-Request-ID", "Authorization"],
        )
    app.add_middleware(CorrelationMiddleware, max_body=settings.max_request_body_bytes,
                       hsts=settings.public_base_url.startswith("https") and not settings.is_dev)
    return app


def app_factory() -> FastAPI:
    return create_app()
