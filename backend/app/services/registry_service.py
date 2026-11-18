"""MCP server registry and tool catalog (spec §10)."""

from __future__ import annotations

import json
import re
import ssl
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from app.config import Settings
from app.core.client_certs import CertificateError, check_key_pair, describe, load_pem_certificates
from app.core.crypto import Encryptor
from app.core.errors import ErrorCode, GatewayError, not_found
from app.core.identity import Principal
from app.core.ids import canonical_json, sha256_hex, utcnow
from app.mcp.adapters.base import ToolDefinition, UpstreamError
from app.mcp.adapters.sdk import validate_stdio_config
from app.mcp.client_manager import ClientManager
from app.mcp.net_guard import NetPolicy, validate_url
from app.models.registry import ClientCertificateInput, ServerCreate, ServerUpdate, ToolUpdate
from app.repositories.collections import Repos
from app.services.audit_service import AuditService
from app.services.validation_service import unsafe_schema_patterns

TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_\-.]{1,64}$")
MAX_SCHEMA_BYTES = 256 * 1024
HEALTH_HISTORY = 50


def upstream_error_to_gateway(exc: UpstreamError) -> GatewayError:
    code = {
        "timeout": ErrorCode.UPSTREAM_TIMEOUT,
        "blocked": ErrorCode.UPSTREAM_BLOCKED,
    }.get(exc.kind, ErrorCode.UPSTREAM_UNAVAILABLE)
    msg = exc.detail if exc.kind == "blocked" else None
    return GatewayError(code, msg)


# Where a server's requests (and its stored credentials) go. Changing any of these re-points the server.
DESTINATION_KEYS = ("endpoint", "command", "args", "env", "cwd", "verify_tls", "tls_ca_pem")


def private_network_allowed(settings: Settings, server_flag: bool) -> bool:
    """Private and loopback upstreams need both opt-ins: the platform setting and the per-server flag."""
    return bool(settings.allow_private_upstream_networks and server_flag)


def server_config_fingerprint(server: dict[str, Any]) -> str:
    """A hash of everything that decides where a server's calls go and with which credentials.

    Recorded on approval requests, so an approved call can't run against a server that was re-pointed since."""
    cfg = server.get("connection_config") or {}
    return sha256_hex(canonical_json({
        "transport": server.get("transport"),
        "destination": {k: cfg.get(k) for k in DESTINATION_KEYS},
        "secret_ref": server.get("secret_ref"), "tls_secret_ref": server.get("tls_secret_ref"),
        "allow_private_network": bool(server.get("allow_private_network")),
    }))


class RegistryService:
    def __init__(
        self, settings: Settings, repos: Repos, encryptor: Encryptor, audit: AuditService, clients: ClientManager
    ) -> None:
        self.settings = settings
        self.repos = repos
        self.encryptor = encryptor
        self.audit = audit
        self.clients = clients

    # ------------------------------------------------------------------ validation
    def _validate_connection(self, transport: str, cfg: dict[str, Any], allow_private: bool) -> None:
        if transport == "streamable_http":
            policy = NetPolicy(
                allow_private=private_network_allowed(self.settings, allow_private),
                host_allowlist=tuple(self.settings.upstream_host_allowlist),
            )
            validate_url(cfg.get("endpoint") or "", policy)
        else:
            try:
                validate_stdio_config(
                    cfg.get("command") or "", cfg.get("args") or [], cfg.get("env") or {},
                    self.settings.stdio_executable_allowlist,
                )
            except UpstreamError as exc:
                raise GatewayError(ErrorCode.UPSTREAM_BLOCKED, exc.detail) from exc

    def _check_private_permission(self, principal: Principal, requested: bool) -> None:
        if requested and not principal.has_any_role("platform_admin", "tenant_admin"):
            raise GatewayError(
                ErrorCode.ACCESS_DENIED, "Only administrators may permit private network destinations."
            )

    @staticmethod
    def _check_stdio_permission(principal: Principal) -> None:
        # A stdio server is a process on the gateway host, shared by every tenant: whoever picks its command,
        # arguments and environment runs code there. Platform administrators only.
        if not principal.has_any_role("platform_admin"):
            raise GatewayError(ErrorCode.ACCESS_DENIED,
                               "Only platform administrators may register or change stdio servers.")

    async def _store_secret(self, tenant_id: str, owner_id: str, secret: dict[str, Any], existing: str | None) -> str:
        if existing:
            await self.repos.secrets.delete(tenant_id, existing)
        doc = await self.repos.secrets.insert(tenant_id, {"owner_id": owner_id, "ciphertext": "", "kind": "upstream"})
        ciphertext = self.encryptor.encrypt(
            json.dumps({k: v for k, v in secret.items() if v is not None}).encode(), f"{tenant_id}:{doc['_id']}"
        )
        await self.repos.secrets.col.update_one(
            {"_id": doc["_id"], "tenant_id": tenant_id}, {"$set": {"ciphertext": ciphertext}}
        )
        return str(doc["_id"])

    @staticmethod
    def _ca_info(ca_pem: str) -> list[dict[str, Any]]:
        try:
            certs = load_pem_certificates(ca_pem)
            ssl.create_default_context(cadata=ca_pem)  # what the connection will do with it
        except (CertificateError, ssl.SSLError) as exc:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, f"CA bundle: {exc}") from None
        return [describe(c).to_api() for c in certs]

    async def _store_client_certificate(self, tenant_id: str, server_id: str, cert: ClientCertificateInput,
                                        existing: str | None) -> tuple[str, dict[str, Any]]:
        """Validate the pair, keep the certificate (public) in the config and the private key encrypted."""
        try:
            info = check_key_pair(cert.cert_pem, cert.key_pem)
        except CertificateError as exc:
            raise GatewayError(ErrorCode.VALIDATION_FAILED, f"Client certificate: {exc}") from None
        ref = await self._store_secret(tenant_id, server_id, {"key_pem": cert.key_pem}, existing)
        return ref, {**info.to_api(), "cert_pem": cert.cert_pem}

    # ------------------------------------------------------------------ servers
    async def create_server(self, p: Principal, data: ServerCreate) -> dict[str, Any]:
        self._check_private_permission(p, data.allow_private_network)
        if data.transport != "streamable_http":
            self._check_stdio_permission(p)
        cfg: dict[str, Any] = {
            "endpoint": data.endpoint,
            "command": data.command,
            "args": data.args,
            "env": data.env,
            "cwd": data.cwd,
            "verify_tls": data.verify_tls,
        }
        if data.tls_ca_pem:
            cfg["tls_ca_pem"], cfg["tls_ca_info"] = data.tls_ca_pem, self._ca_info(data.tls_ca_pem)
        if data.client_certificate:  # checked before anything is written
            try:
                check_key_pair(data.client_certificate.cert_pem, data.client_certificate.key_pem)
            except CertificateError as exc:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, f"Client certificate: {exc}") from None
        self._validate_connection(data.transport, cfg, data.allow_private_network)
        doc = await self.repos.servers.insert(
            p.tenant_id,
            {
                "name": data.name,
                "alias": data.alias,
                "description": data.description,
                "transport": data.transport,
                "connection_config": cfg,
                "enabled": data.enabled,
                "archived": False,
                "environment": data.environment,
                "tags": data.tags,
                "owner": data.owner,
                "authentication_mode": data.authentication_mode,
                "secret_ref": None,
                "connection_timeout_seconds": data.connection_timeout_seconds,
                "request_timeout_seconds": data.request_timeout_seconds,
                "max_concurrent_calls": data.max_concurrent_calls,
                "allow_private_network": data.allow_private_network,
                "health_status": "unknown",
                "tool_count": 0,
                "enabled_tool_count": 0,
                "created_by": p.principal_id,
                "updated_by": p.principal_id,
            },
        )
        if data.secret:
            ref = await self._store_secret(p.tenant_id, doc["_id"], data.secret.model_dump(), None)
            doc = await self.repos.servers.col.find_one_and_update(
                {"_id": doc["_id"], "tenant_id": p.tenant_id}, {"$set": {"secret_ref": ref}}, return_document=True
            )
        if data.client_certificate:
            ref, info = await self._store_client_certificate(p.tenant_id, doc["_id"], data.client_certificate, None)
            doc = await self.repos.servers.col.find_one_and_update(
                {"_id": doc["_id"], "tenant_id": p.tenant_id},
                {"$set": {"tls_secret_ref": ref, "connection_config.tls_client_info": info}}, return_document=True)
        await self.audit.record(
            p.tenant_id, "server.registered", principal=p,
            resource={"server_id": doc["_id"], "server_name": data.name},
            metadata={"transport": data.transport, "allow_private_network": data.allow_private_network,
                      "client_certificate": bool(data.client_certificate), "custom_ca": bool(data.tls_ca_pem)},
        )
        return doc

    async def get_server(self, p: Principal, server_id: str) -> dict[str, Any]:
        doc = await self.repos.servers.get(p.tenant_id, server_id)
        if not doc or doc.get("archived"):
            raise not_found("Server")
        return doc

    async def list_servers(self, p: Principal, *, search: str | None = None, **kw: Any) -> Any:
        q: dict[str, Any] = {"archived": {"$ne": True}}
        if search:
            q["name"] = {"$regex": re.escape(search), "$options": "i"}
        return await self.repos.servers.list(p.tenant_id, q, sort=[("name", 1)], **kw)

    async def update_server(self, p: Principal, server_id: str, data: ServerUpdate) -> dict[str, Any]:
        current = await self.get_server(p, server_id)
        changes: dict[str, Any] = {"updated_by": p.principal_id}
        fields = data.model_dump(exclude_unset=True,
                                 exclude={"version", "secret", "client_certificate", "remove_client_certificate"})
        cfg = dict(current.get("connection_config", {}))
        for key in ("endpoint", "command", "args", "env", "cwd", "verify_tls"):
            if key in fields:
                cfg[key] = fields.pop(key)
        tls_changed = False
        if "tls_ca_pem" in fields:
            ca = fields.pop("tls_ca_pem")
            if ca:
                cfg["tls_ca_pem"], cfg["tls_ca_info"] = ca, self._ca_info(ca)
            else:
                cfg.pop("tls_ca_pem", None)
                cfg.pop("tls_ca_info", None)
            tls_changed = True
        if (data.client_certificate or data.remove_client_certificate) and current["transport"] != "streamable_http":
            raise GatewayError(ErrorCode.VALIDATION_FAILED, "TLS settings apply to streamable_http servers only.")
        if data.client_certificate:
            ref, info = await self._store_client_certificate(p.tenant_id, server_id, data.client_certificate,
                                                             current.get("tls_secret_ref"))
            changes["tls_secret_ref"], cfg["tls_client_info"] = ref, info
            tls_changed = True
        elif data.remove_client_certificate and current.get("tls_secret_ref"):
            await self.repos.secrets.delete(p.tenant_id, current["tls_secret_ref"])
            changes["tls_secret_ref"] = None
            cfg.pop("tls_client_info", None)
            tls_changed = True
        allow_private = fields.get("allow_private_network", current.get("allow_private_network", False))
        if "allow_private_network" in fields:
            self._check_private_permission(p, bool(fields["allow_private_network"]))
        old_cfg = current.get("connection_config") or {}
        repointed = any(cfg.get(k) != old_cfg.get(k) for k in DESTINATION_KEYS)
        if repointed:
            # The stored credentials and the private-network grant were given for the old destination.
            if current["transport"] != "streamable_http":
                self._check_stdio_permission(p)
            if allow_private:
                self._check_private_permission(p, True)
            if current.get("secret_ref") and data.secret is None:
                raise GatewayError(
                    ErrorCode.VALIDATION_FAILED,
                    "Re-enter the server's credential when changing where it connects: a stored credential is "
                    "never sent to a new destination.")
            if current.get("tls_secret_ref") and not (data.client_certificate or data.remove_client_certificate):
                raise GatewayError(
                    ErrorCode.VALIDATION_FAILED,
                    "Upload the client certificate again (or remove it) when changing where the server connects.")
        if cfg != current.get("connection_config") or "allow_private_network" in fields:
            self._validate_connection(current["transport"], cfg, allow_private)
            changes["connection_config"] = cfg
        if tls_changed:
            changes["connection_config"] = cfg
        changes.update(fields)
        if data.secret is not None:
            changes["secret_ref"] = await self._store_secret(
                p.tenant_id, server_id, data.secret.model_dump(), current.get("secret_ref")
            )
        doc = await self.repos.servers.update(p.tenant_id, server_id, changes, expected_version=data.version)
        event = "server.changed"
        if "enabled" in fields and fields["enabled"] != current.get("enabled"):
            event = "server.enabled" if fields["enabled"] else "server.disabled"
        await self.audit.record(
            p.tenant_id, event, principal=p, resource={"server_id": server_id, "server_name": doc["name"]},
            metadata={"changed_fields": sorted(set(changes) - {"updated_by"}), "secret_rotated": data.secret is not None,
                      "destination_changed": repointed,
                      "client_certificate": "replaced" if data.client_certificate else
                      "removed" if data.remove_client_certificate else None},
        )
        return doc

    async def set_server_enabled(self, p: Principal, server_id: str, enabled: bool) -> dict[str, Any]:
        current = await self.get_server(p, server_id)
        doc = await self.repos.servers.update(p.tenant_id, server_id, {"enabled": enabled, "updated_by": p.principal_id})
        if current.get("enabled") != enabled:
            await self.audit.record(
                p.tenant_id, "server.enabled" if enabled else "server.disabled", principal=p,
                resource={"server_id": server_id, "server_name": doc["name"]},
            )
        return doc

    async def archive_server(self, p: Principal, server_id: str) -> None:
        """Delete = archive. Disables immediately, frees the name, keeps tools/audit for history."""
        doc = await self.get_server(p, server_id)
        suffix = f"#archived-{server_id[-8:]}"
        await self.repos.servers.update(
            p.tenant_id, server_id,
            {"archived": True, "enabled": False, "name": doc["name"] + suffix, "alias": doc["alias"] + suffix,
             "updated_by": p.principal_id},
        )
        tools = await self.repos.tools.find_all(p.tenant_id, {"server_id": server_id})
        for t in tools:
            await self.repos.tools.update(
                p.tenant_id, t["_id"],
                {"archived": True, "enabled": False, "gateway_name": t["gateway_name"] + suffix},
            )
        await self.audit.record(
            p.tenant_id, "server.deleted", principal=p, severity="high",
            resource={"server_id": server_id, "server_name": doc["name"]}, metadata={"tools_archived": len(tools)},
        )

    async def test_connection(self, p: Principal | None, server: dict[str, Any]) -> dict[str, Any]:
        """Connects and lists tools; records health. Never returns upstream internals."""
        start = utcnow()
        try:
            async with self.clients.session(server) as adapter:
                result = await adapter.health_check()
        except UpstreamError as exc:
            from app.mcp.adapters.base import HealthResult

            result = HealthResult(False, int((utcnow() - start).total_seconds() * 1000), error=exc.detail or exc.kind)
        status = "healthy" if result.healthy else "unhealthy"
        entry = {"at": utcnow(), "status": status, "latency_ms": result.latency_ms, "error": result.error}
        await self.repos.servers.col.update_one(
            {"_id": server["_id"], "tenant_id": server["tenant_id"]},
            {
                "$set": {
                    "health_status": status, "last_health_check_at": entry["at"],
                    "last_health_error": result.error, "last_latency_ms": result.latency_ms,
                },
                "$push": {"health_history": {"$each": [entry], "$slice": -HEALTH_HISTORY}},
            },
        )
        if p is not None:
            await self.audit.record(
                server["tenant_id"], "server.tested", principal=p,
                resource={"server_id": server["_id"], "server_name": server["name"]}, status=status,
                duration_ms=result.latency_ms,
            )
        return {"healthy": result.healthy, "status": status, "latency_ms": result.latency_ms,
                "error": result.error, "tool_count": result.tool_count}

    # ------------------------------------------------------------------ discovery
    @staticmethod
    def _validate_definition(t: ToolDefinition) -> str | None:
        if not TOOL_NAME_RE.match(t.name):
            return "invalid tool name"
        if len(canonical_json(t.input_schema)) > MAX_SCHEMA_BYTES:
            return "input schema too large"
        if t.input_schema.get("type", "object") != "object":
            return "input schema must describe an object"
        try:
            Draft202012Validator.check_schema(t.input_schema)
            if t.output_schema:
                Draft202012Validator.check_schema(t.output_schema)
        except SchemaError:
            return "invalid JSON schema"
        # Schemas come from the upstream: a regular expression that backtracks catastrophically would let any
        # caller stall the gateway's event loop (validation is synchronous).
        if unsafe_schema_patterns(t.input_schema) or (t.output_schema and unsafe_schema_patterns(t.output_schema)):
            return "unsafe regular expression in schema"
        return None

    async def refresh_tools(self, p: Principal | None, server: dict[str, Any]) -> dict[str, Any]:
        tenant_id = server["tenant_id"]
        try:
            async with self.clients.session(server) as adapter:
                definitions = await adapter.list_tools()
        except UpstreamError as exc:
            await self.repos.servers.col.update_one(
                {"_id": server["_id"], "tenant_id": tenant_id},
                {"$set": {"discovery": {"status": "failed", "at": utcnow(), "error": exc.detail or exc.kind}}},
            )
            raise upstream_error_to_gateway(exc) from exc

        actor = p.principal_id if p else "system"
        now = utcnow()
        summary: dict[str, Any] = {"new": [], "changed": [], "unchanged": 0, "rejected": [], "removed": []}
        seen: set[str] = set()
        for t in definitions[:1000]:
            problem = self._validate_definition(t)
            if problem:
                summary["rejected"].append({"name": t.name[:64], "reason": problem})
                continue
            seen.add(t.name)
            fingerprint = sha256_hex(
                {"input": t.input_schema, "output": t.output_schema, "description": t.description}
            )
            existing = await self.repos.tools.find_one(tenant_id, {"server_id": server["_id"], "upstream_name": t.name})
            if existing is None:
                tool = await self.repos.tools.insert(
                    tenant_id,
                    {
                        "server_id": server["_id"],
                        "server_name": server["name"],
                        "upstream_name": t.name,
                        "gateway_name": f"{server['alias']}__{t.name}",
                        "description": t.description[:4000],
                        "input_schema": t.input_schema,
                        "output_schema": t.output_schema,
                        "annotations": t.annotations,
                        "schema_hash": fingerprint,
                        "schema_version": 1,
                        "risk_level": None,
                        "enabled": False,  # default deny: never auto-enable (spec §10.3)
                        "review_status": "pending_review",
                        "available": True,
                        "archived": False,
                        "last_discovered_at": now,
                    },
                )
                await self._record_version(tenant_id, tool["_id"], fingerprint, t, actor, 1)
                summary["new"].append(t.name)
                await self.audit.record(
                    tenant_id, "tool.discovered", principal=p,
                    resource={"server_id": server["_id"], "tool_id": tool["_id"], "tool_name": t.name},
                )
            elif existing["schema_hash"] != fingerprint:
                version = int(existing.get("schema_version", 1)) + 1
                await self.repos.tools.update(
                    tenant_id, existing["_id"],
                    {
                        "description": t.description[:4000], "input_schema": t.input_schema,
                        "output_schema": t.output_schema, "annotations": t.annotations,
                        "schema_hash": fingerprint, "schema_version": version, "available": True,
                        "previous_schema_hash": existing["schema_hash"],
                        # Block invocation until an administrator reviews the change.
                        "review_status": "schema_changed", "last_discovered_at": now,
                    },
                )
                await self._record_version(tenant_id, existing["_id"], fingerprint, t, actor, version)
                summary["changed"].append(t.name)
                await self.audit.record(
                    tenant_id, "tool.schema.changed", principal=p, severity="high",
                    resource={"server_id": server["_id"], "tool_id": existing["_id"], "tool_name": t.name},
                    metadata={"old_hash": existing["schema_hash"], "new_hash": fingerprint,
                              "schema_version": version, "was_enabled": existing.get("enabled", False)},
                )
            else:
                summary["unchanged"] += 1
                await self.repos.tools.col.update_one(
                    {"_id": existing["_id"], "tenant_id": tenant_id},
                    {"$set": {"last_discovered_at": now, "available": True}},
                )
        # Tools no longer offered upstream become unavailable (kept for history).
        for gone in await self.repos.tools.find_all(
            tenant_id, {"server_id": server["_id"], "upstream_name": {"$nin": list(seen)}, "available": True,
                        "archived": {"$ne": True}}
        ):
            await self.repos.tools.col.update_one(
                {"_id": gone["_id"], "tenant_id": tenant_id}, {"$set": {"available": False}}
            )
            summary["removed"].append(gone["upstream_name"])

        await self._update_counts(tenant_id, server["_id"], extra={
            "discovery": {"status": "ok", "at": now, "summary": {k: (len(v) if isinstance(v, list) else v)
                                                                   for k, v in summary.items()}},
        })
        if p is not None:
            await self.audit.record(
                tenant_id, "server.tools.refreshed", principal=p,
                resource={"server_id": server["_id"], "server_name": server["name"]},
                metadata={k: (len(v) if isinstance(v, list) else v) for k, v in summary.items()},
            )
        return summary

    async def _record_version(
        self, tenant_id: str, tool_id: str, fingerprint: str, t: ToolDefinition, actor: str, version: int
    ) -> None:
        await self.repos.tool_versions.insert(
            tenant_id,
            {
                "tool_id": tool_id, "schema_hash": fingerprint, "schema_version": version,
                "input_schema": t.input_schema, "output_schema": t.output_schema,
                "description": t.description[:4000], "discovered_at": utcnow(), "discovered_by": actor,
            },
        )

    async def _update_counts(self, tenant_id: str, server_id: str, extra: dict[str, Any] | None = None) -> None:
        base = {"server_id": server_id, "archived": {"$ne": True}, "available": True}
        total = await self.repos.tools.count(tenant_id, base)
        enabled = await self.repos.tools.count(tenant_id, {**base, "enabled": True})
        await self.repos.servers.col.update_one(
            {"_id": server_id, "tenant_id": tenant_id},
            {"$set": {"tool_count": total, "enabled_tool_count": enabled, **(extra or {})}},
        )

    # ------------------------------------------------------------------ tools
    async def get_tool(self, p: Principal, tool_id: str) -> dict[str, Any]:
        doc = await self.repos.tools.get(p.tenant_id, tool_id)
        if not doc or doc.get("archived"):
            raise not_found("Tool")
        return doc

    async def list_tools(
        self,
        p: Principal,
        *,
        server_id: str | None = None,
        risk: str | None = None,
        enabled: bool | None = None,
        approval_required: bool | None = None,
        review_status: str | None = None,
        search: str | None = None,
        **kw: Any,
    ) -> Any:
        q: dict[str, Any] = {"archived": {"$ne": True}}
        if server_id:
            q["server_id"] = server_id
        if risk:
            q["risk_level"] = None if risk == "unclassified" else risk
        if enabled is not None:
            q["enabled"] = enabled
        if approval_required is not None:
            q["approval.required"] = True if approval_required else {"$ne": True}
        if review_status:
            q["review_status"] = review_status
        if search:
            rx = {"$regex": re.escape(search), "$options": "i"}
            q["$or"] = [{"upstream_name": rx}, {"gateway_name": rx}, {"description": rx}, {"display_name": rx}]
        return await self.repos.tools.list(p.tenant_id, q, sort=[("gateway_name", 1)], **kw)

    async def update_tool(self, p: Principal, tool_id: str, data: ToolUpdate) -> dict[str, Any]:
        current = await self.get_tool(p, tool_id)
        fields = data.model_dump(exclude_unset=True, exclude={"version", "acknowledge_schema_change"})
        for k in ("approval", "limits", "output"):
            if k in fields and fields[k] is not None:
                fields[k] = getattr(data, k).model_dump()
        risk = fields.get("risk_level", current.get("risk_level"))
        enabling = fields.get("enabled") is True and not current.get("enabled")
        review = current.get("review_status", "pending_review")
        if data.acknowledge_schema_change:
            if review != "schema_changed":
                raise GatewayError(ErrorCode.CONFLICT, "There is no schema change to acknowledge.")
            fields["review_status"] = "approved"
            review = "approved"
        if fields.get("enabled") is True:
            if not risk:
                raise GatewayError(ErrorCode.VALIDATION_FAILED, "Assign a risk level before enabling a tool.",
                                   details=[{"field": "risk_level", "code": "required"}])
            if review == "schema_changed":
                raise GatewayError(ErrorCode.TOOL_SCHEMA_CHANGED,
                                   "Review and acknowledge the schema change before enabling.")
            if review == "pending_review":
                fields["review_status"] = "approved"
            if not current.get("available", True):
                raise GatewayError(ErrorCode.CONFLICT, "The tool is no longer offered by the upstream server.")
        if risk == "critical" and fields.get("approval", current.get("approval", {})).get("required") is False:
            # Critical tools always require approval (spec §14.1); keep the flag truthful.
            approval = dict(fields.get("approval") or current.get("approval") or {})
            approval["required"] = True
            fields["approval"] = approval
        fields["updated_by"] = p.principal_id
        doc = await self.repos.tools.update(p.tenant_id, tool_id, fields, expected_version=data.version)
        await self._update_counts(p.tenant_id, doc["server_id"])
        event = "tool.changed"
        if "enabled" in fields and fields["enabled"] != current.get("enabled"):
            event = "tool.enabled" if fields["enabled"] else "tool.disabled"
        await self.audit.record(
            p.tenant_id, event, principal=p,
            resource={"server_id": doc["server_id"], "tool_id": tool_id, "tool_name": doc["upstream_name"]},
            metadata={"changed_fields": sorted(set(fields) - {"updated_by"}), "risk_level": doc.get("risk_level"),
                      "enabling": enabling, "schema_acknowledged": bool(data.acknowledge_schema_change)},
        )
        return doc

    async def tool_versions(self, p: Principal, tool_id: str) -> list[dict[str, Any]]:
        await self.get_tool(p, tool_id)
        page = await self.repos.tool_versions.list(
            p.tenant_id, {"tool_id": tool_id}, sort=[("discovered_at", -1)], limit=100
        )
        return [
            {"id": v["_id"], "schema_hash": v["schema_hash"], "schema_version": v.get("schema_version"),
             "input_schema": v.get("input_schema"), "output_schema": v.get("output_schema"),
             "discovered_at": v.get("discovered_at"), "discovered_by": v.get("discovered_by")}
            for v in page["items"]
        ]
