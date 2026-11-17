"""The single shared invocation pipeline (spec §11.4, §30).

MCP calls, REST calls and approved executions from the worker all go through
``InvocationService``. The order of checks is fixed:

identity -> tenant -> tool mapping -> server/tool state -> policy -> input validation
-> (approval) -> quotas/concurrency -> audit -> dispatch -> output controls -> audit.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import anyio

from app.config import Settings
from app.core.crypto import Encryptor
from app.core.errors import DEPENDENCY_ERRORS, ErrorCode, GatewayError, dependency_unavailable
from app.core.identity import Principal
from app.core.ids import new_id, sha256_hex, utcnow
from app.core.logging import get_logger, request_id_var
from app.mcp.adapters.base import UpstreamError
from app.mcp.client_manager import ClientManager
from app.repositories.collections import Repos
from app.services.approval_service import ApprovalService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService
from app.services.policy_service import PolicyDecision, PolicyService, RequestContext
from app.services.quota_service import QuotaService
from app.services.registry_service import upstream_error_to_gateway
from app.services.validation_service import ValidationService

log = get_logger(__name__)
RESULT_RETENTION = timedelta(hours=24)
SENSITIVE_RISK = {"high", "critical"}
PERSIST_FOR_SECONDS = 30.0  # longer than a MongoDB election or a Sentinel failover
OUTCOME_UNKNOWN = ("The call was sent to the upstream, but its outcome could not be recorded because a database was "
                   "unavailable. It is not retried. Check the upstream system before requesting it again.")


def _is_dependency_error(exc: BaseException) -> bool:
    if isinstance(exc, GatewayError):
        return exc.code == ErrorCode.DEPENDENCY_UNAVAILABLE
    return isinstance(exc, DEPENDENCY_ERRORS)


async def persist[T](op: Callable[[], Awaitable[T]], seconds: float = PERSIST_FOR_SECONDS) -> T:
    """Run a state write, retrying it through a MongoDB election or Redis failover. Used by the approval worker,
    where giving up would leave an approved call unresolved. Re-raises once ``seconds`` have passed."""
    deadline, delay = time.monotonic() + seconds, 0.5
    while True:
        try:
            return await op()
        except Exception as exc:
            if not _is_dependency_error(exc) or time.monotonic() + delay > deadline:
                raise
            log.warning("worker.write_retry", error=type(exc).__name__, retry_in=delay)
            await anyio.sleep(delay)
            delay = min(delay * 2, 4.0)


@dataclass
class InvocationContext:
    source: str = "mcp"  # mcp | rest | approval_worker
    source_ip: str | None = None
    purpose: str | None = None
    approval_id: str | None = None  # set only by the approval worker


@dataclass
class InvocationOutcome:
    invocation_id: str
    status: str  # completed | tool_error | pending_approval
    content: list[dict[str, Any]] = field(default_factory=list)
    structured_content: dict[str, Any] | None = None
    is_error: bool = False
    approval_id: str | None = None
    expires_at: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


class InvocationService:
    def __init__(
        self,
        settings: Settings,
        repos: Repos,
        encryptor: Encryptor,
        audit: AuditService,
        auth: AuthService,
        policy: PolicyService,
        validation: ValidationService,
        quotas: QuotaService,
        approvals: ApprovalService,
        clients: ClientManager,
    ) -> None:
        self.settings = settings
        self.repos = repos
        self.encryptor = encryptor
        self.audit = audit
        self.auth = auth
        self.policy = policy
        self.validation = validation
        self.quotas = quotas
        self.approvals = approvals
        self.clients = clients

    # ------------------------------------------------------------------ discovery
    async def discover(self, principal: Principal) -> list[dict[str, Any]]:
        """Return only tools the principal may discover. Discovery is not an authorization grant."""
        if principal.principal_type != "agent" or "tools:list" not in principal.scopes:
            return []
        tenant = await self.repos.tenants.get(principal.tenant_id)
        crit = bool((tenant or {}).get("settings", {}).get("critical_requires_approval", True))
        servers = {s["_id"]: s for s in await self.repos.servers.find_all(
            principal.tenant_id, {"enabled": True, "archived": {"$ne": True}})}
        if not servers:
            return []
        tools = await self.repos.tools.find_all(principal.tenant_id, {
            "server_id": {"$in": list(servers)}, "enabled": True, "archived": {"$ne": True}, "available": True,
            "review_status": "approved"})
        policies = await self.repos.policies.enabled_for_tenant(principal.tenant_id)
        from app.services.policy_service import evaluate

        visible = []
        for tool in tools:
            server = servers[tool["server_id"]]
            ctx = RequestContext(principal=principal, action="discover", server=server, tool=tool,
                                 critical_requires_approval=crit)
            if evaluate(policies, ctx).decision == "ALLOW":
                visible.append(tool)
        return sorted(visible, key=lambda t: t["gateway_name"])

    # ------------------------------------------------------------------ invocation
    async def invoke(
        self, principal: Principal, gateway_name: str, arguments: Any, ctx: InvocationContext | None = None,
        stage: dict[str, bool] | None = None,
    ) -> InvocationOutcome:
        """Run the full pipeline. ``stage["committed"]`` turns True at the point of no return: just before the
        tool call is sent to the upstream. A MongoDB or Redis outage before that point is reported as
        DEPENDENCY_UNAVAILABLE with ``extra["before_dispatch"]`` True: the upstream was not called, so the caller
        may retry it."""
        stage = stage if stage is not None else {}
        stage.setdefault("committed", False)
        try:
            return await self._invoke(principal, gateway_name, arguments, ctx or InvocationContext(), stage)
        except GatewayError as exc:
            if exc.code == ErrorCode.DEPENDENCY_UNAVAILABLE:
                exc.extra["before_dispatch"] = not stage["committed"]
            raise
        except DEPENDENCY_ERRORS as exc:
            err = dependency_unavailable(exc) or GatewayError(ErrorCode.DEPENDENCY_UNAVAILABLE)
            err.extra["before_dispatch"] = not stage["committed"]
            log.warning("invocation.dependency_unavailable", error=type(exc).__name__,
                        before_dispatch=not stage["committed"])
            raise err from None

    async def _invoke(self, principal: Principal, gateway_name: str, arguments: Any, ctx: InvocationContext,
                      stage: dict[str, bool]) -> InvocationOutcome:
        inv_id = new_id("inv")
        started = time.perf_counter()
        resource: dict[str, Any] = {"gateway_name": gateway_name[:200]}
        args_hash = None
        try:
            args_hash = sha256_hex(arguments) if isinstance(arguments, dict) else None
        except (TypeError, ValueError):
            args_hash = None
        base_meta = {"source": ctx.source, "source_ip": ctx.source_ip}

        async def deny(code: ErrorCode, msg: str | None = None, *, decision: str = "DENY",
                       policy: PolicyDecision | None = None, status: str = "rejected",
                       headers: dict[str, str] | None = None, **extra: Any) -> GatewayError:
            await self.audit.record(
                principal.tenant_id, "tool.invocation.rejected", principal=principal, invocation_id=inv_id,
                approval_id=ctx.approval_id, resource=resource, decision=decision,
                policy_ids=policy.policy_ids if policy else [],
                # The policy's reason only explains a policy denial; later refusals record their own code.
                reason_code=(policy.reason_code if policy and policy.decision == "DENY" else code),
                status=status, input_hash=args_hash, duration_ms=int((time.perf_counter() - started) * 1000),
                metadata={**base_meta, "error_code": code.value,
                          "explanation": policy.explanation if policy else None, **extra},
            )
            await self._record_invocation(principal, inv_id, resource, decision, status, args_hash, code.value,
                                          started, ctx)
            return GatewayError(code, msg, details=extra.get("details"), headers=headers)

        # 1-3. identity + scope
        if principal.principal_type != "agent":
            raise await deny(ErrorCode.ACCESS_DENIED, "Only agent identities may invoke tools.")
        if "tools:invoke" not in principal.scopes:
            raise await deny(ErrorCode.ACCESS_DENIED, "The credential lacks the tools:invoke scope.")

        # The requested event is written before anything else happens. If audit is mandatory
        # and the event cannot be written, the call fails closed here.
        await self.audit.record(
            principal.tenant_id, "tool.invocation.requested", principal=principal, invocation_id=inv_id,
            approval_id=ctx.approval_id, resource=resource, input_hash=args_hash, metadata=base_meta,
            required=self.settings.audit_required_for_execution,
        )

        tenant = await self.repos.tenants.get(principal.tenant_id)
        if not tenant or tenant.get("status") != "active":
            raise await deny(ErrorCode.TENANT_SUSPENDED, "The tenant is suspended.")

        # 4. tool mapping + state
        tool = await self.repos.tools.by_gateway_name(principal.tenant_id, gateway_name)
        if not tool:
            raise await deny(ErrorCode.TOOL_NOT_FOUND)
        server = await self.repos.servers.get(principal.tenant_id, tool["server_id"])
        resource.update({"tool_id": tool["_id"], "tool_name": tool["upstream_name"], "server_id": tool["server_id"],
                         "risk_level": tool.get("risk_level"), "schema_hash": tool.get("schema_hash"),
                         "schema_version": tool.get("schema_version")})
        if not server or server.get("archived"):
            raise await deny(ErrorCode.TOOL_NOT_FOUND)
        resource["server_name"] = server["name"]

        # 5-6. policy. It is evaluated before the tool-state checks so that a principal without a
        # grant learns nothing about the tool's internal state (disabled, unreviewed, schema change,
        # server disabled). Spec §11.2: do not reveal hidden tools. Both orders deny the call.
        settings = tenant.get("settings", {})
        decision = await self.policy.decide(RequestContext(
            principal=principal, action="invoke", server=server, tool=tool, source_ip=ctx.source_ip,
            critical_requires_approval=bool(settings.get("critical_requires_approval", True))))
        if decision.reason_code == "POLICY_ENGINE_UNAVAILABLE":
            # Fail closed (audited as DENY / POLICY_ENGINE_UNAVAILABLE), but tell the caller it is temporary.
            raise await deny(ErrorCode.DEPENDENCY_UNAVAILABLE, "The policy store is temporarily unavailable.",
                             policy=decision, headers={"Retry-After": "5"})
        if decision.decision == "DENY":
            raise await deny(ErrorCode.ACCESS_DENIED, policy=decision)

        if not server.get("enabled"):
            raise await deny(ErrorCode.SERVER_DISABLED, "The MCP server is disabled.", policy=decision)
        if not tool.get("enabled") or not tool.get("available", True):
            raise await deny(ErrorCode.TOOL_DISABLED, "The tool is disabled.", policy=decision)
        if tool.get("review_status") == "schema_changed":
            raise await deny(ErrorCode.TOOL_SCHEMA_CHANGED, "The tool schema changed and awaits review.",
                             policy=decision)
        if tool.get("review_status") != "approved" or not tool.get("risk_level"):
            raise await deny(ErrorCode.TOOL_DISABLED, "The tool has not been reviewed.", policy=decision)

        # 7. input validation
        try:
            input_bytes = self.validation.validate_input(tool, arguments)
        except GatewayError as exc:
            raise await deny(exc.code, exc.message, policy=decision, details=exc.details) from None
        args_hash = sha256_hex(arguments)

        # 8. approval
        approved_doc: dict[str, Any] | None = None
        if decision.decision == "REQUIRE_APPROVAL":
            if ctx.approval_id:
                approved_doc = await self.repos.approvals.get(principal.tenant_id, ctx.approval_id)
                if (not approved_doc or approved_doc.get("status") != "EXECUTING"
                        or approved_doc.get("arguments_hash") != args_hash
                        or approved_doc.get("tool_id") != tool["_id"]
                        or approved_doc.get("agent_id") != principal.agent_id):
                    raise await deny(ErrorCode.APPROVAL_INVALIDATED, "The approval does not match this request.",
                                     policy=decision)
            else:
                # Rate limits still apply to approval requests to prevent approval flooding.
                try:
                    await self.quotas.check_and_consume(self.quotas.build_limits(
                        principal, tool, settings, decision.obligations,
                        await self.repos.settings.get_value("global_limits")))
                except GatewayError as exc:
                    raise await deny(exc.code, exc.message, policy=decision, headers=exc.headers) from None
                await self._record_invocation(principal, inv_id, resource, decision.decision, "pending_approval",
                                              args_hash, None, started, ctx)
                approval = await self.approvals.create(
                    principal, invocation_id=inv_id, tool=tool, server=server, arguments=arguments,
                    arguments_hash=args_hash, decision_policy_ids=decision.policy_ids,
                    approval_obligation=decision.obligations.get("approval", {}), purpose=ctx.purpose)
                await self.repos.invocations.col.update_one(
                    {"_id": inv_id, "tenant_id": principal.tenant_id}, {"$set": {"approval_id": approval["_id"]}})
                return InvocationOutcome(inv_id, "pending_approval", approval_id=approval["_id"],
                                         expires_at=approval["expires_at"])

        # 9. quotas + concurrency
        try:
            warnings = await self.quotas.check_and_consume(self.quotas.build_limits(
                principal, tool, settings, decision.obligations,
                await self.repos.settings.get_value("global_limits")))
            conc_keys = await self.quotas.acquire_concurrency(principal, tool)
        except GatewayError as exc:
            if exc.code != ErrorCode.DEPENDENCY_UNAVAILABLE:  # an unreachable Redis is not an exceeded quota
                await self.audit.record(principal.tenant_id, "quota.exceeded", principal=principal,
                                        invocation_id=inv_id, resource=resource, metadata={**exc.extra,
                                                                                            "code": exc.code.value})
            raise await deny(exc.code, exc.message, policy=decision, headers=exc.headers, **exc.extra) from None
        for w in warnings:
            await self.audit.record(principal.tenant_id, "quota.threshold.warning", principal=principal,
                                    resource=resource, severity="warning", metadata=w)

        try:
            # 10. dispatch record + audit. Fail closed for sensitive tools if audit is unavailable.
            sensitive = tool.get("risk_level") in SENSITIVE_RISK
            idem = f"approval:{ctx.approval_id}" if ctx.approval_id else None
            try:
                await self._record_invocation(principal, inv_id, resource, decision.decision, "dispatched",
                                              args_hash, None, started, ctx, idempotency_key=idem)
            except GatewayError as exc:
                if exc.code == ErrorCode.CONFLICT:  # duplicate approved execution
                    raise GatewayError(ErrorCode.APPROVAL_STATE_CONFLICT, "Already executed.") from None
                raise
            await self.audit.record(
                principal.tenant_id, "tool.invocation.dispatched", principal=principal, invocation_id=inv_id,
                approval_id=ctx.approval_id, resource=resource, decision="ALLOW", policy_ids=decision.policy_ids,
                input_hash=args_hash, metadata={**base_meta, "input_bytes": input_bytes},
                required=sensitive or self.settings.audit_required_for_execution,
            )

            # 11. upstream call
            timeout = min(float(tool.get("timeout_seconds") or server.get("request_timeout_seconds")
                                or self.settings.default_tool_timeout_seconds),
                          self.settings.max_tool_timeout_seconds)
            try:
                async with self.clients.limited_session(server) as adapter:
                    # Point of no return: from here on the call may reach the upstream, so it is never retried.
                    stage["committed"] = True
                    result = await adapter.call_tool(tool["upstream_name"], arguments, timeout)
            except UpstreamError as exc:
                err = upstream_error_to_gateway(exc)
                await self._finish(principal, inv_id, resource, "failed", started, ctx, error_code=err.code.value,
                                   policy_ids=decision.policy_ids, args_hash=args_hash,
                                   event="tool.invocation.timed_out" if exc.kind == "timeout"
                                   else "tool.invocation.failed")
                raise err from None

            # 12. output controls (output is untrusted data)
            try:
                content, structured, out_meta = self.validation.process_output(
                    tool, result.content, result.structured_content)
            except GatewayError as exc:
                await self._finish(principal, inv_id, resource, "failed", started, ctx, error_code=exc.code.value,
                                   policy_ids=decision.policy_ids, args_hash=args_hash)
                raise
            out_hash = sha256_hex({"content": content, "structured": structured})
            status = "tool_error" if result.is_error else "completed"
            await self._finish(principal, inv_id, resource, status, started, ctx, output_hash=out_hash,
                               policy_ids=decision.policy_ids, args_hash=args_hash, extra_meta=out_meta)
            meta = {"untrusted": True, "invocation_id": inv_id, **{k: v for k, v in out_meta.items()
                                                                   if k in ("redacted_fields", "output_bytes")}}
            return InvocationOutcome(inv_id, status, content, structured, bool(result.is_error), metadata=meta)
        finally:
            await self.quotas.release_concurrency(conc_keys)

    # ------------------------------------------------------------------ approved execution (worker)
    async def execute_approved(self, tenant_id: str, approval_id: str) -> str:
        """Claim and execute one approved request exactly once. Returns the final status."""
        claimed = await self.repos.approvals.transition(tenant_id, approval_id, "APPROVED", "REVALIDATING",
                                                        {"revalidating_at": utcnow()})
        if not claimed:
            return "not_claimed"  # someone else claimed it, or the state changed
        stage = {"committed": False}
        try:
            return await self._execute_claimed(tenant_id, approval_id, claimed, stage)
        except Exception as exc:
            dep = exc if isinstance(exc, GatewayError) and exc.code == ErrorCode.DEPENDENCY_UNAVAILABLE \
                else dependency_unavailable(exc)
            if dep is None or stage["committed"]:
                raise  # after the point of no return the call is never retried
            return await self._defer(tenant_id, approval_id, claimed, type(exc).__name__)

    async def _defer(self, tenant_id: str, approval_id: str, claimed: dict[str, Any], reason: str) -> str:
        """MongoDB or Redis failed before the upstream was called: hand the request back for a later retry.

        Nothing ran, so this is safe. A dispatch record this attempt may have written is marked superseded, so it
        no longer holds the approval's idempotency key. If even these writes fail, the stale-claim sweep returns
        the request later (or, if the dispatch record is still there, resolves it as FAILED)."""
        try:
            await persist(lambda: self._supersede_dispatch(tenant_id, approval_id))
            back = await persist(lambda: self.repos.approvals.transition(
                tenant_id, approval_id, ["REVALIDATING", "EXECUTING"], "APPROVED", {"deferred_at": utcnow()}))
            if back:
                await persist(lambda: self.audit.record(
                    tenant_id, "approval.execution.deferred", principal={"type": "service", "id": "approval-worker"},
                    approval_id=approval_id, invocation_id=claimed.get("invocation_id"),
                    reason_code=ErrorCode.DEPENDENCY_UNAVAILABLE.value, metadata={"error": reason}))
        except Exception as exc:  # noqa: BLE001
            log.warning("approval.defer_failed", approval_id=approval_id, error=type(exc).__name__)
        return "DEFERRED"

    async def _supersede_dispatch(self, tenant_id: str, approval_id: str) -> None:
        """Release the idempotency key held by a dispatch record of an attempt that never reached the upstream.

        Only called while this worker holds the claim, and an attempt that passed the point of no return never
        hands the claim back, so every such record belongs to an attempt that was deferred."""
        key = f"approval:{approval_id}"
        async for d in self.repos.invocations.col.find(
                {"tenant_id": tenant_id, "idempotency_key": key, "status": "dispatched"}, {"_id": 1}):
            await self.repos.invocations.col.update_one(
                {"_id": d["_id"], "tenant_id": tenant_id, "idempotency_key": key},
                {"$set": {"status": "superseded", "idempotency_key": f"{key}:superseded:{d['_id']}",
                          "updated_at": utcnow()}})

    async def release_stale_claims(self, older_than: timedelta = timedelta(minutes=5)) -> int:
        """Resolve claims abandoned by a crashed or cut-off worker (REVALIDATING/EXECUTING).

        No dispatch record holds the approval's idempotency key: the call never reached the upstream, so it goes
        back to APPROVED and runs later. A dispatch record exists: it may have reached the upstream, so it is
        never run again; it is marked FAILED with the outcome unknown instead of being left in limbo."""
        cutoff, n = utcnow() - older_than, 0
        for d in await self.repos.approvals.stale_claims_global(cutoff):
            key = f"approval:{d['_id']}"
            if await self.repos.invocations.find_one(d["tenant_id"], {"idempotency_key": key}):
                failed = await self.repos.approvals.col.find_one_and_update(
                    {"_id": d["_id"], "tenant_id": d["tenant_id"], "status": d["status"],
                     "updated_at": d["updated_at"]},
                    {"$set": {"status": "FAILED", "updated_at": utcnow(), "completed_at": utcnow(),
                              "execution": {"error_code": ErrorCode.DEPENDENCY_UNAVAILABLE.value,
                                            "message": OUTCOME_UNKNOWN}}})
                if failed:
                    n += 1
                    await self.audit.record(d["tenant_id"], "approval.execution.failed", severity="high",
                                            principal={"type": "service", "id": "worker"}, approval_id=d["_id"],
                                            reason_code="OUTCOME_UNKNOWN", metadata={"from_status": d["status"]})
                continue
            back = await self.repos.approvals.col.find_one_and_update(
                {"_id": d["_id"], "tenant_id": d["tenant_id"], "status": d["status"], "updated_at": d["updated_at"]},
                {"$set": {"status": "APPROVED", "updated_at": utcnow(), "deferred_at": utcnow()}})
            if back:
                n += 1
                await self.audit.record(d["tenant_id"], "approval.execution.deferred",
                                        principal={"type": "service", "id": "worker"}, approval_id=d["_id"],
                                        reason_code="STALE_CLAIM", metadata={"from_status": d["status"]})
        return n

    async def _execute_claimed(self, tenant_id: str, approval_id: str, claimed: dict[str, Any],
                               stage: dict[str, bool]) -> str:
        actor = {"type": "service", "id": "approval-worker"}
        await self.audit.record(tenant_id, "approval.revalidating", principal=actor, approval_id=approval_id,
                                invocation_id=claimed.get("invocation_id"))

        async def abort(code: str, message: str) -> str:
            await self.repos.approvals.transition(tenant_id, approval_id, ["REVALIDATING", "EXECUTING"],
                                                  "EXECUTION_ABORTED",
                                                  {"execution": {"error_code": code, "message": message,
                                                                 "at": utcnow()}})
            await self.repos.invocations.update(tenant_id, claimed["invocation_id"], {"status": "aborted",
                                                                                     "error_code": code})
            await self.audit.record(tenant_id, "approval.execution.aborted", principal=actor, severity="high",
                                    approval_id=approval_id, invocation_id=claimed.get("invocation_id"),
                                    reason_code=code, metadata={"message": message})
            return "EXECUTION_ABORTED"

        try:
            await self.auth.revalidate_agent(tenant_id, claimed["agent_id"], claimed.get("credential_id"))
            arguments = self.approvals.decrypt_arguments(claimed)
        except GatewayError as exc:
            if exc.code == ErrorCode.DEPENDENCY_UNAVAILABLE:
                raise  # temporary: deferred by execute_approved, not aborted
            return await abort(exc.code.value, exc.message)
        cred = await self.repos.credentials.get(tenant_id, claimed["credential_id"]) if claimed.get(
            "credential_id") else None
        agent = await self.repos.agents.get(tenant_id, claimed["agent_id"])
        principal = Principal(
            principal_type="agent", principal_id=claimed["agent_id"], tenant_id=tenant_id,
            scopes=tuple((cred or {}).get("scopes", [])), credential_id=claimed.get("credential_id"),
            agent_id=claimed["agent_id"], display_name=(agent or {}).get("name", ""),
            delegated_by_user_id=claimed.get("delegated_by_user_id"),
        )
        moved = await self.repos.approvals.transition(tenant_id, approval_id, "REVALIDATING", "EXECUTING",
                                                      {"executed_at": utcnow()})
        if not moved:
            return "not_claimed"
        token = request_id_var.set(f"req_apr_{approval_id[-12:]}")
        try:
            outcome = await self.invoke(principal, claimed["gateway_name"], arguments,
                                        InvocationContext(source="approval_worker", approval_id=approval_id),
                                        stage=stage)
        except GatewayError as exc:
            if exc.code == ErrorCode.DEPENDENCY_UNAVAILABLE and not stage["committed"]:
                raise  # deferred by execute_approved
            if exc.code in (ErrorCode.ACCESS_DENIED, ErrorCode.TOOL_DISABLED, ErrorCode.SERVER_DISABLED,
                            ErrorCode.TOOL_SCHEMA_CHANGED, ErrorCode.APPROVAL_INVALIDATED, ErrorCode.TOOL_NOT_FOUND,
                            ErrorCode.TENANT_SUSPENDED, ErrorCode.TOOL_ARGUMENT_VALIDATION_FAILED,
                            ErrorCode.QUOTA_EXCEEDED, ErrorCode.RATE_LIMIT_EXCEEDED, ErrorCode.APPROVAL_STATE_CONFLICT):
                return await abort(exc.code.value, exc.message)
            code, message = exc.code.value, (OUTCOME_UNKNOWN if exc.code == ErrorCode.DEPENDENCY_UNAVAILABLE else exc.message)
            await persist(lambda: self.repos.approvals.transition(tenant_id, approval_id, "EXECUTING", "FAILED", {
                "completed_at": utcnow(), "execution": {"error_code": code, "message": message}}))
            await persist(lambda: self.repos.invocations.update(tenant_id, claimed["invocation_id"], {
                "status": "failed", "error_code": code}))
            return "FAILED"
        finally:
            request_id_var.reset(token)
        result_ct = self.encryptor.encrypt(
            json.dumps({"content": outcome.content, "structured_content": outcome.structured_content,
                        "is_error": outcome.is_error}).encode(),
            f"{tenant_id}:{approval_id}:result")
        await persist(lambda: self.repos.approvals.transition(tenant_id, approval_id, "EXECUTING", "COMPLETED", {
            "completed_at": utcnow(), "result_encrypted": result_ct, "result_expires_at": utcnow() + RESULT_RETENTION,
            "execution": {"invocation_id": outcome.invocation_id, "status": outcome.status}}))
        await persist(lambda: self.repos.invocations.update(tenant_id, claimed["invocation_id"], {
            "status": "approved_executed", "executed_invocation_id": outcome.invocation_id}))
        await persist(lambda: self.audit.record(
            tenant_id, "approval.execution.completed", principal=actor, approval_id=approval_id,
            invocation_id=claimed.get("invocation_id"), status=outcome.status,
            metadata={"executed_invocation_id": outcome.invocation_id}))
        return "COMPLETED"

    def approval_result(self, doc: dict[str, Any]) -> dict[str, Any] | None:
        from app.core.ids import ensure_aware

        if doc.get("status") != "COMPLETED" or not doc.get("result_encrypted"):
            return None
        exp = ensure_aware(doc.get("result_expires_at"))
        if exp and exp <= utcnow():
            return {"expired": True}
        raw = self.encryptor.decrypt(doc["result_encrypted"], f"{doc['tenant_id']}:{doc['_id']}:result")
        return json.loads(raw)  # type: ignore[no-any-return]

    # ------------------------------------------------------------------ helpers
    async def _record_invocation(self, principal: Principal, inv_id: str, resource: dict[str, Any], decision: str,
                                 status: str, args_hash: str | None, error_code: str | None, started: float,
                                 ctx: InvocationContext, idempotency_key: str | None = None) -> None:
        doc = {
            "request_id": request_id_var.get(), "principal": principal.audit_ref(),
            "tool_id": resource.get("tool_id"), "tool_name": resource.get("tool_name"),
            "gateway_name": resource.get("gateway_name"), "server_id": resource.get("server_id"),
            "server_name": resource.get("server_name"), "risk_level": resource.get("risk_level"),
            "decision": decision, "status": status, "input_hash": args_hash, "output_hash": None,
            "duration_ms": int((time.perf_counter() - started) * 1000), "error_code": error_code,
            "source": ctx.source, "approval_id": ctx.approval_id,
        }
        if idempotency_key:
            doc["idempotency_key"] = idempotency_key
        existing = await self.repos.invocations.get(principal.tenant_id, inv_id)
        if existing:
            await self.repos.invocations.update(principal.tenant_id, inv_id, {
                k: v for k, v in doc.items() if v is not None or k in ("error_code",)})
        else:
            await self.repos.invocations.insert(principal.tenant_id, {**doc, "_id": inv_id})
        tool_id = resource.get("tool_id")
        if status in ("rejected", "pending_approval") and tool_id:
            await self.repos.usage.increment(principal.tenant_id, utcnow().strftime("%Y-%m-%dT%H"),
                                             principal.principal_id, tool_id, status)

    async def _finish(self, principal: Principal, inv_id: str, resource: dict[str, Any], status: str,
                      started: float, ctx: InvocationContext, *, error_code: str | None = None,
                      output_hash: str | None = None, policy_ids: list[str] | None = None,
                      args_hash: str | None = None, event: str | None = None,
                      extra_meta: dict[str, Any] | None = None) -> None:
        duration = int((time.perf_counter() - started) * 1000)
        await self.repos.invocations.update(principal.tenant_id, inv_id, {
            "status": status, "output_hash": output_hash, "duration_ms": duration, "error_code": error_code,
            "completed_at": utcnow()})
        await self.audit.record(
            principal.tenant_id, event or ("tool.invocation.completed" if status in ("completed", "tool_error")
                                           else "tool.invocation.failed"),
            principal=principal, invocation_id=inv_id, approval_id=ctx.approval_id, resource=resource,
            decision="ALLOW", policy_ids=policy_ids or [], status="success" if status == "completed" else status,
            duration_ms=duration, input_hash=args_hash, output_hash=output_hash, reason_code=error_code,
            metadata={"source": ctx.source, **(extra_meta or {})})
        if resource.get("tool_id"):
            await self.repos.usage.increment(principal.tenant_id, utcnow().strftime("%Y-%m-%dT%H"),
                                             principal.principal_id, resource["tool_id"], status,
                                             units=int(await self._tool_cost(principal.tenant_id,
                                                                              resource["tool_id"])))

    async def _tool_cost(self, tenant_id: str, tool_id: str) -> int:
        t = await self.repos.tools.get(tenant_id, tool_id)
        return int(((t or {}).get("limits") or {}).get("cost_units") or 1)
