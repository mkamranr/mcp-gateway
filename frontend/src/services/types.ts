export type Risk = 'low' | 'medium' | 'high' | 'critical'

export interface Page<T> { items: T[]; next_cursor: string | null; total: number }

export interface TenantRef { id: string; name: string; slug: string; status: string }

export interface Me {
  principal_type: 'user' | 'agent'
  principal_id: string
  tenant_id: string
  display_name: string
  roles: string[]
  scopes: string[]
  is_platform_admin: boolean
  tenants: TenantRef[]
  environment: string
  version: string
  csrf_token?: string | null
  must_change_password?: boolean
  auth_source?: 'local' | 'oidc'
}

export interface SsoPublicConfig { enabled: boolean; display_name: string; local_login: 'enabled' | 'break_glass_only' }
export interface SsoGroupRule { group: string; tenant_id: string; roles: string[] }
export interface SsoConfig {
  enabled: boolean; display_name: string; issuer: string; client_id: string
  token_auth_method: 'client_secret_basic' | 'client_secret_post'; scopes: string[]; allowed_algorithms: string[]
  username_claim: string; email_claim: string; name_claim: string; groups_claim: string
  group_rules: SsoGroupRule[]; platform_admin_groups: string[]; jit_provisioning: boolean; link_local_accounts: boolean
  local_login: 'enabled' | 'break_glass_only'; break_glass_usernames: string[]
  has_client_secret: boolean; redirect_uri: string; updated_at: string | null; updated_by: string | null
}
export interface SsoTestResult {
  ok: boolean; error?: string; detail?: string; authorization_endpoint?: string; token_endpoint?: string
  userinfo_endpoint?: string | null; end_session_endpoint?: string | null; signing_keys?: number
  signing_algorithms?: string[]; algorithm_overlap?: string[] | null
}

export interface CertInfo {
  fingerprint_sha256: string; subject: string; issuer: string; serial: string
  not_before: string; not_after: string; sans: string[]
}

export interface HealthEntry { at: string; status: string; latency_ms: number; error: string | null }

export interface Server {
  id: string; tenant_id: string; name: string; alias: string; description: string
  transport: 'streamable_http' | 'stdio'; endpoint: string | null; command: string | null; args: string[]
  env_keys: string[]; cwd: string | null; verify_tls: boolean; enabled: boolean; archived: boolean
  environment: string; tags: string[]; owner: string | null; authentication_mode: string; has_secret: boolean
  connection_timeout_seconds: number; request_timeout_seconds: number; max_concurrent_calls: number
  allow_private_network: boolean; health_status: string; last_health_check_at: string | null
  last_health_error: string | null; last_latency_ms: number | null; health_history: HealthEntry[]
  discovery: { status?: string; at?: string; error?: string; summary?: Record<string, number> }
  tool_count: number; enabled_tool_count: number; version: number
  tls?: { ca_certificates: CertInfo[]; client_certificate: CertInfo | null }
  created_at: string; updated_at: string; created_by: string; updated_by: string
}

export interface ApprovalPolicyConfig {
  required_approvals: 1 | 2; approver_roles: string[]; allow_self_approval: boolean; ttl_minutes: number
  require_comment_on_reject: boolean; require_comment_on_approve: boolean
  approver_groups?: string[]; escalate_after_minutes?: number | null; escalation_roles?: string[]
  remind_before_expiry_minutes?: number | null
}

export interface Tool {
  id: string; tenant_id: string; server_id: string; server_name: string | null; upstream_name: string
  gateway_name: string; display_name: string; description: string; upstream_description: string
  input_schema: Record<string, unknown>; output_schema: Record<string, unknown> | null
  schema_hash: string; schema_version: number; risk_level: Risk | null; enabled: boolean
  review_status: 'pending_review' | 'approved' | 'schema_changed'; available: boolean
  approval: { required: boolean; policy: ApprovalPolicyConfig }
  timeout_seconds: number | null; max_input_bytes: number | null; max_output_bytes: number | null
  limits: { per_minute?: number | null; per_hour?: number | null; per_day?: number | null; per_month?: number | null; concurrency?: number | null; cost_units?: number }
  output: { validate_output: boolean; redact_fields: string[] }
  tags: string[]; owner: string | null; last_discovered_at: string | null; version: number
  calls_7d?: number
  policies?: { id: string; name: string; effect: string; enabled: boolean; priority: number; principals: PolicyPrincipals }[]
}

export interface PolicyPrincipals { types: string[]; ids: string[]; roles: string[] }
export interface PolicyResources { servers: string[]; tools: string[]; risk_levels: Risk[] }
export interface PolicyConstraints {
  environments: string[]; max_calls_per_minute: number | null; max_calls_per_hour: number | null
  max_calls_per_day: number | null; require_approval: boolean; required_approvals: 1 | 2 | null
  approver_roles: string[] | null; approval_policy_id: string | null
  approver_groups: string[] | null; escalate_after_minutes: number | null; escalation_roles: string[] | null
  remind_before_expiry_minutes: number | null
  time_windows: { days: number[]; start: string; end: string }[]; source_cidrs: string[]
}

export interface Policy {
  id: string; tenant_id: string; scope: 'tenant' | 'global'; name: string; description: string
  effect: 'allow' | 'deny'; kind: string; system: boolean; principals: PolicyPrincipals
  resources: PolicyResources; actions: ('discover' | 'invoke')[]; constraints: PolicyConstraints
  priority: number; enabled: boolean; broad: string[]; version: number
  managed_by?: { kind: 'bundle'; bundle: string } | null
  created_by: string; updated_by: string; created_at: string; updated_at: string
}

export type BundleAction = 'create' | 'update' | 'adopt' | 'delete' | 'unchanged' | 'orphan'
export interface BundleIssue { policy: string; code: string; message: string }
export interface BundlePlan {
  bundle: string; scope: 'tenant' | 'global'; tenant_id: string; prune: boolean; valid: boolean
  errors: BundleIssue[]; warnings: BundleIssue[]; summary: Record<BundleAction, number>; fingerprint: string
  changes: { action: BundleAction; name: string; policy_id: string | null; broad?: string[]; diff: Record<string, { from: unknown; to: unknown }> }[]
  applied?: boolean
}

export interface Decision {
  decision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL'; reason_code: string; policy_ids: string[]
  obligations: Record<string, any>
  explanation: { policy_id: string; name: string; effect: string; matched: boolean; not_matched_on: string | null }[]
}

export interface Credential {
  id: string; name: string; principal_id: string; scopes: string[]
  type: 'api_key' | 'client_certificate'; key_prefix: string | null
  certificate: CertInfo | null; subject_name: string | null
  expires_at: string | null; revoked_at: string | null; last_used_at: string | null
  last_used_source: string | null; created_at: string; created_by: string; status: 'active' | 'revoked' | 'expired'
  secret?: string
}

export interface Agent {
  id: string; tenant_id: string; name: string; description: string; status: string
  owner_user_id: string | null; tags: string[]; environment: string; last_activity_at: string | null
  version: number; created_at: string; active_credentials?: number
  credentials?: Credential[]; recent_invocations?: Invocation[]
  policies?: { id: string; name: string; effect: string; enabled: boolean; priority: number }[]
  permitted_tools?: { id: string; gateway_name: string; risk_level: Risk }[]
}

export interface Invocation {
  id: string; request_id: string; principal: { type: string; id: string; name?: string }
  tool_id: string; tool_name: string; gateway_name: string; server_name: string; risk_level: Risk
  decision: string; status: string; duration_ms: number; error_code: string | null; created_at: string
}

export interface Approval {
  id: string; tenant_id: string; invocation_id: string; status: string
  requester: { type: string; id: string; name: string; credential_id?: string }
  agent_id: string; delegated_by_user_id: string | null; tool_id: string; tool_name: string; gateway_name: string
  server_id: string; server_name: string; risk_level: Risk; purpose: string | null; arguments_hash: string
  arguments_preview: unknown; policy_ids: string[]; approval_policy: Partial<ApprovalPolicyConfig> & { reasons?: string[] }
  required_approvals: number
  approvals: { approver_id: string; approver_name: string; at: string; comment: string; on_behalf_of?: string | null; on_behalf_of_name?: string | null }[]
  rejection: { by_name: string; at: string; comment: string; on_behalf_of_name?: string | null } | null; cancellation: { by: string; reason: string; at: string } | null
  expires_at: string; approved_at: string | null; executed_at: string | null; completed_at: string | null
  execution: { error_code?: string; message?: string; status?: string } | null; created_at: string
  arguments?: unknown; integrity?: string; changes_since_request?: string[]; related_invocations?: Invocation[]
  separation_of_duties_warning?: boolean; can_decide?: boolean; cannot_decide_reason?: string | null
  decide_as?: { on_behalf_of: string; on_behalf_of_name: string; delegation_id: string } | null
  escalate_at?: string | null; escalated_at?: string | null
}

export interface Delegation {
  id: string; tenant_id: string; status: 'active' | 'scheduled' | 'expired' | 'revoked'
  delegator_user_id: string; delegator_name: string; delegate_user_id: string; delegate_name: string
  starts_at: string; ends_at: string; reason: string; created_by: string; created_at: string
  revoked_at: string | null; revoked_by: string | null
}

export interface DelegateCandidate { id: string; username: string; display_name: string; can_approve: boolean }

export interface AuditEvent {
  id: string; event_id: string; tenant_id: string; timestamp: string; event_type: string; severity: string
  request_id: string | null; invocation_id: string | null; approval_id: string | null
  principal: { type: string; id: string | null; name?: string; credential_id?: string | null } | null
  delegated_by_user_id: string | null
  resource: Record<string, any>; decision: string | null; reason_code: string | null; policy_ids: string[]
  status: string | null; duration_ms: number | null; input_hash: string | null; output_hash: string | null
  metadata: Record<string, any>
  correlated?: AuditEvent[]; approval?: { id: string; status: string; approvals: any[]; rejection: any } | null
}

export interface TenantUser {
  membership_id: string; user_id: string; username: string; email: string | null; display_name: string
  roles: string[]; status: string; user_status: string; last_login_at: string | null; created_at: string
  auth_source?: 'local' | 'oidc'; managed_by?: 'manual' | 'oidc'
}

export interface Tenant { id: string; name: string; slug: string; status: string; settings: Record<string, any>; created_at: string }

export interface HealthComponent { name: string; status: string; last_heartbeat?: string | null; queue_depth?: number | null; workers_alive?: number }

export interface Overview {
  cards: { servers: number; servers_healthy: number; enabled_tools: number; total_tools: number; active_agents: number; calls_today: number; denied_today: number; pending_approvals: number }
  decisions: Record<string, number>
  series: { date: string; count: number; completed: number; failed: number; rejected: number; pending: number; tool_error: number }[]
  top_tools: { tool_id: string; gateway_name: string; count: number; completed: number; rejected: number }[]
  server_health: { id: string; name: string; status: string; enabled: boolean; latency_ms: number | null; last_check: string | null }[]
  recent: { id: string; at: string; principal: { name?: string; id: string }; tool: string; decision: string; status: string; duration_ms: number }[]
  health: HealthComponent[]
  approvals: { pending: number; oldest_pending_age_seconds: number }
}

export interface SiemConfig {
  enabled: boolean; transport: 'syslog_tcp' | 'syslog_tls' | 'syslog_udp' | 'http'
  host: string; port: number; syslog_facility: number
  url: string; http_body: 'ndjson' | 'json_array' | 'splunk_hec'; http_auth_header: string
  format: 'json' | 'cef'; min_severity: 'info' | 'warning' | 'high' | 'critical'; event_types: string[]
  tls_ca_pem: string; tls_verify_hostname: boolean; batch_size: number
  has_http_auth_value: boolean; updated_at: string | null; updated_by: string | null
}
export interface SiemStatus {
  enabled: boolean; cursor: string | null; lag_seconds: number | null; pending_events: number | null
  forwarded_total: number; last_success_at: string | null; last_error: string | null; last_error_at: string | null; failing: boolean
}
