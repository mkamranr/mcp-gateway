import pathlib
def sub(path, old, new):
    p = pathlib.Path(path); s = p.read_text(encoding="utf-8")
    assert s.count(old) == 1, (path, old[:60])
    p.write_text(s.replace(old, new), encoding="utf-8")
sub("backend/app/main.py", """        log.info("gateway.started", env=settings.app_env, version=settings.app_version)""",
    """        log.info("gateway.started", env=settings.app_env, version=settings.app_version,
                 kms_wrapped=settings.kms_wrapped or None)""")
O = "backend/app/api/v1/observability.py"
sub(O, """            "security": {"default_deny": True, "audit_required_for_execution": s.audit_required_for_execution,
                         "allow_private_upstream_networks": s.allow_private_upstream_networks},""",
    """            "security": {"default_deny": True, "audit_required_for_execution": s.audit_required_for_execution,
                         "allow_private_upstream_networks": s.allow_private_upstream_networks,
                         "key_management": _key_management(s)},""")
sub(O, """@router.get("/settings")""", """def _key_management(s: Any) -> dict[str, Any]:
    \"\"\"Which secrets the key service unwrapped at startup, and the (non-secret) key service settings.\"\"\"
    from app.core import kms

    wrapped = s.kms_wrapped
    return {"wrapped": wrapped, **(kms.KmsConfig.from_env().describe() if wrapped else {"provider": None})}


@router.get("/settings")""")
T = "frontend/src/services/types.ts"
sub(T, "    security: { default_deny: boolean; audit_required_for_execution: boolean; allow_private_upstream_networks: boolean }",
    "    security: {\n      default_deny: boolean; audit_required_for_execution: boolean; allow_private_upstream_networks: boolean\n      key_management?: { provider: 'vault' | 'command' | null; wrapped: string[]; address?: string; key?: string; mount?: string; namespace?: string | null; auth?: string; command?: string | null }\n    }")
S = "frontend/src/features/settings/SettingsPage.tsx"
sub(S, """    <Callout>Secrets, encryption keys and peppers are configured only through environment variables or mounted secret files. They are never shown here.</Callout>
  </Panel>""", """    <KeyManagement km={s.security.key_management} />
    <Callout>Secrets, encryption keys and peppers are configured only through environment variables or mounted secret files. They are never shown here.</Callout>
  </Panel>""")
p = pathlib.Path(S); s = p.read_text(encoding="utf-8")
s = s.rstrip("\n") + """

const KEY_LABELS: Record<string, string> = { data_encryption_key: 'data encryption key', api_key_hash_pepper: 'API key pepper', session_secret: 'session secret' }

function KeyManagement({ km }: { km?: Settings['system']['security']['key_management'] }) {
  if (!km?.provider) return <div className="toggle-row"><span>Keys protected by a key service (KMS / HSM)</span><Badge color="orange">no: keys are in secret files</Badge></div>
  const where = km.provider === 'vault' ? `Vault Transit key ${km.key} at ${km.address}${km.namespace ? ` (namespace ${km.namespace})` : ''}, ${km.auth} auth` : `external command ${km.command ?? ''}`
  return <div className="toggle-row"><span>Keys protected by a key service: {km.wrapped.map(w => KEY_LABELS[w] || w).join(', ')}<div className="muted" style={{ fontSize: 10, marginTop: 3 }}>{where}</div></span><Badge color="green">{km.provider === 'vault' ? 'Vault' : 'command'}</Badge></div>
}
"""
p.write_text(s, encoding="utf-8")
