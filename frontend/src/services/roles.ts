/** Mirrors backend role groups in app/core/identity.py. Used only to hide controls; the API enforces access. */
export const ADMINS = ['platform_admin', 'tenant_admin']
export const SECURITY = ['platform_admin', 'security_admin', 'tenant_admin']
export const REGISTRY_WRITE = ['platform_admin', 'tenant_admin', 'developer']
export const AUDIT_READ = ['platform_admin', 'security_admin', 'tenant_admin', 'auditor']
export const APPROVERS = ['platform_admin', 'security_admin', 'tenant_admin', 'approver']
