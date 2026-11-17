# Key management: KMS and HSM

The gateway's three master secrets can be protected by an external key service instead of sitting in plain
files:

| Secret | Protects |
|---|---|
| `DATA_ENCRYPTION_KEY` | AES-256-GCM encryption of upstream credentials, approval arguments and results, and the SSO and SIEM secrets |
| `API_KEY_HASH_PEPPER` | the HMAC that stores agent keys and the SCIM token |
| `SESSION_SECRET` | console sessions |

## How it works: envelope encryption

```
secret file:  mgw-kms:v1:vault:vault:v1:8SDd3WHDOjf7mq69...   (wrapped value)
                      │
startup ──────────────┴──▶ key service: decrypt with the key-encryption key (KEK)
                                      │  (Vault Transit, AWS KMS, Cloud HSM, an on-prem HSM, ...)
                                      ▼
                         plain value, kept in process memory only
```

- **What's stored:** the secret files, `.env`, Kubernetes Secrets and backups hold only **wrapped** values,
  encrypted under a key-encryption key that never leaves the key service. A copy of them is useless without
  access to the key service.
- **One call at startup:** each wrapped value is unwrapped once when a process starts. The key service is not
  called per request, so a key-service outage doesn't affect a running gateway, only processes starting during
  it.
- **Crypto-shredding:** destroying or disabling the KEK makes the data permanently unreadable, including every
  backup.
- **Adoption:** plain values keep working, so you can wrap one secret at a time. Wrap at least
  `DATA_ENCRYPTION_KEY` and `API_KEY_HASH_PEPPER`.
- **What it doesn't protect against:** the keys are plain inside the running processes. Someone who can read a
  gateway process's memory, or run code in its container, can read them. A KMS doesn't change that for any
  application that decrypts locally.

**Settings → Security** shows which secrets were unwrapped and by which key service. The startup log lists the
same (`kms_wrapped=[...]`), never values.

## Providers

### HashiCorp Vault Transit

The KEK is a transit key in Vault. Vault can itself be backed by an HSM (Vault Enterprise seal wrap or managed
keys), so this is also the way to an on-premises HSM.

```bash
vault secrets enable transit
vault write -f transit/keys/mgw-kek            # aes256-gcm96, not exportable
vault policy write mcp-gateway - <<'EOF'
path "transit/decrypt/mgw-kek" { capabilities = ["update"] }
EOF
# Operators who wrap and rotate also need transit/encrypt/mgw-kek and transit/rewrap/mgw-kek.
```

| Variable | |
|---|---|
| `KMS_PROVIDER` | `vault` |
| `VAULT_ADDR` | `https://vault.corp.example:8200`. https only; `http://` needs `KMS_ALLOW_INSECURE_HTTP=true` and is refused in production. |
| `VAULT_TRANSIT_KEY` | `mgw-kek` |
| `VAULT_TRANSIT_MOUNT` | default `transit` |
| `VAULT_NAMESPACE` | Vault Enterprise namespace, if any |
| `VAULT_CA_BUNDLE_FILE` | PEM bundle when Vault's certificate is from an internal CA |
| **Authentication**, one of: | |
| `VAULT_TOKEN_FILE` | a token (periodic, with only the policy above) |
| `VAULT_APPROLE_ROLE_ID` + `VAULT_APPROLE_SECRET_ID_FILE` | AppRole (`VAULT_APPROLE_MOUNT`, default `approle`) |
| `VAULT_K8S_ROLE` | Kubernetes auth with the pod's service account token (`VAULT_K8S_MOUNT`, default `kubernetes`; `VAULT_K8S_TOKEN_PATH`) |

Unreachable, sealed or standby Vault answers are retried three times; then the process doesn't start.
Permission errors fail at once with Vault's message, which contains no key material.

### Any KMS or HSM: `command`

The gateway runs a program you provide: the wrapped value on stdin, the plain value on stdout. Use your cloud
provider's CLI, an HSM vendor tool or a script. There's no shell: the command is a JSON list or shell-style words.

| Variable | |
|---|---|
| `KMS_PROVIDER` | `command` |
| `KMS_UNWRAP_COMMAND` | e.g. `["/opt/mgw/aws-kms.sh", "unwrap"]` |
| `KMS_WRAP_COMMAND` | for `python -m app.tools.kms generate`, `wrap` and `rewrap` |
| `KMS_COMMAND_TIMEOUT_SECONDS` | default 30 |

A non-zero exit code, an empty answer or a timeout stops startup. The error names the exit code, never the
program's output, which could echo its input.

Examples, untested here: [`deploy/kms/aws-kms.sh`](../deploy/kms/aws-kms.sh) (AWS KMS, with an encryption context)
and [`deploy/kms/gcp-kms.sh`](../deploy/kms/gcp-kms.sh) (Google Cloud KMS and Cloud HSM). For Azure Key Vault or a
PKCS#11 HSM, use the vendor's CLI the same way (`az keyvault key decrypt`, `pkcs11-tool`, Thales or Entrust
tools). The images don't contain these CLIs: build a derived image, and check the result with
`python -m app.tools.kms check`.

The gateway has no built-in PKCS#11 client. Reach an HSM through Vault or through `command`.

## Wrapping the secrets

Run the tool where the gateway runs, so it has the same `KMS_*` and `VAULT_*` settings.

**New installation:** generate the secrets already wrapped, so the plain value never touches a disk.

```bash
docker compose run --rm --no-deps -T gateway-api python -m app.tools.kms generate data_encryption_key \
  > secrets/data_encryption_key
docker compose run --rm --no-deps -T gateway-api python -m app.tools.kms generate api_key_hash_pepper \
  > secrets/api_key_hash_pepper
docker compose run --rm --no-deps -T gateway-api python -m app.tools.kms generate session_secret \
  > secrets/session_secret
```

**Existing installation:** wrap the current values. They stay the same, so stored data, agent keys and sessions
keep working.

```bash
for s in data_encryption_key api_key_hash_pepper session_secret; do
  docker compose run --rm --no-deps -T gateway-api python -m app.tools.kms wrap < secrets/$s > secrets/$s.wrapped
done
# Each .wrapped file must show the same fingerprint as its plain file:
docker compose run --rm --no-deps -T -v "$PWD/secrets:/w:ro" gateway-api python -m app.tools.kms check \
  /w/data_encryption_key /w/data_encryption_key.wrapped /w/api_key_hash_pepper /w/api_key_hash_pepper.wrapped \
  /w/session_secret /w/session_secret.wrapped
for s in data_encryption_key api_key_hash_pepper session_secret; do mv secrets/$s.wrapped secrets/$s; done
docker compose up -d
```

Then **destroy the plain copies everywhere**: old backups of the `secrets/` folder, password managers and
deployment pipelines. Until you do, the plain key still exists outside the key service.

`check` prints a fingerprint (the first 12 hex digits of a SHA-256) for each file, wrapped or plain. Compare
fingerprints to confirm that a wrapped file holds the same value as the plain one, without printing either.

On Kubernetes, put the wrapped values in the Secret (`deploy/helm/create-secret.sh` reads the files) and pass the
settings through `api.extraEnv` and `worker.extraEnv`. For Vault Kubernetes auth, mount a service account token,
since the chart doesn't mount one by default:

```yaml
api:
  extraEnv:
    - { name: KMS_PROVIDER, value: vault }
    - { name: VAULT_ADDR, value: "https://vault.corp.example:8200" }
    - { name: VAULT_TRANSIT_KEY, value: mgw-kek }
    - { name: VAULT_K8S_ROLE, value: mcp-gateway }
    - { name: VAULT_K8S_TOKEN_PATH, value: /var/run/secrets/vault/token }
  extraVolumes:
    - name: vault-token
      projected:
        sources: [{ serviceAccountToken: { path: token, expirationSeconds: 3600, audience: vault } }]
  extraVolumeMounts:
    - { name: vault-token, mountPath: /var/run/secrets/vault, readOnly: true }
worker:   # the same extraEnv, extraVolumes and extraVolumeMounts
```

## Rotation

- **The key-encryption key:** rotate it in the key service (`vault write -f transit/keys/mgw-kek/rotate`), then
  re-encrypt the wrapped values under the new version:
  `python -m app.tools.kms rewrap < secrets/data_encryption_key > new` (for each secret), replace the files and
  restart. The secrets themselves don't change, so nothing in MongoDB is touched. Afterwards retire the old KEK
  version (`min_decryption_version`). Values wrapped under it, including old backups of the secret files, then
  can't be unwrapped.
- **The data encryption key itself:** as before, with `python -m app.tools.rotate_encryption_key`
  ([operations](operations.md)). Both key files may be wrapped.

## Revocation and incidents

- **Stop a compromised deployment:** revoke its Vault token or AppRole, or remove its access to the KMS key. Its
  processes can't start again. Running processes keep the keys in memory until they stop, so restart or stop
  them as well.
- **Destroy the data:** destroy the KEK (or, with Vault, every version of it). Every copy of the data, backups
  included, becomes unreadable. This can't be undone.
- **Disaster recovery:** a restore needs the wrapped secret files *and* access to the same KEK. Test it: restore
  into an isolated environment and run `python -m app.tools.verify_data`.

## Audit

The key service's own audit log records every unwrap (one per process start) and every wrap. Ship it to your
SIEM next to the gateway's. An unwrap that doesn't match a gateway restart is worth investigating.
