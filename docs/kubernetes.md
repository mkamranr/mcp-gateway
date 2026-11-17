# Kubernetes (Helm)

The Helm chart in `deploy/helm/mcp-gateway` runs the same images as Docker Compose:

| Workload | Kind | Default |
|---|---|---|
| API | Deployment + Service, PodDisruptionBudget, optional HorizontalPodAutoscaler | 2 replicas |
| Worker | Deployment | 1 replica (more are safe) |
| Web UI (nginx: console, `/api`, `/mcp`) | Deployment + Service, optional Ingress | 2 replicas |
| MongoDB, Redis | StatefulSets with persistent volumes | bundled single instances; turn off for external |

Requires Kubernetes 1.27 or later and Helm 3.

Verified in CI on a kind cluster (`kubernetes` job, started by hand like the other integration jobs):
- **Install:** into a namespace that enforces the **restricted** Pod Security Standard, then `helm test`.
- **Checks through the web UI:** the full Compose smoke test (sign-in, CSRF, security headers) and the SCIM
  check.
- **Agent mTLS:** the listener refuses a client with no certificate, and passes a valid one through to the gateway.
- **Network policies:** an unrelated pod can't reach the API, MongoDB or Redis.
- **Rolling restart:** of the API and worker without failed requests.
- **Generated Secret:** unchanged by `helm upgrade` and kept on `helm uninstall`.

## Security defaults

- **Pod Security:** every pod meets the *restricted* standard. That means non-root, a read-only root filesystem,
  all capabilities dropped, no privilege escalation and the `RuntimeDefault` seccomp profile.
- **Service accounts:** tokens are not mounted, because the gateway never calls the Kubernetes API.
- **Secrets:** mounted as files (mode 0440) and read through `*_FILE`, never through environment variables.
  Redis reads its password from a file, so it never appears on a command line.
- **Network policies (ingress):**
  - MongoDB and Redis accept only the API and the worker.
  - The API accepts only the web UI.
  - The worker accepts nothing.
  - The web UI accepts anyone by default; restrict it with `networkPolicy.webIngressFrom`.
  
  Egress stays open, because the API and worker reach your upstream MCP servers and identity provider. Restrict
  egress with your own policies or an egress gateway if you can list the upstreams. Policies only work if your
  network plugin enforces them (Calico, Cilium and most managed offerings do).

## Install

### 1. Images

Every image comes from the offline bundle (`deploy/offline/save-images.sh`): `mcp-gateway/backend`,
`mcp-gateway/web-ui`, `mongo` and `redis`. Load it on a connected host, push to your registry, and set
`global.imageRegistry`:

```bash
docker load -i images.tar.gz
for i in mcp-gateway/backend:0.1.0 mcp-gateway/web-ui:0.1.0 mongo:7.0.14 redis:7.4.1-alpine; do
  docker tag "$i" registry.corp.example/mgw/$i && docker push registry.corp.example/mgw/$i
done
```

### 2. Secret

Recommended: create it once and keep it in your secret store.

```bash
kubectl create namespace mcp-gateway
kubectl label namespace mcp-gateway pod-security.kubernetes.io/enforce=restricted
./deploy/helm/create-secret.sh mcp-gateway mgw          # namespace, release name
```

This uses the same generator as Compose. It writes the files to `./secrets-k8s-mcp-gateway-mgw/` and creates the
Secret `mcp-gateway-secrets`. Move the files to your secret store and delete the folder. **Back up
`data_encryption_key` and `api_key_hash_pepper`.** Without them, stored upstream secrets can't be decrypted and
every agent key stops working.

With external databases, put your connection strings in `mongodb_uri` and `redis_url` before running the
script; the formats are in [high availability](high-availability.md). With External Secrets, Vault or Sealed
Secrets, create a Secret with the same keys yourself:

| Key | |
|---|---|
| `session_secret`, `api_key_hash_pepper` | random, 48+ bytes |
| `data_encryption_key` | 32 random bytes, urlsafe base64 |
| `bootstrap_admin_password` | the first administrator's password |
| `mongodb_uri`, `redis_url` | connection strings |
| `mongo_root_password`, `redis_password` | only for the bundled databases (they must match the strings above) |

**Generated instead:** `--set secrets.generate=true` creates the Secret at the first install. The chart reuses
it on upgrades and keeps it on uninstall. Don't use it with tools that render without access to the cluster
(`helm template`, Argo CD, Flux): every render would produce new keys.

### 3. Values

```yaml
# values-prod.yaml
global:
  imageRegistry: registry.corp.example/mgw
secrets:
  existingSecret: mcp-gateway-secrets
ingress:
  enabled: true
  className: nginx
  host: mcp-gateway.corp.example
  tls: { enabled: true, secretName: mcp-gateway-tls }
  annotations:
    nginx.ingress.kubernetes.io/proxy-buffering: "off"       # stream MCP responses
    nginx.ingress.kubernetes.io/proxy-read-timeout: "330"
    nginx.ingress.kubernetes.io/proxy-body-size: 2m
web:
  realIpFrom: [10.244.0.0/16]     # the ingress controller pods: the gateway then sees real client addresses
networkPolicy:
  webIngressFrom:
    - namespaceSelector: { matchLabels: { kubernetes.io/metadata.name: ingress-nginx } }
config:
  UPSTREAM_HOST_ALLOWLIST: "hr-mcp.corp.example,finance-mcp.corp.example"
```

```bash
helm install mgw deploy/helm/mcp-gateway -n mcp-gateway -f values-prod.yaml --wait
helm test mgw -n mcp-gateway
```

`publicBaseUrl` defaults to `https://<ingress.host>`. Set it explicitly when TLS ends somewhere else. Any setting
from `.env.example` can go under `config`. All values are documented in
[`values.yaml`](../deploy/helm/mcp-gateway/values.yaml).

Without `web.realIpFrom`, the gateway sees the ingress controller's address as the client. Sign-in throttling and
the audit log then can't tell clients apart.

## Production topology

The bundled MongoDB and Redis are single instances, fine for evaluations and small sites. For production:

```yaml
mongodb: { enabled: false }
redis: { enabled: false }
```

Use a MongoDB replica set (`w=majority`) and Redis with Sentinel. These can be your platform's operators or
managed services, as long as they're reachable from the namespace. Put their URIs in the Secret. Then scale the
API (`api.replicaCount`, or `api.autoscaling.enabled`) and the worker. The behaviour during failover is the same
as in [high availability](high-availability.md).

## Agent mTLS

```yaml
mtls:
  enabled: true
  existingSecret: mgw-mtls          # server.crt, server.key, agent-ca.pem
  trustedProxies: 10.244.0.0/16     # the pod network the web UI pods run in
  service: { type: LoadBalancer }
```

The web UI then has a second listener on 8443. It requires a client certificate from `agent-ca.pem` and serves
only the agent endpoints. Expose it with a **TCP** (layer 4) load balancer, never through a TLS-terminating
ingress. The chart refuses `mtls.enabled` without network policies. `trustedProxies` covers the whole pod range,
so the policy restricting the API to the web UI is what keeps other pods from forging the certificate header. See
[mtls.md](mtls.md).

## Operations

- **Upgrades:** `helm upgrade` with the new image tag. API and web UI roll with `maxUnavailable: 0`, and database
  indexes are created at startup, so there's no migration step. Read the release notes first.
- **Backups:** back up MongoDB with your platform's tooling (volume snapshots, or `mongodump` through
  `kubectl exec`), and keep the Secret in your secret store. Restoring the data without the same
  `data_encryption_key` leaves stored secrets unreadable. After a restore, run
  `kubectl exec deploy/mgw-mcp-gateway-api -- python -m app.tools.verify_data` to check that every secret
  decrypts ([operations](operations.md)).
- **Logs:** JSON on stdout, for your cluster's log collector. Ship the audit log with
  [SIEM forwarding](siem.md).
- **Uninstall:** `helm uninstall` keeps the volumes (PersistentVolumeClaims) and a chart-generated Secret. Delete
  them yourself to remove all data.
