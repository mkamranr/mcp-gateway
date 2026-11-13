# Air-Gapped Installation

The running system makes no outbound internet requests. The UI bundles every asset (no CDN), and the backend
downloads nothing at runtime. Only **building** needs internet access, which happens on a connected build host.

## 1. On the connected build host

Requirements: Docker, git, uv, Node 20 (for the SBOM step).

```bash
git clone <repo> mcp-gateway && cd mcp-gateway
make check                              # optional: run the full test suite and build
./deploy/scripts/sbom.sh                # CycloneDX SBOMs into ./sbom (included in the bundle)
./deploy/offline/save-images.sh 0.1.0   # builds images, pulls pinned third-party images
```

Output in `release/`:

```
mcp-gateway-0.1.0.tar.gz          the bundle
mcp-gateway-0.1.0.tar.gz.sha256   checksum for the transfer
mcp-gateway-0.1.0/
  images.tar.gz                   backend, web-ui, mongo:7.0.14, redis:7.4.1-alpine
  images.txt                      image name → image ID (verified on load)
  docker-compose.yml  .env.example  deploy/  sbom/
  SHA256SUMS                      checksums of every file in the bundle
```

Scan `images.tar.gz` and review the SBOMs according to your policy before transfer.

## 2. Transfer

Move `mcp-gateway-0.1.0.tar.gz` and its `.sha256` through your approved transfer process (data diode,
scanned media, …).

## 3. On the air-gapped host

```bash
sha256sum -c mcp-gateway-0.1.0.tar.gz.sha256
tar xzf mcp-gateway-0.1.0.tar.gz && cd mcp-gateway-0.1.0
./deploy/offline/load-images.sh            # verifies SHA256SUMS, docker load, checks image IDs
./deploy/scripts/generate-secrets.sh
cp .env.example .env && vi .env             # PUBLIC_BASE_URL, allowlists, limits
docker compose up -d --no-build --pull never
```

`--pull never` makes Compose fail instead of trying to reach a registry. Continue with the verification
checklist in [deployment.md](deployment.md#first-install-verification-checklist).

## Using an internal registry instead

Push the loaded images to your registry, then set `MGW_BACKEND_IMAGE` / `MGW_WEB_IMAGE` in `.env` and
change the `mongo`/`redis` image references to your registry, preferably by digest
(`registry.internal/mongo@sha256:…`).

## Updates

Repeat steps 1–3 with a new version. `docker compose up -d --no-build --pull never` replaces the containers.
Volumes and secrets are kept. Read the release notes for migration steps (indexes are created automatically).

## What was verified

The bundle scripts are POSIX shell and use only `docker`, `gzip`, `tar` and `sha256sum`. They were written
for this release, but there was no Docker host in the development environment, so they have not yet been run
end to end. Do a dry run in a staging enclave first.
