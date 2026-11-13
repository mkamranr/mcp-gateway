#!/usr/bin/env sh
# Generates CycloneDX SBOMs for the backend (from uv.lock) and the frontend (from package-lock.json)
# into ./sbom. Run on a connected build host. The tools run ephemerally and are not added to the project.
set -eu
mkdir -p sbom

( cd backend && uv export --frozen --no-dev --no-hashes --format requirements-txt > ../sbom/backend-requirements.txt )
uvx --from cyclonedx-bom cyclonedx-py requirements sbom/backend-requirements.txt \
  --output-format JSON --output-file sbom/backend.cdx.json

( cd frontend && npx --yes @cyclonedx/cyclonedx-npm --omit dev --output-format JSON --output-file ../sbom/frontend.cdx.json )

echo "SBOMs written to ./sbom"
