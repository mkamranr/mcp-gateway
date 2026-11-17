# MCP-Gateway developer tasks. Requires uv (Python 3.12) and Node 22.12+ (Vite 8). Docker is only needed for compose/release.
.PHONY: help install dev dev-ui test test-fast lint fmt typecheck build check secrets up down logs release sbom

help:
	@echo "install    install backend (uv) and frontend (npm ci) dependencies"
	@echo "dev        run the no-Docker dev stack (mongod + fakeredis + mock MCP + API + worker)"
	@echo "dev-ui     run the Vite dev server (proxies /api and /mcp to :8080)"
	@echo "test       backend test suite"
	@echo "lint       ruff + frontend typecheck"
	@echo "typecheck  mypy + tsc"
	@echo "build      production frontend build"
	@echo "check      lint + typecheck + test + build"
	@echo "secrets    generate ./secrets for docker compose"
	@echo "up/down    docker compose up -d / down"
	@echo "release    build air-gap bundle (deploy/offline/save-images.sh)"
	@echo "sbom       CycloneDX SBOMs into ./sbom"

install:
	cd backend && uv sync --frozen
	cd frontend && npm ci

dev:
	cd backend && uv run python -m devtools.dev_stack

dev-ui:
	cd frontend && npm run dev

test:
	cd backend && uv run pytest tests -q

test-fast:
	cd backend && uv run pytest tests/unit -q

lint:
	cd backend && uv run ruff check app devtools tests
	cd frontend && npm run typecheck

fmt:
	cd backend && uv run ruff format app devtools tests && uv run ruff check --fix app devtools tests

typecheck:
	cd backend && uv run mypy app
	cd frontend && npm run typecheck

build:
	cd frontend && npm run build

check: lint typecheck test build

secrets:
	sh deploy/scripts/generate-secrets.sh

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=200

release:
	sh deploy/offline/save-images.sh

sbom:
	sh deploy/scripts/sbom.sh
