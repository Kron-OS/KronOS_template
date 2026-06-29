.PHONY: dev dev-detach dev-down logs shell-backend shell-postgres reset-db \
        test test-integration lint typecheck format \
        frontend-dev frontend-build frontend-lint \
        helm-lint helm-template helm-install-dev helm-install-prod \
        build push clean clean-cache

# ── Development ──────────────────────────────────────────────────────────────

dev:
	docker compose -f docker/docker-compose.dev.yml up

dev-detach:
	docker compose -f docker/docker-compose.dev.yml up -d

dev-down:
	docker compose -f docker/docker-compose.dev.yml down

logs:
	docker compose -f docker/docker-compose.dev.yml logs -f

logs-backend:
	docker compose -f docker/docker-compose.dev.yml logs -f kronos-backend

shell-backend:
	docker compose -f docker/docker-compose.dev.yml exec kronos-backend bash

shell-postgres:
	docker compose -f docker/docker-compose.dev.yml exec postgres \
		psql -U kronos -d kronos

reset-db:
	docker compose -f docker/docker-compose.dev.yml exec postgres \
		psql -U kronos -d kronos -c \
		"DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

seed-data:
	docker compose -f docker/docker-compose.dev.yml exec kronos-backend \
		python -m src.external.seed_dev_data

# ── Testing ───────────────────────────────────────────────────────────────────

test:
	source ~/venv/bin/activate && \
	python -m pytest tests/unit/ -v --tb=short \
		--cov=src --cov-report=term-missing --cov-fail-under=80

test-fast:
	source ~/venv/bin/activate && python -m pytest tests/unit/ -q

test-integration:
	docker compose -f docker/docker-compose.test.yml up -d && \
	source ~/venv/bin/activate && \
	python -m pytest tests/integration/ -v --tb=short; \
	docker compose -f docker/docker-compose.test.yml down

# ── Code quality ──────────────────────────────────────────────────────────────

lint:
	source ~/venv/bin/activate && ruff check src/ tests/

typecheck:
	source ~/venv/bin/activate && mypy src/ --ignore-missing-imports

format:
	source ~/venv/bin/activate && black src/ tests/

format-check:
	source ~/venv/bin/activate && black --check src/ tests/

check: lint typecheck format-check test

# ── Frontend ──────────────────────────────────────────────────────────────────

frontend-dev:
	cd frontend && npm run dev

frontend-build:
	cd frontend && npm run build

frontend-lint:
	cd frontend && npm run lint

frontend-test:
	cd frontend && npm test

# ── Helm ──────────────────────────────────────────────────────────────────────

helm-lint:
	helm lint charts/kronos/

helm-template:
	helm template kronos charts/kronos/ --debug

helm-install-dev:
	helm upgrade --install kronos charts/kronos/ \
		--namespace kronos --create-namespace \
		--values charts/kronos/values-dev.yaml \
		--wait

helm-install-prod:
	helm upgrade --install kronos charts/kronos/ \
		--namespace kronos --create-namespace \
		--values charts/kronos/values.yaml \
		--wait

helm-uninstall:
	helm uninstall kronos --namespace kronos

# ── Build ─────────────────────────────────────────────────────────────────────

build:
	docker build -t kronos-backend:dev -f docker/Dockerfile .

push:
	docker push ghcr.io/kron-os/kronos-backend:$(shell git rev-parse --short HEAD)

# ── CLI ───────────────────────────────────────────────────────────────────────

attest-verify-day:
	source ~/venv/bin/activate && \
	python -m kronos_attest.cli verify-day --help

attest-verify-case:
	source ~/venv/bin/activate && \
	python -m kronos_attest.cli verify-case --help

# ── Cleanup ───────────────────────────────────────────────────────────────────

# Full reset of the dev stack: stop containers, delete the compose named volumes
# (postgres/minio/opensearch/clamav/step-ca data) and the default network, drop
# orphan containers, then rebuild all images from scratch. Use this after a
# schema or realm change that left stale state behind. WARNING: deletes all
# local dev data in those volumes.
clean: clean-cache
	docker compose -f docker/docker-compose.dev.yml down --volumes --remove-orphans
	docker compose -f docker/docker-compose.dev.yml build --no-cache

# Local build artefacts and Python/tool caches only (no Docker side effects).
clean-cache:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf frontend/dist frontend/node_modules/.vite 2>/dev/null || true
