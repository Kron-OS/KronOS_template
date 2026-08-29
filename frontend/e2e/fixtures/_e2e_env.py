"""Shared KRONOS_E2E_* environment overrides for frontend/e2e/fixtures/*.py.

Milestone PPP: seed_detection.py (Milestone NNN) and seed_second_org.py
(Milestone OOO) each independently defined their own
`KEYCLOAK_INTERNAL_URL = os.environ.get("KRONOS_E2E_KEYCLOAK_URL", ...)`
line. That duplication is exactly what let Milestone OOO's real incident
happen: one sibling script got the override, the other didn't, for an
entire cycle, and the resulting "one script quietly still points at the
wrong stack" gap cost a real, extended false-positive-Keycloak-bug
debugging session (docs/GAP_AUDIT_2026-08-28_MILESTONE_OOO.md) before the
missing override -- not a Keycloak bug -- turned out to be the cause.

This module exists so a THIRD fixture script can't repeat that: import
`KEYCLOAK_INTERNAL_URL` (and `POSTGRES_DSN` if it needs Postgres) from
here instead of redefining the same `os.environ.get(...)` line.

Deliberately does NOT add a "verify this is the intended stack" runtime
assertion (e.g. probing a distinctive resource before proceeding): the
actual risk this override exists for -- a host running the real dev
stack and an isolated test-stack instance side by side, both publishing
Keycloak on the same unremapped host port -- is a local multi-stack-host
verification concern only. Real CI never runs two stacks at once, so
there is nothing to assert against there; adding one anyway would be
validating a scenario that can't happen in the only environment this
code ships to, which CLAUDE.md's own guidelines argue against. The fix
for the local-verification case is procedural (Milestone OOO's own
lesson: print the resolved constant and look at it before trusting an
override took effect), not a new runtime check baked into every fixture
script.
"""
from __future__ import annotations

import os

# Both docker-compose.dev.yml and .test.yml publish keycloak on host 8080
# unremapped, so this default is correct for either profile running
# alone. Overridable for local verification against an isolated,
# differently-port-mapped test-stack instance on a host that also has
# the real dev stack's own keycloak already holding 8080.
KEYCLOAK_INTERNAL_URL = os.environ.get("KRONOS_E2E_KEYCLOAK_URL", "http://localhost:8080")

# Only meaningful to scripts that touch Postgres directly (seed_detection.py;
# seed_second_org.py is Keycloak-Admin-API-only and doesn't import this).
# docker-compose.dev.yml and .test.yml use different passwords AND
# database names, so this cannot share a single hardcoded default the
# way KEYCLOAK_INTERNAL_URL does -- the dev-stack value is kept as the
# default for backward compatibility with every existing local/dev-stack
# invocation of seed_detection.py.
POSTGRES_DSN = os.environ.get(
    "KRONOS_E2E_POSTGRES_DSN",
    "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos",
)
