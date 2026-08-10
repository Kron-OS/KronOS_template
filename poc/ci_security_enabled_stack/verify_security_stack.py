"""Real verification that docker/docker-compose.test.yml's now-security-
enabled stack (Gap Audit P1-14 / V3) actually does what it claims:

  (a) OpenSearch's security plugin is genuinely enabled (not
      DISABLE_SECURITY_PLUGIN=true) and DLS/tenant-role provisioning
      genuinely works -- mirrors poc/keycloak_opensearch_dls/run_poc.py's
      own already-established real verification pattern, this time against
      the real docker-compose.test.yml file (2.13.0, not that PoC's 2.11.1)
      and the real production docker/keycloak/kronos-realm.json (not a
      throwaway PoC realm).
  (b) a real Keycloak instance with the real kronos-realm.json import and
      a real provisioned org ("kronos-test", created by the real
      keycloak-init service in docker-compose.test.yml) issues a real JWT
      that a real KronOS backend class (src/external/middleware/
      keycloak_auth.py's KeycloakTokenValidator, completely unmodified,
      never before exercised against a live Keycloak anywhere in this
      repo's test suite -- it's in pyproject.toml's coverage `omit` list
      for exactly that reason) can validate.
  (c) an equivalent-to-I1 tenant-isolation check: two real users in two
      real, different Keycloak Organizations ("kronos-test" from the
      shipped keycloak-init service, and "kronos-ci-org-b" from this
      directory's provision_ci_org_b.py) each see ONLY their own org's
      documents through OpenSearch's real DLS enforcement -- something
      that could not even be expressed against the old
      DISABLE_SECURITY_PLUGIN=true stack (no security plugin, no DLS,
      no tenant isolation at all).

This script is intentionally poc/-resident (CLAUDE.md §F.3) and imports
src/ + framework libraries directly; tests/integration/
test_security_enabled_stack.py carries a slimmed, pytest-shaped version of
the same real checks for CI wiring.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import httpx  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.external.middleware.keycloak_auth import KeycloakTokenValidator  # noqa: E402

KC_PORT = os.environ.get("CISEC_KC_PORT", "18080")
OS_PORT = os.environ.get("CISEC_OS_PORT", "19200")
KC_BASE = f"http://localhost:{KC_PORT}"
OS_URL = f"https://localhost:{OS_PORT}"
REALM = "kronos"
TOKEN_URL = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/token"
JWKS_URL = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect/certs"
CI_CLIENT_ID = "kronos-ci-verifier"

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def password_grant(username: str, password: str) -> str:
    resp = httpx.post(
        TOKEN_URL,
        data={
            "client_id": CI_CLIENT_ID,
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        timeout=15.0,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def search_as(token: str, index: str) -> dict:
    with httpx.Client(
        verify=False
    ) as h:  # noqa: S501 - self-signed demo cert, same as prod's verify_certs=False
        resp = h.get(f"{OS_URL}/{index}/_search", headers={"Authorization": f"Bearer {token}"})
    resp.raise_for_status()
    return resp.json()


async def main() -> None:
    # --- 1. Real password-grant logins against the real Keycloak +
    # real kronos-realm.json import + real keycloak-init-provisioned orgs ---
    print("=" * 10, "1. Real password-grant logins (real Keycloak, real orgs)", "=" * 10)
    token_a = password_grant(
        "analyst", "DevAnalyst#2026"
    )  # kronos-test org (shipped keycloak-init)
    token_b = password_grant(
        "ci-analyst-b", "CiAnalystB#2026"
    )  # kronos-ci-org-b (this PoC's own extra org)

    claims_a = jose_jwt.get_unverified_claims(token_a)
    claims_b = jose_jwt.get_unverified_claims(token_b)
    print(
        "analyst (org A) claims:",
        json.dumps(
            {k: claims_a.get(k) for k in ("sub", "roles", "organization", "org_id", "aud", "typ")},
            indent=2,
        ),
    )
    print(
        "ci-analyst-b (org B) claims:",
        json.dumps(
            {k: claims_b.get(k) for k in ("sub", "roles", "organization", "org_id", "aud", "typ")},
            indent=2,
        ),
    )

    check("real login succeeded for both real users (password grant, real Keycloak)", True)
    org_id_a = claims_a.get("org_id")
    org_id_b = claims_b.get("org_id")
    check(
        "analyst's real JWT carries a flat org_id claim (kronos-test org)",
        isinstance(org_id_a, str),
    )
    check(
        "ci-analyst-b's real JWT carries a flat org_id claim (kronos-ci-org-b)",
        isinstance(org_id_b, str),
    )
    check(
        "the two real orgs have DIFFERENT real org_id values",
        org_id_a is not None and org_id_a != org_id_b,
    )

    # --- 2. Real KronOS backend code validates the real tokens (MINIMUM
    # BAR (b)) -- KeycloakTokenValidator, completely unmodified, is the
    # exact class src/external/fastapi_app.py wires into app.state for
    # every real KronOS backend process. ---
    print(
        "\n" + "=" * 10,
        "2. Real KeycloakTokenValidator.validate_and_extract() (unmodified src/ class)",
        "=" * 10,
    )
    validator = KeycloakTokenValidator(
        issuer=f"{KC_BASE}/realms/{REALM}", audience="kronos-backend", jwks_url=JWKS_URL
    )
    tenant_a = await validator.validate_and_extract(token_a)
    tenant_b = await validator.validate_and_extract(token_b)
    roles_a = sorted(r.value for r in tenant_a.roles)
    roles_b = sorted(r.value for r in tenant_b.roles)
    print(
        f"analyst -> TenantContext(org_id={tenant_a.org_id}, "
        f"org_alias={tenant_a.org_alias}, roles={roles_a})"
    )
    print(
        f"ci-analyst-b -> TenantContext(org_id={tenant_b.org_id}, "
        f"org_alias={tenant_b.org_alias}, roles={roles_b})"
    )
    check(
        "real backend validator extracts a real TenantContext for analyst",
        str(tenant_a.org_id) == org_id_a,
    )
    check(
        "real backend validator extracts a real TenantContext for ci-analyst-b",
        str(tenant_b.org_id) == org_id_b,
    )
    check(
        "the two extracted TenantContexts have DIFFERENT org_id (real isolation signal)",
        tenant_a.org_id != tenant_b.org_id,
    )

    # A tampered/garbage token must be REJECTED, not silently accepted --
    # confirms this is real cryptographic validation against the real JWKS,
    # not a no-op.
    try:
        await validator.validate_and_extract(token_a[:-4] + "abcd")
        check("a tampered token is rejected by the real validator", False, "no exception raised")
    except Exception as exc:  # AuthenticationError, but broad on purpose here
        check(
            "a tampered token is rejected by the real validator",
            True,
            f"{type(exc).__name__}: {exc}",
        )

    # --- 3. Real bulk_index() (unmodified production OpenSearchClient) +
    # real DLS isolation via the real Keycloak-issued tokens (MINIMUM BAR
    # (a) + (c), equivalent to I1's own tenant-isolation proof) ---
    print(
        "\n" + "=" * 10,
        "3. Real bulk_index() + real DLS isolation (unmodified src/ OpenSearchClient)",
        "=" * 10,
    )
    client = OpenSearchClient(
        hosts=[{"host": "localhost", "port": int(OS_PORT)}],
        # Must match docker-compose.test.yml's OPENSEARCH_INITIAL_ADMIN_PASSWORD
        # (OpenSearch 2.12+ refuses "admin" as the demo-installer password --
        # see that file's own comment for the real, reproduced finding).
        http_auth=("admin", "KronOSCiTest#2026"),
        use_ssl=True,
        verify_certs=False,
    )
    await client.ensure_index_template()
    index_name = f"kronos-cisec-poc-{uuid.uuid4().hex[:8]}"
    docs = [
        (
            index_name,
            "doc-org-a",
            {
                "@timestamp": "2026-08-10T00:00:00Z",
                "message": "belongs to real org A (kronos-test)",
                "kronos": {
                    "org_id": org_id_a,
                    "case_id": "cisec-poc",
                    "evidence_id": "e1",
                    "parser": "test",
                    "parser_version": "1",
                    "record_index": 0,
                    "ingest_timestamp": "2026-08-10T00:00:00Z",
                },
            },
        ),
        (
            index_name,
            "doc-org-b",
            {
                "@timestamp": "2026-08-10T00:00:00Z",
                "message": "belongs to real org B (kronos-ci-org-b)",
                "kronos": {
                    "org_id": org_id_b,
                    "case_id": "cisec-poc",
                    "evidence_id": "e2",
                    "parser": "test",
                    "parser_version": "1",
                    "record_index": 0,
                    "ingest_timestamp": "2026-08-10T00:00:00Z",
                },
            },
        ),
    ]
    n = await client.bulk_index(docs)
    await client._client.indices.refresh(
        index=index_name
    )  # noqa: SLF001 - poc-only, real client internals
    check("both real docs indexed via the real, unmodified bulk_index()", n == 2)

    # Real ensure_generic_tenant_role() -- the same production method
    # opensearch-init's provision_opensearch_security.py mirrors, and
    # TimelineIngestionService calls on every real ingest when
    # opensearch_security_enabled=True. Calling it again here is harmless
    # (idempotent PUT) and re-verifies the real src/ method itself, not
    # just the provisioning script's own copy of the same design.
    await client.ensure_generic_tenant_role()
    await client.close()

    result_a = search_as(token_a, index_name)
    ids_a = {h["_id"] for h in result_a["hits"]["hits"]}
    print(f"analyst (real org {org_id_a}) sees: {ids_a}")
    check(
        "analyst sees ONLY org A's doc via real DLS (real token)",
        ids_a == {"doc-org-a"},
        str(ids_a),
    )

    result_b = search_as(token_b, index_name)
    ids_b = {h["_id"] for h in result_b["hits"]["hits"]}
    print(f"ci-analyst-b (real org {org_id_b}) sees: {ids_b}")
    check(
        "ci-analyst-b sees ONLY org B's doc via real DLS (real token)",
        ids_b == {"doc-org-b"},
        str(ids_b),
    )

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
