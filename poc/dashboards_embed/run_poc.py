"""PoC: cases.py's GET /{case_id}/dashboard-url route (backend side only --
this repo's real dependency-injected FastAPI route, `assert_case_access`,
and the exact RISON string it produces). Real browser-level verification
of what OpenSearch Dashboards actually DOES with the resulting URL is
poc/frontend_browser's separate, not-yet-done job (Playwright); this PoC
is scoped to what's verifiable without a browser: is the route's own logic
correct, and is the URL it hand-builds actually well-formed against the
real OpenSearch Dashboards 2.11.1 source/dependencies it targets.

Uses the real, unmodified FastAPI app (create_app()) and InMemoryCaseRepository
(the route's own logic doesn't touch OpenSearch at all -- it only builds a
URL string -- so no real OpenSearch/Postgres container is needed here).
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi.testclient import TestClient  # noqa: E402

from src.adapter.repository.case_repository import InMemoryCaseRepository  # noqa: E402
from src.domain.case import Case, CaseMetadata  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.dependencies import get_case_repository, get_opensearch_dashboards_url  # noqa: E402
from src.external.fastapi_app import create_app  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


ORG_ID = uuid.uuid4()
USER_ID = uuid.uuid4()
OTHER_ORG_ID = uuid.uuid4()
OTHER_USER_ID = uuid.uuid4()


def main() -> None:
    app = create_app(
        keycloak_issuer="http://unused.invalid/realms/kronos",
        keycloak_audience="kronos-backend",
        keycloak_jwks_url="http://unused.invalid/realms/kronos/protocol/openid-connect/certs",
    )
    case_repo = InMemoryCaseRepository()
    app.dependency_overrides[get_case_repository] = lambda: case_repo

    def _tenant_override() -> TenantContext:
        return TenantContext(
            org_id=ORG_ID, org_alias="acmecorp", user_id=USER_ID, username="analyst1",
            roles=frozenset({Role.ANALYST}), correlation_id=str(uuid.uuid4()),
        )

    from src.external.dependencies import get_tenant_context  # noqa: PLC0415
    app.dependency_overrides[get_tenant_context] = _tenant_override

    with TestClient(app) as client:
        import asyncio  # noqa: PLC0415

        case = Case(
            org_id=ORG_ID, org_alias="acmecorp", owner_user_id=USER_ID,
            metadata=CaseMetadata(title="Real PoC case"),
            member_user_ids=frozenset({USER_ID}),
        )
        asyncio.run(case_repo.save(case))
        other_org_case = Case(
            org_id=OTHER_ORG_ID, org_alias="othercorp", owner_user_id=OTHER_USER_ID,
            metadata=CaseMetadata(title="Not our case"),
        )
        asyncio.run(case_repo.save(other_org_case))

        # --- 1. Real 503 when Dashboards isn't configured ---
        print("=" * 10, "1. Real 503 when OPENSEARCH_DASHBOARDS_URL is unconfigured", "=" * 10)
        resp = client.get(f"/api/cases/{case.case_id}/dashboard-url")
        print(f"-> {resp.status_code} {resp.json()}")
        check("real route returns 503 when Dashboards is not configured", resp.status_code == 503)

        # --- Now configure it for the rest of the checks ---
        app.dependency_overrides[get_opensearch_dashboards_url] = (
            lambda: "https://dashboards.kronos.example"
        )

        # --- 2. Real 404 for a nonexistent case ---
        print("\n" + "=" * 10, "2. Real 404 for a nonexistent case", "=" * 10)
        resp = client.get(f"/api/cases/{uuid.uuid4()}/dashboard-url")
        check("real route returns 404 for a case that doesn't exist", resp.status_code == 404)

        # --- 3. Real 404 for a case in a DIFFERENT org (get_by_id itself scopes by org_id) ---
        print("\n" + "=" * 10, "3. Real cross-org isolation via case_repo.get_by_id", "=" * 10)
        resp = client.get(f"/api/cases/{other_org_case.case_id}/dashboard-url")
        check("real route returns 404 for a case belonging to a different org (never leaks 403 that would confirm existence)",
              resp.status_code == 404)

        # --- 4. Real 200 + real URL for an authorized case ---
        print("\n" + "=" * 10, "4. Real 200 with a real embed URL", "=" * 10)
        resp = client.get(f"/api/cases/{case.case_id}/dashboard-url")
        print(f"-> {resp.status_code}")
        check("real route returns 200 for the case's real owner/member", resp.status_code == 200)
        url = resp.json()["url"]
        print(f"URL: {url}")
        check("URL is rooted at the configured Dashboards origin (loaded from its own domain, not proxied)",
              url.startswith("https://dashboards.kronos.example/"))

        # --- 5. Confirm the app path against real OpenSearch Dashboards 2.11.1 source ---
        print("\n" + "=" * 10, "5. Real app path + query-param key, verified against pinned 2.11.1 source", "=" * 10)
        check(
            "app path is /app/data-explorer/discover -- confirmed via the real "
            "OpenSearch-Dashboards 2.11.1 source: data_explorer's PLUGIN_ID is "
            "literally 'data-explorer' (src/plugins/data_explorer/common/index.ts), "
            "and discover's plugin.ts registers itself as a VIEW within that app "
            "via dataExplorer.registerView({id: 'discover', ...}) -- so the full "
            "real path is exactly app/<data-explorer-id>/<discover-view-id>",
            "/app/data-explorer/discover" in url,
        )
        check(
            "'_g' is the real global-state query param key -- confirmed via "
            "data_explorer/public/plugin.ts's createOsdUrlTracker call, which "
            "registers stateParams with osdUrlKey: '_g' for exactly this "
            "(filters/time/refreshInterval) global state",
            "_g=" in url,
        )

        import urllib.parse  # noqa: PLC0415
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        check("embed=true is present (suppresses Dashboards chrome for iframe embedding)",
              qs.get("embed") == ["true"])
        ks_filter = qs["_g"][0]
        print(f"raw _g RISON: {ks_filter}")

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)

    # Hand the raw _g RISON blob to run_poc.sh, which decodes it with the
    # real pinned rison-node@1.0.2 library (matching package.json) via a
    # real node container -- the strongest available verification that the
    # backend's hand-built string is genuinely well-formed RISON, not just
    # "looks right."
    Path("/tmp/kronos_poc_dashboards_embed_g.txt").write_text(ks_filter)


if __name__ == "__main__":
    main()
