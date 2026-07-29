"""PoC step 2: resolves poc/dashboards_embed/README.md's flagged-not-resolved
question -- does the embed URL actually make Discover open with the right
data, zero clicks? Backend-side half: confirms the real, updated
get_dashboard_url() route emits a URL whose _a/_g/_q blobs (in the URL
FRAGMENT, not the top-level query string -- see below) are genuinely
well-formed RISON for the real pinned OpenSearch Dashboards 2.11.1.

The real browser half (does loading this URL actually skip the tenant
dialog and load the case's data) is autoload_verification/README.md's own
"Real browser confirmation" section -- run against the live dev stack, not
scriptable as a hermetic PoC the way this backend-only half is.

Real finding this fixes: a hand-built URL with _a/_g in the TOP-LEVEL query
string (the original poc/dashboards_embed/ route) is silently ignored by
data-explorer's own router -- confirmed by loading one in a real logged-in
browser and reading back what state the app actually settled on (its own
getPreloadedState() default, i.e. whatever index pattern was last viewed,
not what the URL asked for). The real, working state lives in the URL
FRAGMENT: #?_a=...&_g=...&_q=..., confirmed the same way.
"""
from __future__ import annotations

import sys
import urllib.parse
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from fastapi.testclient import TestClient  # noqa: E402

from src.adapter.repository.case_repository import InMemoryCaseRepository  # noqa: E402
from src.domain.case import Case, CaseMetadata  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.dependencies import (  # noqa: E402
    get_case_repository,
    get_opensearch_dashboards_url,
    get_tenant_context,
)
from src.external.fastapi_app import create_app  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


ORG_ID = uuid.uuid4()
USER_ID = uuid.uuid4()


def main() -> None:
    app = create_app(
        keycloak_issuer="http://unused.invalid/realms/kronos",
        keycloak_audience="kronos-backend",
        keycloak_jwks_url="http://unused.invalid/realms/kronos/protocol/openid-connect/certs",
    )
    case_repo = InMemoryCaseRepository()
    app.dependency_overrides[get_case_repository] = lambda: case_repo
    app.dependency_overrides[get_opensearch_dashboards_url] = (
        lambda: "https://dashboards.kronos.example"
    )

    def _tenant_override() -> TenantContext:
        return TenantContext(
            org_id=ORG_ID, org_alias="acmecorp", user_id=USER_ID, username="analyst1",
            roles=frozenset({Role.ANALYST}), correlation_id=str(uuid.uuid4()),
        )

    app.dependency_overrides[get_tenant_context] = _tenant_override

    with TestClient(app) as client:
        import asyncio  # noqa: PLC0415

        case = Case(
            org_id=ORG_ID, org_alias="acmecorp", owner_user_id=USER_ID,
            metadata=CaseMetadata(title="Autoload PoC case"),
            member_user_ids=frozenset({USER_ID}),
        )
        asyncio.run(case_repo.save(case))

        resp = client.get(f"/api/cases/{case.case_id}/dashboard-url")
        check("real route still returns 200", resp.status_code == 200)
        url = resp.json()["url"]
        print(f"URL: {url}")

        parsed = urllib.parse.urlparse(url)
        top_qs = urllib.parse.parse_qs(parsed.query)
        check(
            "security_tenant is a TOP-LEVEL query param (real security-dashboards-plugin's "
            "tenant_resolver.ts checks this before falling back to the session cookie, "
            "resolving the org's tenant on the very first request)",
            top_qs.get("security_tenant") == [f"kronos-{case.org_alias}"],
            str(top_qs.get("security_tenant")),
        )
        check(
            "top-level query string has NO _a/_g/_q -- those must live in the "
            "fragment or data-explorer's own router silently overwrites them",
            not any(k in top_qs for k in ("_a", "_g", "_q")),
        )

        check("URL has a fragment (#?...)", bool(parsed.fragment), parsed.fragment[:80])
        # parsed.fragment is "?_a=...&_g=...&_q=..." -- urlparse doesn't strip
        # a leading "?" from the FRAGMENT component the way it does for the
        # query component, so parse_qs would otherwise treat "?_a" as one key.
        frag_qs = urllib.parse.parse_qs(parsed.fragment.lstrip("?"))
        check("fragment has _a", "_a" in frag_qs)
        check("fragment has _g", "_g" in frag_qs)
        check("fragment has _q", "_q" in frag_qs)

        pattern_id = f"kronos-case-{case.case_id}-timeline"
        a_blob = frag_qs["_a"][0]
        q_blob = frag_qs["_q"][0]
        g_blob = frag_qs["_g"][0]
        check(
            "_a.metadata.indexPattern references the REAL deterministic saved-object id "
            "DashboardsIndexPatternProvisioner provisions (case_index_pattern_id()) -- "
            "confirmed via metadata_slice.ts at tag 2.11.1: indexPattern is what data-explorer "
            "reads to select the active index pattern, regardless of which view is shown",
            f"indexPattern:'{pattern_id}'" in a_blob,
            a_blob,
        )
        check("_a sets view:discover", "view:discover" in a_blob)
        check(
            "_q carries the case_id filter (not _a -- confirmed via a real browser "
            "reading back data-explorer's own default _q shape)",
            f"kronos.case_id" in q_blob and str(case.case_id) in q_blob,
            q_blob,
        )
        check("_g carries the time range, not the filter", "time:(from:now-30d" in g_blob, g_blob)

        print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
        if FAIL:
            print("FAILURES:", FAIL)
            sys.exit(1)

        Path("/tmp/kronos_poc_autoload_a.txt").write_text(a_blob)
        Path("/tmp/kronos_poc_autoload_g.txt").write_text(g_blob)
        Path("/tmp/kronos_poc_autoload_q.txt").write_text(q_blob)


if __name__ == "__main__":
    main()
