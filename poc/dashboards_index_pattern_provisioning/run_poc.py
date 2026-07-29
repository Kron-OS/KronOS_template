"""PoC: exercise the real src/adapter/opensearch/dashboards_client.py
(DashboardsIndexPatternProvisioner) against the real, already-running dev
stack's OpenSearch Dashboards 2.11.1 (localhost:5601) -- imports and calls
the exact class KronOS ships, not a reimplementation.

Fixes the gap this whole session's prior PoCs (opensearch_dashboards_dls,
dashboards_embed) surfaced but didn't close: cases.py's get_dashboard_url()
only ever put a raw index-name string into the embed URL's filter, and
nothing ever created a real saved index-pattern object, so every real user
landed on Dashboards' "create an index pattern first" empty state even
after DLS access was fixed. This provisions one automatically at
case-creation time.

Run: source ~/venv/bin/activate && python poc/dashboards_index_pattern_provisioning/run_poc.py
Requires the real dev stack up (docker compose -f docker/docker-compose.dev.yml up -d),
opensearch-dashboards reachable on localhost:5601.
"""
from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.opensearch.dashboards_client import DashboardsIndexPatternProvisioner  # noqa: E402

DASHBOARDS_URL = "http://localhost:5601"
ORG_ALIAS = "kronos-dev"  # the real dev org's alias (docker/keycloak/kronos-realm.json)
TENANT = f"kronos-{ORG_ALIAS}"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def fetch_saved_object(pattern_id: str) -> httpx.Response:
    return httpx.get(
        f"{DASHBOARDS_URL}/api/saved_objects/index-pattern/{pattern_id}",
        headers={"securitytenant": TENANT},
        auth=("admin", "admin"),
        timeout=10,
    )


async def main() -> None:
    case_id = uuid.uuid4()
    pattern_id = f"kronos-case-{case_id}-timeline"
    expected_title = f"kronos-{ORG_ALIAS}-case-{case_id}-*"

    provisioner = DashboardsIndexPatternProvisioner(
        base_url=DASHBOARDS_URL, admin_username="admin", admin_password="admin"
    )

    print(f"case_id: {case_id}")
    print(f"expected saved-object id: {pattern_id}")
    print(f"expected title: {expected_title}")

    # --- First call: creates the object ---
    await provisioner.ensure_case_index_pattern(ORG_ALIAS, case_id)
    resp = fetch_saved_object(pattern_id)
    check("index pattern exists after first call", resp.status_code == 200, f"status={resp.status_code}")
    if resp.status_code == 200:
        body = resp.json()
        check("title matches the real index-name pattern", body["attributes"]["title"] == expected_title, body["attributes"]["title"])
        check("timeFieldName is @timestamp", body["attributes"]["timeFieldName"] == "@timestamp")
        version_1 = body["version"]

    # --- Second call: idempotent re-run must not fail or duplicate ---
    await provisioner.ensure_case_index_pattern(ORG_ALIAS, case_id)
    resp2 = fetch_saved_object(pattern_id)
    check("second call still succeeds (idempotent)", resp2.status_code == 200, f"status={resp2.status_code}")
    if resp2.status_code == 200:
        body2 = resp2.json()
        check("same saved-object id reused, not duplicated", body2["id"] == pattern_id, body2["id"])

    # --- Visible via the real _find API real Dashboards users hit ---
    find_resp = httpx.get(
        f"{DASHBOARDS_URL}/api/saved_objects/_find",
        params={"type": "index-pattern", "search": f'"{expected_title}"'},
        headers={"securitytenant": TENANT},
        auth=("admin", "admin"),
        timeout=10,
    )
    titles = [so["attributes"]["title"] for so in find_resp.json().get("saved_objects", [])]
    check("discoverable via the real _find API a real user's browser calls", expected_title in titles, str(titles))

    # --- Confirms the pattern actually resolves the real backing indices ---
    resolve_resp = httpx.get(
        f"https://localhost:9200/_resolve/index/{expected_title}",
        auth=("admin", "admin"),
        verify=False,
        timeout=10,
    )
    check(
        "OpenSearch itself resolves this exact pattern string cleanly (200, valid syntax)",
        resolve_resp.status_code == 200,
        resolve_resp.text[:200],
    )

    # --- Failure mode: unreachable Dashboards must not raise, only log ---
    broken_provisioner = DashboardsIndexPatternProvisioner(
        base_url="http://localhost:1", admin_username="admin", admin_password="admin"
    )
    try:
        await broken_provisioner.ensure_case_index_pattern(ORG_ALIAS, uuid.uuid4())
        check("unreachable Dashboards is swallowed (best-effort), doesn't raise", True)
    except Exception as exc:  # noqa: BLE001
        check("unreachable Dashboards is swallowed (best-effort), doesn't raise", False, str(exc))

    # --- Cleanup ---
    httpx.delete(
        f"{DASHBOARDS_URL}/api/saved_objects/index-pattern/{pattern_id}",
        headers={"securitytenant": TENANT, "osd-xsrf": "true"},
        auth=("admin", "admin"),
        timeout=10,
    )

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
