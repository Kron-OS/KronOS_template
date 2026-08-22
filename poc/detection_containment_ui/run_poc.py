"""Live-browser verification for Gap Audit Milestone MM: the new
Containment UI on DetectionDetailPage (frontend/src/components/
ContainmentPanel.tsx), covering both real backend routes that had zero
frontend affordance before this milestone:

  - POST /api/detections/{id}/contain/revoke-session (ORG_ADMIN/CASE_LEAD)
  - POST /api/detections/{id}/sync-to-siem/{sink_name} (+ANALYST)

This is the FIRST real UI consumer of POST /api/step-up/ticket anywhere in
this codebase (confirmed by grep before writing any frontend code -- see
this PoC's own README) -- exercised here end to end against the real,
running dev stack: real Keycloak login, a real redirect-driven step-up
re-authentication (RFC 9470), a real minted ticket, a real Keycloak session
revocation, and a real, independent Admin API re-check that the session is
actually gone. No mocks anywhere in this file.

Run: ~/venv/bin/python3 poc/detection_containment_ui/run_poc.py
Requires: the dev stack already up (this PoC's own commit already rebuilt
docker-nginx-1 from the new frontend source -- see README), and
poc/detection_containment_ui/setup.py's own real dependencies (Keycloak
26.2.5, Postgres 16).
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pyotp
from playwright.sync_api import Page, sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[2]
POC_DIR = Path(__file__).resolve().parent
SCREENSHOT_DIR = POC_DIR / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)
SECRET_FILE = POC_DIR / "case_lead_totp_secret.txt"

BACKEND = "https://kronos.local"
KEYCLOAK_INTERNAL_URL = "http://localhost:8080"
KEYCLOAK_REALM = "kronos"
KEYCLOAK_ADMIN_CLIENT_ID = "kronos-backend"
KEYCLOAK_ADMIN_CLIENT_SECRET = "kronos-backend-secret"

CHECKS: list[tuple[str, bool]] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(UTC).isoformat()}] {msg}")


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    log(f"{'PASS' if ok else 'FAIL'}: {label}")


def run_setup() -> dict:
    """Real setup: resolves the live org id, seeds a real Detection, creates
    a real throwaway Keycloak user, and produces a real live session for it
    (poc/detection_containment_ui/setup.py) -- see that module for why this
    is a separate script rather than inlined here."""
    result = subprocess.run(
        [sys.executable, str(POC_DIR / "setup.py")],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=True,
    )
    log("=== setup.py stderr (its own progress log) ===")
    print(result.stderr, file=sys.stderr)
    return json.loads(result.stdout.strip().splitlines()[-1])


def get_admin_token(client: httpx.Client) -> str:
    resp = client.post(
        f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_ADMIN_CLIENT_ID,
            "client_secret": KEYCLOAK_ADMIN_CLIENT_SECRET,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def list_sessions(client: httpx.Client, token: str, user_id: str) -> list[dict]:
    """A SEPARATE, fresh Admin API round trip -- independent of whatever the
    real UI/backend route itself just did -- per this initiative's own
    established proof bar (mirrors poc/revoke_session_route/run_poc.py)."""
    resp = client.get(
        f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}/sessions",
        headers={"Authorization": f"Bearer {token}"},
    )
    resp.raise_for_status()
    return resp.json()


def real_ui_login(page: Page, username: str, password: str, landing_path: str) -> None:
    page.goto(f"{BACKEND}{landing_path}", timeout=20000)
    page.wait_for_selector("text=Sign in with SSO", timeout=15000)
    page.click("text=Sign in with SSO")
    page.wait_for_selector("#username", timeout=15000)
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#kc-login")
    page.wait_for_url(f"{BACKEND}{landing_path}**", timeout=20000)
    page.wait_for_selector("text=New Case", timeout=15000)
    # Real, reproduced race found while building this PoC: main.tsx's
    # initKeycloak() finishes adopting the fresh token (URL already matches
    # landing_path) slightly BEFORE its own async hand-off of the refresh
    # token to the backend's HttpOnly-cookie proxy (POST /auth/refresh,
    # keycloak.ts::initKeycloak) actually completes. A full page navigation
    # (page.goto, not client-side routing) immediately after that point
    # reloads the SPA before the cookie exists, so the reloaded app's own
    # bootstrap 401s on /auth/refresh and never re-authenticates. Giving
    # that hand-off a moment to finish avoids it -- a real PoC-environment
    # timing detail, not a src/ change.
    page.wait_for_timeout(1500)


def complete_step_up_challenge(page: Page, username: str, password: str) -> None:
    """Handle the real, interactive Keycloak re-authentication triggered by
    apiClient's response interceptor calling keycloak.login({acrValues:
    'aal2', prompt: 'login'}) (frontend/src/api/client.ts). Real markup for
    both possible pages (confirmed by direct inspection against this exact
    dev stack before writing this function -- see README):
      - CONFIGURE_TOTP (case-lead has no OTP credential yet): manual-mode
        secret extraction + real enrollment, secret persisted to
        SECRET_FILE for future runs.
      - login-otp (case-lead already enrolled): submit a real TOTP code
        computed from the persisted secret.
    """
    page.wait_for_url(lambda url: "kronos.local:8443" in url, timeout=20000)
    log(f"redirected to real Keycloak step-up challenge: {page.url}")
    page.wait_for_selector("#password", timeout=15000)
    # Real markup difference found live: since this browser context already
    # holds an active Keycloak SSO session (from the earlier plain login),
    # `prompt=login` renders a "please re-authenticate" form that shows the
    # username read-only (#kc-attempted-username) and asks only for the
    # password -- NOT the fresh two-field login form real_ui_login() uses.
    # Fill #username too when present (a cold context with no existing SSO
    # session would still show the full form).
    if page.locator("#username").count() > 0:
        page.fill("#username", username)
    page.fill("#password", password)
    page.click("#kc-login")
    page.wait_for_load_state("networkidle", timeout=15000)

    if page.locator("a#mode-manual").count() > 0:
        log("real CONFIGURE_TOTP page reached (no prior OTP credential)")
        page.click("a#mode-manual")
        page.wait_for_selector("#kc-totp-secret-key", timeout=5000)
        secret = page.locator("#kc-totp-secret-key").inner_text().replace(" ", "")
        code = pyotp.TOTP(secret).now()
        page.fill("#totp", code)
        page.fill("#userLabel", "poc-mm-authenticator")
        page.click("#saveTOTPBtn")
        SECRET_FILE.write_text(secret)
        log(f"real TOTP credential enrolled; secret persisted to {SECRET_FILE}")
    elif page.locator("#otp").count() > 0:
        log("real login-otp page reached (already-enrolled credential)")
        assert SECRET_FILE.exists(), "case-lead has an OTP credential but no secret was persisted"
        secret = SECRET_FILE.read_text().strip()
        code = pyotp.TOTP(secret).now()
        page.fill("#otp", code)
        page.click("#kc-login")
    else:
        raise RuntimeError(f"Unrecognized step-up challenge page: {page.url}\n{page.content()[:2000]}")

    page.wait_for_url(lambda url: "kronos.local:8443" not in url, timeout=20000)
    log(f"real step-up re-authentication completed, returned to app: {page.url}")


def main() -> None:
    setup = run_setup()
    org_id = setup["org_id"]
    detection_id = setup["detection_id"]
    target_user_id = setup["target_user_id"]
    target_session_id = setup["target_session_id"]
    log(f"real setup complete: org_id={org_id} detection_id={detection_id} "
        f"target_user_id={target_user_id} target_session_id={target_session_id}")

    with httpx.Client(timeout=15) as admin_client:
        admin_token = get_admin_token(admin_client)
        sessions_before = list_sessions(admin_client, admin_token, target_user_id)
        check(
            "real target session appears in a fresh, independent Admin API "
            "sessions list BEFORE any UI action",
            any(s["id"] == target_session_id for s in sessions_before),
        )

        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--ignore-certificate-errors"])

            # -----------------------------------------------------------
            # Part 1: case-lead -- full containment UI, both sections.
            # -----------------------------------------------------------
            log("=== PART 1: case-lead sees and uses the full Containment UI ===")
            ctx_lead = browser.new_context(ignore_https_errors=True)
            page = ctx_lead.new_page()
            real_ui_login(page, "case-lead", "DevCaseLead#2026", "/cases")

            page.goto(f"{BACKEND}/detections/{detection_id}", timeout=20000)
            page.wait_for_selector("text=Containment", timeout=15000)
            check(
                "real detection detail page renders the Containment heading",
                page.locator("text=Containment").count() > 0,
            )
            check(
                "case-lead sees the Sync to SIEM control",
                page.get_by_role("button", name="Sync to SIEM").count() > 0,
            )
            check(
                "case-lead sees the Revoke Session controls (User ID input)",
                page.get_by_label("User ID").count() > 0,
            )
            page.screenshot(path=str(SCREENSHOT_DIR / "1_case_lead_containment_panel.png"))

            log("--- Sync to SIEM: no sink configured in this dev stack (confirmed via env) ---")
            with page.expect_response(
                lambda r: "/sync-to-siem/" in r.url and r.request.method == "POST", timeout=15000
            ) as siem_resp_info:
                page.get_by_role("button", name="Sync to SIEM").click()
            siem_resp = siem_resp_info.value
            check(
                "real POST /sync-to-siem/splunk returns 404 (honest 'not configured', "
                "confirmed no SPLUNK_HEC_URL/CEF/SENTINEL env vars set on docker-kronos-backend-1)",
                siem_resp.status == 404,
            )
            page.wait_for_selector("text=is not configured in this deployment", timeout=5000)
            check(
                "UI shows the honest 'not configured' message (not a fabricated success)",
                page.locator("text=is not configured in this deployment").count() > 0,
            )
            page.screenshot(path=str(SCREENSHOT_DIR / "2_sync_to_siem_not_configured.png"))

            log("--- Revoke Session: fill target details, request approval (real step-up) ---")
            page.get_by_label("User ID").fill(target_user_id)
            page.get_by_label("Session ID").fill(target_session_id)
            page.get_by_role("button", name="Request Approval").click()

            complete_step_up_challenge(page, "case-lead", "DevCaseLead#2026")
            page.screenshot(path=str(SCREENSHOT_DIR / "3_after_step_up_redirect_back.png"))

            log("--- Retry after step-up: this is the SAME real UX gap noted in the brief -- ")
            log("the original in-flight form state was lost on the full-page redirect. ---")
            page.wait_for_selector("text=Containment", timeout=15000)
            page.get_by_label("User ID").fill(target_user_id)
            page.get_by_label("Session ID").fill(target_session_id)

            with page.expect_response(
                lambda r: "/api/step-up/ticket" in r.url and r.request.method == "POST", timeout=15000
            ) as ticket_resp_info:
                page.get_by_role("button", name="Request Approval").click()
            ticket_resp = ticket_resp_info.value
            check(
                f"real POST /api/step-up/ticket returns {ticket_resp.status} after "
                "step-up re-authentication (aal2 now actually carried by the SPA's token)",
                ticket_resp.status == 201,
            )
            page.screenshot(path=str(SCREENSHOT_DIR / "4_approval_granted.png"))

            log("--- Confirm Revoke: fires the real revoke-session route with the real ticket ---")
            with page.expect_response(
                lambda r: "/contain/revoke-session" in r.url and r.request.method == "POST", timeout=15000
            ) as revoke_resp_info:
                page.get_by_role("button", name="Confirm Revoke").click()
            revoke_resp = revoke_resp_info.value
            check("real POST /contain/revoke-session returns 200", revoke_resp.status == 200)
            revoke_body = revoke_resp.json()
            check("real revoke succeeded=true in the response body", revoke_body["succeeded"] is True)
            page.wait_for_selector("text=Succeeded", timeout=5000)
            check(
                "UI shows the real 'Succeeded' outcome banner",
                page.locator("text=Succeeded").count() > 0,
            )
            page.screenshot(path=str(SCREENSHOT_DIR / "5_revoke_succeeded.png"))

            sessions_after = list_sessions(admin_client, admin_token, target_user_id)
            check(
                "the real target session is GONE from a FRESH, independent Admin API "
                "re-check performed AFTER the UI action (not the same call the backend made)",
                not any(s["id"] == target_session_id for s in sessions_after),
            )

            ctx_lead.close()

            # -----------------------------------------------------------
            # Part 2: analyst -- sync-to-siem yes, revoke-session no.
            # -----------------------------------------------------------
            log("=== PART 2: analyst can use Sync to SIEM but cannot see Revoke Session ===")
            ctx_analyst = browser.new_context(ignore_https_errors=True)
            page2 = ctx_analyst.new_page()
            real_ui_login(page2, "analyst", "DevAnalyst#2026", "/cases")

            page2.goto(f"{BACKEND}/detections/{detection_id}", timeout=20000)
            page2.wait_for_selector("text=Containment", timeout=15000)
            check(
                "analyst sees the Sync to SIEM control",
                page2.get_by_role("button", name="Sync to SIEM").count() > 0,
            )
            check(
                "analyst does NOT see the Revoke Session User ID input",
                page2.get_by_label("User ID").count() == 0,
            )
            check(
                "analyst does NOT see a Request Approval / Confirm Revoke button",
                page2.get_by_role("button", name="Request Approval").count() == 0
                and page2.get_by_role("button", name="Confirm Revoke").count() == 0,
            )
            check(
                "analyst sees the role-restriction message for Revoke Session",
                page2.locator("text=org-admin or case-lead required").count() > 0,
            )
            page2.screenshot(path=str(SCREENSHOT_DIR / "6_analyst_containment_panel.png"))

            log("--- analyst really can trigger sync-to-siem (same honest 404 outcome) ---")
            with page2.expect_response(
                lambda r: "/sync-to-siem/" in r.url and r.request.method == "POST", timeout=15000
            ) as siem_resp2_info:
                page2.get_by_role("button", name="Sync to SIEM").click()
            siem_resp2 = siem_resp2_info.value
            check(
                "analyst's real POST /sync-to-siem/splunk also returns 404 "
                "(role gate allows the call through; sink is just not configured)",
                siem_resp2.status == 404,
            )
            page2.wait_for_selector("text=is not configured in this deployment", timeout=5000)
            page2.screenshot(path=str(SCREENSHOT_DIR / "7_analyst_sync_to_siem_result.png"))

            ctx_analyst.close()
            browser.close()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    log(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
