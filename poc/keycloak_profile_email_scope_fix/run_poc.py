"""PoC: verify Gap Audit Milestone Y2's fix -- real profile/email
client scope definitions added to docker/keycloak/kronos-realm.json --
actually causes preferred_username/email to appear in a real, freshly
minted access token from the real dev Keycloak.

Reuses poc/keycloak_browser_login/'s proven real-Chromium-through-real-
Keycloak pattern (Milestone X3), trimmed to just what's needed to mint and
decode one real token: no mocked routes, real "case-lead" credentials
(pre-existing, docker/keycloak/kronos-realm.json), real PKCE login through
kronos.local -> nginx -> Keycloak.

Before this fix: the same flow (see poc/keycloak_browser_login/output.txt,
captured during X3) produced preferred_username=None, email=None.

Run:
    /home/reca/venv/bin/python poc/keycloak_profile_email_scope_fix/run_poc.py

Requires: the real dev stack up, docker-keycloak-1 restarted after the
kronos-realm.json edit (KC_DB: dev-mem means every restart re-imports the
realm fresh -- confirmed via `docker logs docker-keycloak-1` showing
"Realm 'kronos' imported" / "Import finished successfully").
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BACKEND = "https://kronos.local"
SCREENSHOT_DIR = Path(__file__).resolve().parent / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)

PASS, FAIL = [], []
TRANSCRIPT: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    line = f"[{status}] {name}" + (f" -- {detail}" if detail else "")
    print(line)
    TRANSCRIPT.append(line)


def log(msg: str) -> None:
    print(msg)
    TRANSCRIPT.append(msg)


def decode_jwt_payload(token: str) -> dict:
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def main() -> None:
    with sync_playwright() as p:
        log(f"Playwright {p.chromium.name} launching (real Chromium, headless)")
        browser = p.chromium.launch(args=["--ignore-certificate-errors"])
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        log(f"\n=== real login: {BACKEND}/cases -> Keycloak's real hosted form -> back ===")
        page.goto(f"{BACKEND}/cases", timeout=20000)
        page.wait_for_load_state("networkidle")
        check("unauthenticated visit redirects to real /login", page.url == f"{BACKEND}/login")

        page.click("text=Sign in with SSO")
        page.wait_for_selector("#username", timeout=15000)
        check(
            "redirected to Keycloak's real auth endpoint",
            "/realms/kronos/protocol/openid-connect/auth" in page.url,
        )
        page.screenshot(path=str(SCREENSHOT_DIR / "1_keycloak_login_form.png"))

        page.fill("#username", "case-lead")
        page.fill("#password", "DevCaseLead#2026")
        page.click("#kc-login")
        page.wait_for_url(f"{BACKEND}/cases**", timeout=20000)
        page.wait_for_load_state("networkidle")
        check("landed back authenticated on /cases", page.url.startswith(f"{BACKEND}/cases"))
        page.screenshot(path=str(SCREENSHOT_DIR / "2_authenticated_cases.png"))

        log("\n=== decode the real, freshly minted access token ===")
        token_json = page.evaluate("""
            async () => {
                const res = await fetch('/auth/refresh', { method: 'POST', credentials: 'include' });
                if (!res.ok) return null;
                return await res.json();
            }
            """)
        assert token_json and token_json.get(
            "access_token"
        ), "no real token returned from /auth/refresh"
        claims = decode_jwt_payload(token_json["access_token"])
        log(
            "real decoded access-token claims: "
            f"sub={claims.get('sub')} preferred_username={claims.get('preferred_username')!r} "
            f"email={claims.get('email')!r} email_verified={claims.get('email_verified')!r} "
            f"roles={claims.get('roles')} organization={claims.get('organization')}"
        )
        check(
            "preferred_username is now populated (was None before Y2's fix)",
            claims.get("preferred_username") == "case-lead",
            repr(claims.get("preferred_username")),
        )
        check(
            "email is now populated (was None before Y2's fix)",
            bool(claims.get("email")),
            repr(claims.get("email")),
        )
        check(
            "existing organization claim still present (regression check)",
            bool(claims.get("organization")),
        )
        check("existing roles claim still present (regression check)", bool(claims.get("roles")))

        log("\n=== confirm the frontend header now renders the real username ===")
        header_text = page.locator("header").inner_text()
        log(f"real header content: {header_text!r}")
        check(
            "header shows the real username 'case-lead' (was empty before Y2's fix, see X3's own screenshot)",
            "case-lead" in header_text,
        )
        page.screenshot(path=str(SCREENSHOT_DIR / "3_header_shows_username.png"))

        page.click("text=Sign out")
        page.wait_for_url(f"{BACKEND}/login**", timeout=15000)
        check("real sign-out returns to /login", page.url == f"{BACKEND}/login")

        browser.close()

    print(f"\n{'=' * 70}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 70}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")

    out_path = Path(__file__).resolve().parent / "output.txt"
    out_path.write_text(
        "\n".join(TRANSCRIPT)
        + f"\n\n{'=' * 70}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 70}\n"
    )

    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
