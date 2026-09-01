"""One-time real TOTP enrollment for the dev-stack `admin` Keycloak user
(Gap Audit Milestone JJJJ).

Context: `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.8's new `frontend/e2e/a11y.spec.ts`
needs a real browser login as `admin` (the only dev-seeded account with
Role.ORG_ADMIN, required by `RbacGuard requiredRole="org-admin"` on
`/admin/org`) to scan AdminPage for real WCAG violations. The realm import
(`docker/keycloak/kronos-realm.json`) ships `admin` with
`"requiredActions": ["CONFIGURE_TOTP"]` -- confirmed live via the Admin API
before writing this script (`GET .../users/{id}` showed `"totp": false`,
`requiredActions: ["CONFIGURE_TOTP"]`, and `GET .../credentials` had no
`otp` entry) -- so the FIRST real browser login attempt as `admin` in this
initiative hit Keycloak's own interactive CONFIGURE_TOTP required-action
page and the plain `#username`/`#password`/`#kc-login` selectors
`LoginPage.ts` uses never got a chance to complete a normal login.

This mirrors the exact, already-established precedent
`poc/detection_containment_ui/setup.py`/README documents for `case-lead`'s
own first-ever TOTP enrollment: a real, scripted Authorization Code + PKCE
login via `poc/auth_flow/auth_helpers.py`'s `real_browser_login()`, which
transparently completes the real CONFIGURE_TOTP form (parses the real
base32 secret, computes a real TOTP code with `pyotp`, submits the real
enrollment form) when it detects a fresh account. One-time side effect,
same as case-lead's: `admin` now has a persistent `otp` credential and its
`requiredActions` is cleared server-side. The secret is captured below
purely for the record (matching `case_lead_totp_secret.txt`'s own
precedent) -- `frontend/e2e/a11y.spec.ts`'s admin-page test does NOT need
it, because (confirmed live, see output.txt) this realm's browser flow
does not force OTP entry on a plain password login even after enrollment
-- exactly the same behavior already relied on by every other spec in
`frontend/e2e/` logging in as `case-lead`/`analyst` (KronOS's own
app-level step-up ticket flow is what actually gates OTP entry for
privileged actions, not Keycloak's browser flow on every login).

Run: ~/venv/bin/python3 poc/admin_totp_enrollment/enroll.py
Requires docker-keycloak-1/docker-tls-init-1 already running (dev stack).
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "poc" / "auth_flow"))

import auth_helpers as ah  # noqa: E402


def main() -> None:
    ah.trust_dev_stack_step_ca("docker-tls-init-1")
    ah.KC = "https://kronos.local:8443"
    ah.REDIRECT_URI = "https://kronos.local/e2e-admin-totp-callback"

    tokens, new_secret, mfa_path = ah.real_browser_login(
        "admin", "DevAdmin#2026", totp_secret=None, state="jjjj-admin-totp-enroll"
    )
    claims = ah.decode_jwt_payload(tokens["access_token"])
    print(f"mfa_path={mfa_path}")
    print(f"new_secret={new_secret}")
    print(f"preferred_username={claims.get('preferred_username')}")
    print(f"roles={claims.get('roles')}")
    assert mfa_path == "setup", f"expected a fresh CONFIGURE_TOTP enrollment, got mfa_path={mfa_path}"
    assert new_secret, "expected a real new TOTP secret to be returned"

    # Second real login, password-only, no totp_secret passed -- confirms
    # (for real, not assumed) that a plain future login as admin does NOT
    # require OTP entry, matching case-lead/analyst's existing behavior in
    # every other frontend/e2e/ spec.
    tokens2, new_secret2, mfa_path2 = ah.real_browser_login(
        "admin", "DevAdmin#2026", totp_secret=None, state="jjjj-admin-totp-replogin"
    )
    print(f"replogin_mfa_path={mfa_path2}")
    print(f"replogin_new_secret={new_secret2}")
    assert mfa_path2 == "none", f"expected plain password login post-enrollment, got mfa_path={mfa_path2}"
    assert new_secret2 is None

    print("OK: admin TOTP enrolled once; subsequent plain password logins need no OTP step.")


if __name__ == "__main__":
    main()
