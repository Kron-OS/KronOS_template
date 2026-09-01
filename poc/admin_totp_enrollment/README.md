# PoC: real `admin` TOTP enrollment (Gap Audit Milestone JJJJ)

**Versions pinned:** Keycloak 26.2.5 (`docker-keycloak-1`, matches
`docker/docker-compose.dev.yml`'s pinned tag), `pyotp` (already a
`poc/auth_flow/auth_helpers.py` dependency in `~/venv`).

**Why this exists:** `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.8's new
`frontend/e2e/a11y.spec.ts` needs a real browser login as `admin` (the only
dev-seeded `Role.ORG_ADMIN` account) to scan `/admin/org` for real WCAG
violations. `docker/keycloak/kronos-realm.json` ships `admin` with
`"requiredActions": ["CONFIGURE_TOTP"]` — confirmed live via the Admin API
before writing anything (`GET .../users/{id}` showed `"totp": false` and
that required action still pending on this dev stack's current Keycloak
instance) — so the first-ever real browser login as `admin` in this
initiative landed on Keycloak's own interactive "Mobile Authenticator
Setup" page, not a normal login.

**What `enroll.py` does and proves:** a real, scripted Authorization Code +
PKCE login via `poc/auth_flow/auth_helpers.py`'s `real_browser_login()`,
which transparently completes the real CONFIGURE_TOTP form (parses the real
base32 secret, computes a real TOTP code with `pyotp`, submits the real
enrollment form) — the exact same mechanism already used once for
`case-lead`'s own enrollment (`poc/detection_containment_ui/setup.py`).
Then does a **second** real login with no `totp_secret` passed, to confirm
(not assume) that a plain future password login needs no further OTP step —
matching `case-lead`/`analyst`'s already-relied-on behavior throughout
`frontend/e2e/`.

**Real captured output:** `output.txt` (this run) —
`mfa_path=setup` / `new_secret=JB3US4TBJNBEO32BOJJTSZCEI5WGYMKG` on the first
login, `replogin_mfa_path=none` / `replogin_new_secret=None` on the second.

**What this unblocked, and the more general fix that followed:** this
script's own real captured DOM (the manual-mode `#kc-totp-secret-key` span,
the `#totp`/`#userLabel`/`#totpSecret`/`#mode` form fields, `#saveTOTPBtn`)
was reused to build a general, CI-portable version directly in
`frontend/e2e/pages/LoginPage.ts`
(`completeConfigureTotpIfPresented()` + `frontend/e2e/totp.ts`'s own
RFC 6238 TOTP implementation, Node `crypto`-only, no new npm dependency) —
this dev stack is long-lived so this one-time script was enough to unblock
local verification, but `docker-compose.test.yml`'s CI profile
re-provisions Keycloak from the same `kronos-realm.json` on every run, so
`admin`'s first login there would hit the exact same wall every time
without a general fix. Verified live with two throwaway probe accounts
(`requiredActions: ["CONFIGURE_TOTP"]`, deleted after each run) driven
through the real `LoginPage.loginWithSso()` end-to-end, including a second
login confirming the no-further-OTP-needed behavior — see
`docs/GAP_AUDIT_2026-08-28_MILESTONE_JJJJ.md` for the full account.
`a11y.spec.ts` itself needs no special-casing for `admin` as a result.

Run: `~/venv/bin/python3 poc/admin_totp_enrollment/enroll.py`
(requires `docker-keycloak-1`/`docker-tls-init-1` already running).
