"""One-off manual recovery: unblock evidence stuck in RECEIVED after a
worker restart, using the documented ORG_ADMIN recovery endpoint
(CLAUDE.md Section E.6) -- not part of the harness's normal flow."""
import sys

sys.path.insert(0, "poc/auth_flow")
import auth_helpers  # noqa: E402

auth_helpers.KC = "https://kronos.local:8443"
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
auth_helpers.trust_dev_stack_step_ca()
import httpx  # noqa: E402

tokens, new_secret, mfa_path = auth_helpers.real_browser_login(
    "admin", "DevAdmin#2026", totp_secret=None, state="i1-recovery"
)
print("mfa_path", mfa_path, "new_secret", new_secret)
client = httpx.Client(
    base_url="https://kronos.local",
    headers={"Authorization": f"Bearer {tokens['access_token']}"},
    verify=auth_helpers.CA_BUNDLE,
    timeout=30,
)

evidence_id = sys.argv[1]
resp = client.post(f"/api/evidence/parse/start/{evidence_id}")
print(resp.status_code, resp.text[:500])
