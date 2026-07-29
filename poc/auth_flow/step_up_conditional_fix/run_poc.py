"""P1 fix verification: real scripted PKCE logins against a real Keycloak
26.2, using a candidate FIXED realm (kronos-realm-poc.json in this dir)
that adds a "browser-stepup level1" conditional subflow before the
existing level-2 (OTP) one.

Root cause (confirmed by reading the real Keycloak 26.2.0 source,
ConditionalLoaAuthenticator.matchCondition()): a SINGLE
conditional-level-of-authentication check, with nothing establishing a
baseline LoA first, always sees "no level attained yet in this session"
and unconditionally evaluates true -- forcing entry into the OTP subflow
regardless of the actual requested acr_values. The official Keycloak
step-up pattern uses a LOWER-level conditional subflow first (here:
level=1, no extra authenticator) specifically to establish that baseline,
so the level=2 condition afterwards sees a real level to compare the
request against.

Uses the real, unmodified auth_helpers.py from ../ (the same real PKCE +
TOTP scripted "browser" the original poc/auth_flow/ used), extended with
an acr_values parameter.
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth_helpers import decode_jwt_payload, real_browser_login  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def main() -> None:
    # --- 1. No acr_values requested at all -- must NOT require TOTP ---
    print("=" * 10, "1. Plain login, no acr_values requested (analyst)", "=" * 10)
    tokens1, new_secret1, mfa_path1 = real_browser_login(
        "analyst", "DevAnalyst#2026", totp_secret=None, state=str(uuid.uuid4()), acr_values=None,
    )
    claims1 = decode_jwt_payload(tokens1["access_token"])
    print(f"acr claim: {claims1.get('acr')!r}, mfa_path={mfa_path1!r}")
    check("plain login with NO acr_values requested did NOT trigger any real TOTP setup/entry page",
          mfa_path1 == "none", f"mfa_path={mfa_path1!r}")
    check("resulting real token's acr claim is 'aal1', not 'aal2'", claims1.get("acr") == "aal1", str(claims1.get("acr")))

    # --- 2. acr_values=aal2 requested -- MUST require TOTP, first-time setup ---
    print("\n" + "=" * 10, "2. Step-up login, acr_values=aal2 requested (case-lead, first time)", "=" * 10)
    tokens2, new_secret2, mfa_path2 = real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=None, state=str(uuid.uuid4()), acr_values="aal2",
    )
    claims2 = decode_jwt_payload(tokens2["access_token"])
    print(f"acr claim: {claims2.get('acr')!r}, mfa_path={mfa_path2!r}")
    check("step-up login WITH acr_values=aal2 DID go through real CONFIGURE_TOTP setup",
          mfa_path2 == "setup", f"mfa_path={mfa_path2!r}")
    check("resulting real token's acr claim is 'aal2'", claims2.get("acr") == "aal2", str(claims2.get("acr")))

    # --- 3. Same case-lead user, now WITHOUT acr_values -- real regression
    # check: adding the level-1 subflow must not make a user who has a TOTP
    # credential get stuck being asked for it even on a plain login. ---
    print("\n" + "=" * 10, "3. Plain login (no acr_values), same user now HAS a TOTP credential", "=" * 10)
    tokens3, new_secret3, mfa_path3 = real_browser_login(
        "case-lead", "DevCaseLead#2026", totp_secret=new_secret2, state=str(uuid.uuid4()), acr_values=None,
    )
    claims3 = decode_jwt_payload(tokens3["access_token"])
    print(f"acr claim: {claims3.get('acr')!r}, mfa_path={mfa_path3!r}")
    check(
        "a user who HAS a real TOTP credential, logging in with NO acr_values requested, "
        "is still NOT forced through real OTP entry",
        mfa_path3 == "none", f"mfa_path={mfa_path3!r}",
    )
    check("resulting real token's acr claim is 'aal1' even though the user has TOTP set up",
          claims3.get("acr") == "aal1", str(claims3.get("acr")))

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
