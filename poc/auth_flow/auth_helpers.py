"""Real, scripted "browser" for Keycloak's Authorization Code + PKCE flow,
including real TOTP-based step-up MFA -- no shortcuts (no password grant,
no hand-minted tokens). Used by run_poc.py.

Two scripting-environment quirks fixed here (documented so they aren't
mistaken for application bugs):
  1. Python's stdlib http.cookiejar treats bare hostnames like "localhost"
     specially (appends ".local"), breaking cookie matching -- use 127.0.0.1.
  2. Keycloak marks its session cookies Secure=True even over plain HTTP in
     dev mode; a real browser would just use HTTPS. For this scripted
     client, the Secure-flag gate is bypassed (only that check).

A real bug this file's own client config caused, found and fixed while
verifying the step-up conditional-flow fix (see
poc/auth_flow/step_up_conditional_fix/): the shared httpx.Client is built
with follow_redirects=True. Under the ORIGINAL (broken) step-up flow, a
login POST's response was always a 200 MFA page, never a redirect, so this
never mattered. Once step-up was actually fixed, a plain aal1 login's
login POST became an IMMEDIATE 302 straight to redirect_uri?code=... --
and nothing listens on that port in this PoC (see
extract_code_and_exchange's own comment below) -- so httpx's automatic
redirect-following tried to connect there itself and raised a raw
ConnectError, which looked exactly like environment flakiness at first
until traced to this. Fixed by passing follow_redirects=False on this one
call site, matching every other POST in this file that already does.
"""

from __future__ import annotations

import base64
import hashlib
import http.cookiejar
import os
import re
from html import unescape
from urllib.parse import parse_qs, urlparse

import httpx
import pyotp

http.cookiejar.DefaultCookiePolicy.return_ok_secure = lambda self, cookie, request: True  # noqa: ARG005

KC = "http://127.0.0.1:18082"
REALM = "kronos"
CLIENT_ID = "kronos-frontend"
REDIRECT_URI = "http://localhost:5173/callback"
# Real, reproduced regression found while re-verifying the LAN-HTTPS nginx
# work (see poc/tls_lan_https/): the dev stack's Keycloak pins KC_HOSTNAME
# to https://kronos.local:8443 (the sole authorized domain,
# docs/lan-dev-access.md), so a login flow against it
# (poc/full_ingestion_test/login.py, poc/kape_ingestion_test/*.py) lands
# on the interactive login-form step there -- httpx's default
# `verify=True` (system trust store) doesn't know the
# stack's own step-ca root, so that redirect failed with
# CERTIFICATE_VERIFY_FAILED. Callers that cross into the LAN HTTPS origin
# set this to the real root_ca.crt path (e.g. `docker cp
# docker-tls-init-1:/certs/root_ca.crt`); callers that stay entirely on
# plain HTTP (this file's own throwaway-Keycloak PoCs) leave it at the
# default `True`, unaffected.
CA_BUNDLE: str | bool = True


def trust_dev_stack_step_ca(tls_init_container: str = "docker-tls-init-1") -> None:
    """Fetch the real dev-stack step-ca root (docker cp from the tls-init
    container's own output volume) and set CA_BUNDLE to it. Call this before
    real_browser_login() when KC points at the real docker-compose.dev.yml
    stack rather than a throwaway PoC-only Keycloak container -- see
    CA_BUNDLE's own comment for why."""
    import subprocess  # noqa: PLC0415
    import tempfile  # noqa: PLC0415

    global CA_BUNDLE
    tmp_dir = tempfile.mkdtemp(prefix="kronos-step-ca-")
    dest = f"{tmp_dir}/root_ca.crt"
    subprocess.run(
        ["docker", "cp", f"{tls_init_container}:/certs/root_ca.crt", dest],
        check=True,
        capture_output=True,
    )
    CA_BUNDLE = dest


def new_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def start_auth(
    client: httpx.Client,
    verifier_challenge: tuple[str, str],
    *,
    state: str,
    acr_values: str | None = None,
) -> httpx.Response:
    _, challenge = verifier_challenge
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    if acr_values is not None:
        params["acr_values"] = acr_values
    return client.get(
        f"{KC}/realms/{REALM}/protocol/openid-connect/auth",
        params=params,
    )


def submit_username_password(client: httpx.Client, resp: httpx.Response, username: str, password: str) -> httpx.Response:
    action = unescape(re.search(r'action="([^"]+)"', resp.text).group(1))
    # follow_redirects=False: when no further MFA is needed (e.g. a plain
    # aal1 login under the fixed step-up flow), this response IS the final
    # 302 straight to redirect_uri with ?code=... -- nothing listens on
    # that port in this PoC (see extract_code_and_exchange's docstring),
    # so the client's own default follow_redirects=True would make httpx
    # try to auto-follow it and raise a real ConnectError on THAT hop, not
    # this one. Every other call site in this file already passes
    # follow_redirects=False for exactly this reason; this was the one
    # that didn't, because until the step-up flow was actually fixed this
    # call's response was never a redirect (always a 200 MFA page).
    return client.post(
        action,
        data={"username": username, "password": password},
        follow_redirects=False,
    )


def complete_totp_setup(client: httpx.Client, resp: httpx.Response) -> tuple[str, httpx.Response]:
    """Handle Keycloak's CONFIGURE_TOTP required-action page: extract the
    real base32 secret, compute a real TOTP code, submit the setup form.
    Returns the base32 secret (caller needs it for future logins)."""
    totp_action = unescape(re.search(r'<form[^>]*\baction="([^"]+)"', resp.text).group(1))
    raw_secret = re.search(r'name="totpSecret" value="([^"]+)"', resp.text).group(1)
    manual_link = unescape(re.search(r'href="([^"]+)" id="mode-manual"', resp.text).group(1))
    resp_manual = client.get(manual_link)
    b32secret = re.search(r'id="kc-totp-secret-key">([^<]+)<', resp_manual.text).group(1).replace(" ", "")
    code = pyotp.TOTP(b32secret).now()
    resp2 = client.post(
        totp_action,
        data={"totp": code, "totpSecret": raw_secret, "userLabel": "poc-authenticator", "logout-sessions": "on"},
        follow_redirects=False,
    )
    return b32secret, resp2


def submit_totp_code(client: httpx.Client, resp: httpx.Response, b32secret: str) -> httpx.Response:
    """Handle Keycloak's login-otp page for a user who already has a TOTP credential."""
    otp_action = unescape(re.search(r'<form[^>]*\baction="([^"]+)"', resp.text).group(1))
    cred_id_match = re.search(r'name="selectedCredentialId" value="([^"]+)"', resp.text)
    data = {"otp": pyotp.TOTP(b32secret).now()}
    if cred_id_match:
        data["selectedCredentialId"] = cred_id_match.group(1)
    return client.post(otp_action, data=data, follow_redirects=False)


def extract_code_and_exchange(client: httpx.Client, redirect_resp: httpx.Response, verifier: str) -> dict:
    """From a 3xx response whose Location carries ?code=..., follow any
    Keycloak-internal intermediate redirects (never the final redirect_uri,
    which nothing is listening on in this PoC), then exchange the code for
    real tokens."""
    resp = redirect_resp
    loc = resp.headers.get("location")
    while loc and REDIRECT_URI not in loc:
        resp = client.get(loc, follow_redirects=False)
        loc = resp.headers.get("location")
    if not loc:
        raise RuntimeError(f"No redirect Location header found; last response: {resp.status_code} {resp.text[:300]}")
    qs = parse_qs(urlparse(loc).query)
    code = qs.get("code", [None])[0]
    if not code:
        raise RuntimeError(f"No ?code= in redirect: {loc}")

    token_resp = httpx.post(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token",
        verify=CA_BUNDLE,
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "client_id": CLIENT_ID,
            "code_verifier": verifier,
        },
    )
    token_resp.raise_for_status()
    return token_resp.json()


def decode_jwt_payload(token: str) -> dict:
    import json

    parts = token.split(".")
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def real_browser_login(
    username: str,
    password: str,
    *,
    totp_secret: str | None,
    state: str,
    acr_values: str | None = None,
) -> tuple[dict, str | None, str]:
    """Full real scripted browser login. If totp_secret is None, assumes the
    user has no TOTP credential yet and completes real CONFIGURE_TOTP setup,
    returning the newly-registered secret as the second tuple element (None
    if a pre-existing secret was reused). Third element reports what
    actually happened server-side ("none" | "setup" | "otp_entry") so
    callers can assert on it directly instead of inferring it from
    new_secret alone (which is None both when no MFA step ran at all AND
    when OTP entry ran with an already-known secret -- those are very
    different outcomes to be verifying)."""
    client = httpx.Client(follow_redirects=True, verify=CA_BUNDLE)
    verifier, challenge = new_pkce_pair()
    resp = start_auth(client, (verifier, challenge), state=state, acr_values=acr_values)
    resp = submit_username_password(client, resp, username, password)

    # submit_username_password disables auto-follow (see its own comment).
    # If MFA IS required, Keycloak's response here is itself a 302 to an
    # intermediate page (e.g. .../login-actions/required-action?execution=
    # CONFIGURE_TOTP), not the final redirect_uri -- follow that one
    # explicitly to reach the real page whose content the checks below
    # inspect. If no MFA is required, the redirect goes straight to
    # redirect_uri and is left alone for extract_code_and_exchange.
    loc = resp.headers.get("location")
    if loc and REDIRECT_URI not in loc:
        resp = client.get(loc, follow_redirects=False)

    new_secret = None
    mfa_path = "none"
    if "login-config-totp" in resp.text:
        b32secret, resp = complete_totp_setup(client, resp)
        new_secret = b32secret
        mfa_path = "setup"
    elif "login-otp" in resp.text:
        if totp_secret is None:
            raise RuntimeError("User already has a TOTP credential but no secret was provided")
        resp = submit_totp_code(client, resp, totp_secret)
        mfa_path = "otp_entry"

    tokens = extract_code_and_exchange(client, resp, verifier)
    return tokens, new_secret, mfa_path
