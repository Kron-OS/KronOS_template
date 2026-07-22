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


def new_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def start_auth(client: httpx.Client, verifier_challenge: tuple[str, str], *, state: str) -> httpx.Response:
    _, challenge = verifier_challenge
    return client.get(
        f"{KC}/realms/{REALM}/protocol/openid-connect/auth",
        params={
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": "openid",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
    )


def submit_username_password(client: httpx.Client, resp: httpx.Response, username: str, password: str) -> httpx.Response:
    action = unescape(re.search(r'action="([^"]+)"', resp.text).group(1))
    return client.post(action, data={"username": username, "password": password})


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


def real_browser_login(username: str, password: str, *, totp_secret: str | None, state: str) -> tuple[dict, str | None]:
    """Full real scripted browser login. If totp_secret is None, assumes the
    user has no TOTP credential yet and completes real CONFIGURE_TOTP setup,
    returning the newly-registered secret as the second tuple element (None
    if a pre-existing secret was reused)."""
    client = httpx.Client(follow_redirects=True)
    verifier, challenge = new_pkce_pair()
    resp = start_auth(client, (verifier, challenge), state=state)
    resp = submit_username_password(client, resp, username, password)

    new_secret = None
    if "login-config-totp" in resp.text:
        b32secret, resp = complete_totp_setup(client, resp)
        new_secret = b32secret
    elif "login-otp" in resp.text:
        if totp_secret is None:
            raise RuntimeError("User already has a TOTP credential but no secret was provided")
        resp = submit_totp_code(client, resp, totp_secret)

    tokens = extract_code_and_exchange(client, resp, verifier)
    return tokens, new_secret
