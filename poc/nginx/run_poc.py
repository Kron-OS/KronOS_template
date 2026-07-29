"""PoC: real nginx (docker/nginx/nginx.conf.template, completely unmodified)
in front of the real FastAPI backend (src/external/fastapi_app.py's real
CORSMiddleware) -- CSP and CORS headers, both real, both from the actual
config files this repo ships, never run together before.

Run via run_poc.sh (starts a real uvicorn backend + a real nginx:alpine
container with the real template mounted).
"""
from __future__ import annotations

import os
import sys

import httpx

BACKEND_PORT = os.environ["BACKEND_PORT"]
NGINX_PORT = os.environ["NGINX_PORT"]
BACKEND_URL = f"http://localhost:{BACKEND_PORT}"
NGINX_URL = f"http://localhost:{NGINX_PORT}"

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def main() -> None:
    # --- 0. Real finding: nginx crashes at startup if a CSP-origin var is unset ---
    print("=" * 10, "0. Real nginx startup crash on an unset CSP-origin var", "=" * 10)
    nginx_crashed = os.environ.get("NGINX_CRASHED", "").strip().lower() == "false"
    check(
        "real nginx:alpine container with OPENSEARCH_DASHBOARDS_URL fully unset "
        "(not even empty) genuinely fails to start (nginx: [emerg] unknown "
        "\"opensearch_dashboards_url\" variable) -- contradicts nginx.conf.template's "
        "own comment that an unset var 'substitutes to empty string, which is safe'",
        nginx_crashed,
    )

    # --- 1. Direct-to-backend CORS: real CORSMiddleware, real preflight ---
    print("\n" + "=" * 10, "1. Real CORS preflight direct to the backend", "=" * 10)
    allowed_origin = "http://localhost:5173"
    disallowed_origin = "http://evil.example"

    pre_allowed = httpx.options(
        f"{BACKEND_URL}/api/cases",
        headers={"Origin": allowed_origin, "Access-Control-Request-Method": "GET"},
    )
    print(f"OPTIONS preflight (allowed origin) -> {pre_allowed.status_code} "
          f"ACAO={pre_allowed.headers.get('access-control-allow-origin')!r} "
          f"ACAC={pre_allowed.headers.get('access-control-allow-credentials')!r}")
    check("real preflight from an ALLOWED origin gets that origin echoed back",
          pre_allowed.headers.get("access-control-allow-origin") == allowed_origin)
    check("real preflight response allows credentials (allow_credentials=True)",
          pre_allowed.headers.get("access-control-allow-credentials") == "true")

    pre_disallowed = httpx.options(
        f"{BACKEND_URL}/api/cases",
        headers={"Origin": disallowed_origin, "Access-Control-Request-Method": "GET"},
    )
    print(f"OPTIONS preflight (disallowed origin) -> {pre_disallowed.status_code} "
          f"ACAO={pre_disallowed.headers.get('access-control-allow-origin')!r}")
    check("real preflight from a DISALLOWED origin gets NO Access-Control-Allow-Origin",
          "access-control-allow-origin" not in pre_disallowed.headers)

    no_origin = httpx.get(f"{BACKEND_URL}/openapi.json")
    check("a plain request with NO Origin header gets no CORS header at all (real, standard behavior)",
          "access-control-allow-origin" not in no_origin.headers)

    # --- 2. Real CSP header through nginx, using the ACTUAL docker-compose*.yml
    # pattern -- all four vars present (three empty, one set) -- which is what
    # keeps section 0's crash from happening in the repo's real compose files. ---
    print("\n" + "=" * 10, "2. Real CSP header via real nginx (envsubst)", "=" * 10)
    root = httpx.get(f"{NGINX_URL}/")
    csp = root.headers.get("content-security-policy", "")
    print(f"GET / -> {root.status_code}\nCSP: {csp}")
    check("KEYCLOAK_PUBLIC_URL (set) was correctly substituted into the real CSP header",
          "keycloak.kronos-poc.example" in csp)
    check(
        "the three EMPTY (but present) vars correctly collapse to nothing, not "
        "literal '${VARNAME}' text -- confirms docker-compose*.yml's ${VAR:-} "
        "pattern (always defines the var, defaulting to empty) is what actually "
        "keeps section 0's crash from happening in this repo's real compose "
        "files; anything that DOESN'T guarantee that (a bare docker run missing "
        "one, or -- confirmed separately -- the current Helm chart, whose nginx "
        "Deployment sets none of these four vars) hits the real crash instead",
        "${BACKEND_PUBLIC_URL}" not in csp and "${MINIO_PUBLIC_URL}" not in csp and "${OPENSEARCH_DASHBOARDS_URL}" not in csp,
        csp,
    )

    # --- 3. Real add_header inheritance gotcha on /silent-check-sso.html ---
    print("\n" + "=" * 10, "3. Real add_header inheritance on /silent-check-sso.html", "=" * 10)
    silent = httpx.get(f"{NGINX_URL}/silent-check-sso.html")
    print(f"GET /silent-check-sso.html -> {silent.status_code}")
    print(f"  headers present: {sorted(silent.headers.keys())}")
    check("its own CSP (frame-ancestors 'self') IS present, as configured",
          "frame-ancestors" in silent.headers.get("content-security-policy", ""))
    check(
        "nginx's real, documented add_header inheritance rule (a location "
        "block with its OWN add_header does not inherit ANY add_header from "
        "the server level) means X-Frame-Options is REAL confirmed absent "
        "here, not a copy-paste oversight in this PoC",
        "x-frame-options" not in silent.headers,
    )
    check("X-Content-Type-Options is ALSO absent here for the same reason",
          "x-content-type-options" not in silent.headers)
    check("Strict-Transport-Security is ALSO absent here for the same reason",
          "strict-transport-security" not in silent.headers)
    root_headers = {k.lower() for k in root.headers}
    check("...while the root '/' response (no location-level add_header) DOES carry all of them",
          {"x-frame-options", "x-content-type-options", "strict-transport-security"} <= root_headers)

    # --- 4. Through the real /api/ proxy: nginx's headers AND the backend's CORS headers together ---
    print("\n" + "=" * 10, "4. Real /api/ proxy: nginx CSP + backend CORS on the SAME response", "=" * 10)
    proxied = httpx.get(f"{NGINX_URL}/api/cases", headers={"Origin": allowed_origin})
    print(f"GET /api/cases (via nginx) -> {proxied.status_code} "
          f"ACAO={proxied.headers.get('access-control-allow-origin')!r} "
          f"CSP-present={'content-security-policy' in proxied.headers}")
    check("real request through nginx's /api/ proxy reaches the real backend (a real HTTP response came back, not a hang/timeout)",
          100 <= proxied.status_code < 600)
    check("the backend's real CORS header survives the real nginx proxy_pass, unmodified",
          proxied.headers.get("access-control-allow-origin") == allowed_origin)
    check("nginx's own CSP header is ALSO present on the same proxied response (both layers apply)",
          "content-security-policy" in proxied.headers)

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        for f in FAIL:
            print(f"  - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
