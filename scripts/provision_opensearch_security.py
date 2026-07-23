#!/usr/bin/env python3
"""Provision OpenSearch's security config (idempotent): a real openid authc
domain trusting Keycloak, plus the generic DLS tenant role. Real design and
bugs verified end-to-end in poc/opensearch_dashboards_sso/ -- see that
PoC's README.md for the full account (source citations, root causes) behind
every choice below; this script ports the verified config into a reusable,
production-shaped provisioning step (the single source of truth shared by
dev/prod compose and any future Helm provisioning Job, mirroring
scripts/provision_keycloak_org.sh's own role for Keycloak).

Required env:
  OS_BASE            OpenSearch base URL, e.g. https://opensearch:9200
  OS_ADMIN_USER       OpenSearch Security admin username (superuser)
  OS_ADMIN_PASSWORD   OpenSearch Security admin password
  KC_BASE             Keycloak base URL, e.g. http://keycloak:8080
  KC_REALM            Keycloak realm, e.g. kronos
"""
from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

_GENERIC_TENANT_ROLE_NAME = "kronos-generic-tenant"
_GENERIC_TENANT_BACKEND_ROLES = ["org-admin", "case-lead", "analyst", "read-only"]


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"ERROR: {name} is required", file=sys.stderr)
        sys.exit(1)
    return value


def _request(method: str, url: str, user: str, password: str, body: dict | None = None) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    creds = f"{user}:{password}".encode()
    import base64

    req.add_header("Authorization", f"Basic {base64.b64encode(creds).decode()}")
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else {}


def wait_for_opensearch(os_base: str, user: str, password: str) -> None:
    for attempt in range(60):
        try:
            _request("GET", f"{os_base}/_cluster/health", user, password)
            return
        except (urllib.error.URLError, ConnectionError) as exc:
            if attempt == 59:
                raise
            print(f"waiting for OpenSearch ({attempt + 1}/60): {exc}")
            time.sleep(5)


def main() -> None:
    os_base = _env("OS_BASE")
    os_user = _env("OS_ADMIN_USER")
    os_password = _env("OS_ADMIN_PASSWORD")
    kc_base = _env("KC_BASE")
    kc_realm = _env("KC_REALM")

    wait_for_opensearch(os_base, os_user, os_password)

    full = _request("GET", f"{os_base}/_plugins/_security/api/securityconfig", os_user, os_password)
    authc = full["config"]["dynamic"]["authc"]

    # Real BackendRegistry.java auth-domain loop (read directly, not
    # guessed): a domain with challenge=true that fails to extract
    # credentials immediately short-circuits with its own 401 and never
    # tries later domains. Both the bundled basic domain and this new
    # openid domain must be challenge=false so admin:admin (this script,
    # and any other Basic-Auth caller) and Bearer-JWT callers each fall
    # through to whichever domain actually matches their credentials.
    if "basic_internal_auth_domain" in authc:
        authc["basic_internal_auth_domain"]["http_authenticator"]["challenge"] = False

    authc["openid_auth_domain"] = {
        "http_enabled": True,
        "transport_enabled": False,
        "order": 10,
        "http_authenticator": {
            "type": "openid",
            "challenge": False,
            "config": {
                # subject_key=sub, not preferred_username (the generic
                # OpenSearch docs' own example): this realm's real tokens
                # have no preferred_username claim -- confirmed empirically
                # in poc/opensearch_dashboards_sso/.
                "subject_key": "sub",
                # roles_key=org_id reuses the exact same flat claim DLS
                # already templates via ${attr.jwt.org_id} below -- a
                # Dashboards openid session gets DLS enforcement for free.
                "roles_key": "org_id",
                "openid_connect_url": f"{kc_base}/realms/{kc_realm}/.well-known/openid-configuration",
            },
        },
        "authentication_backend": {"type": "noop", "config": {}},
    }
    _request("PUT", f"{os_base}/_plugins/_security/api/securityconfig/config", os_user, os_password, full["config"])
    print("openid authc domain configured.")

    # The real, already-shipped generic DLS role
    # (src/adapter/opensearch/client.py's ensure_generic_tenant_role) --
    # reproduced here so a fresh dev/prod OpenSearch also has it available
    # before the backend's own lazy first-ingest call would otherwise
    # create it (this makes Dashboards' own DLS-scoped queries work even
    # before any evidence has ever been ingested).
    role_body = {
        "cluster_permissions": [],
        "index_permissions": [
            {
                "index_patterns": ["kronos-*"],
                "dls": json.dumps({"term": {"kronos.org_id": "${attr.jwt.org_id}"}}),
                "allowed_actions": ["read", "indices:data/read/search"],
            }
        ],
        "tenant_permissions": [],
    }
    _request(
        "PUT",
        f"{os_base}/_plugins/_security/api/roles/{_GENERIC_TENANT_ROLE_NAME}",
        os_user,
        os_password,
        role_body,
    )
    _request(
        "PUT",
        f"{os_base}/_plugins/_security/api/rolesmapping/{_GENERIC_TENANT_ROLE_NAME}",
        os_user,
        os_password,
        {"backend_roles": _GENERIC_TENANT_BACKEND_ROLES},
    )
    print(f"{_GENERIC_TENANT_ROLE_NAME} role + rolesmapping ensured.")
    print("provision_opensearch_security: complete")


if __name__ == "__main__":
    main()
